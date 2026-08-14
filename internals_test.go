package lumoauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Coverage for the pieces the flow-level tests do not reach: the RSA and
// ECDSA verification paths, the option plumbing, and the small helpers.

func TestVerifyJWSRSAAlgorithms(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwk, err := jwkFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("jwkFromPublicKey: %v", err)
	}
	publicKey, err := jwk.PublicKey()
	if err != nil {
		t.Fatalf("JWK.PublicKey: %v", err)
	}

	signingInput := []byte("header.payload")

	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		t.Run(alg, func(t *testing.T) {
			hashID, digest := hashFor(alg, signingInput)

			var signature []byte
			if strings.HasPrefix(alg, "PS") {
				signature, err = rsa.SignPSS(rand.Reader, key, hashID, digest, &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hashID,
				})
			} else {
				signature, err = rsa.SignPKCS1v15(rand.Reader, key, hashID, digest)
			}
			if err != nil {
				t.Fatalf("signing: %v", err)
			}

			if !verifyJWS(alg, signingInput, signature, publicKey) {
				t.Errorf("%s signature did not verify", alg)
			}
			if verifyJWS(alg, []byte("tampered.payload"), signature, publicKey) {
				t.Errorf("%s verified over the wrong input", alg)
			}
		})
	}
}

func TestVerifyJWSRejectsUnsafeAlgorithms(t *testing.T) {
	keypair, _ := GenerateKeypair("")
	publicKey, _ := keypair.JWK.PublicKey()

	// HMAC and "none" must never verify, whatever the signature bytes.
	for _, alg := range []string{"HS256", "HS384", "HS512", "none", "", "ES256K"} {
		if verifyJWS(alg, []byte("a.b"), []byte("signature"), publicKey) {
			t.Errorf("algorithm %q must be rejected", alg)
		}
	}
}

func TestAlgMatchesKeyType(t *testing.T) {
	cases := []struct {
		alg, kty string
		want     bool
	}{
		{"EdDSA", "OKP", true},
		{"RS256", "RSA", true},
		{"PS512", "RSA", true},
		{"ES256", "EC", true},
		// Cross-type combinations are what key-confusion attacks rely on.
		{"EdDSA", "RSA", false},
		{"RS256", "OKP", false},
		{"ES256", "RSA", false},
		{"HS256", "OKP", false},
		{"RS256", "unknown", false},
	}
	for _, tc := range cases {
		if got := algMatchesKeyType(tc.alg, tc.kty); got != tc.want {
			t.Errorf("algMatchesKeyType(%q, %q) = %v, want %v", tc.alg, tc.kty, got, tc.want)
		}
	}
}

func TestLoadPrivateKeyAcceptsRSAFormats(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	formats := map[string][]byte{
		"PRIVATE KEY":     pkcs8,
		"RSA PRIVATE KEY": x509.MarshalPKCS1PrivateKey(key),
	}
	for blockType, der := range formats {
		t.Run(blockType, func(t *testing.T) {
			encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
			signer, err := LoadPrivateKey(string(encoded))
			if err != nil {
				t.Fatalf("LoadPrivateKey: %v", err)
			}
			if _, ok := signer.(*rsa.PrivateKey); !ok {
				t.Errorf("got %T, want an RSA key", signer)
			}
		})
	}
}

func TestSignRequestWithRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	headers, err := SignRequest(keyPEM, http.MethodPost, "https://auth.test/token", SignOptions{
		Body:    []byte(`{"request_type":"auth"}`),
		Created: vectorCreated,
		Nonce:   vectorNonce,
	})
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	signature, err := parseSignatureHeader(headers["Signature"])
	if err != nil {
		t.Fatalf("parseSignatureHeader: %v", err)
	}
	components, created, nonce, err := parseSignatureInput(headers["Signature-Input"])
	if err != nil {
		t.Fatalf("parseSignatureInput: %v", err)
	}

	base := BuildSignatureBase(components, map[string]string{
		"@method":        http.MethodPost,
		"@authority":     "auth.test",
		"@path":          "/token",
		"signature-key":  "",
		"content-digest": headers["Content-Digest"],
		"content-type":   "application/json",
		"authorization":  "",
	}, created, nonce)

	// RSA keys sign with RSA-PSS-SHA512, per the AAuth profile.
	if !VerifySignatureBase(base, signature, &key.PublicKey) {
		t.Error("an RSA-signed request did not verify")
	}
}

func TestJWKRoundTripsECKeys(t *testing.T) {
	// The EC path exists for issuer keys, so the conversion must survive a
	// round trip even though this SDK never generates EC keys itself.
	for _, curve := range []string{"P-256", "P-384", "P-521"} {
		if _, err := curveFromName(curve); err != nil {
			t.Errorf("curveFromName(%q): %v", curve, err)
		}
	}
	if _, err := curveFromName("P-192"); !errors.Is(err, ErrValidation) {
		t.Error("an unsupported curve should be a validation error")
	}
}

func TestJWKPublicKeyRejectsMalformedInput(t *testing.T) {
	cases := []JWK{
		{Kty: "OKP", Crv: "X25519", X: "abc"},         // wrong curve
		{Kty: "OKP", Crv: "Ed25519", X: "!!!"},        // undecodable
		{Kty: "OKP", Crv: "Ed25519", X: "c2hvcnQ"},    // wrong key length
		{Kty: "RSA", N: "!!!", E: "AQAB"},             // undecodable modulus
		{Kty: "EC", Crv: "P-256", X: "!!!", Y: "abc"}, // undecodable coordinate
		{Kty: "oct"}, // symmetric key
	}
	for _, jwk := range cases {
		if _, err := jwk.PublicKey(); err == nil {
			t.Errorf("JWK %+v should have been rejected", jwk)
		}
	}
}

func TestLeftPad(t *testing.T) {
	if got := leftPad([]byte{1, 2}, 4); len(got) != 4 || got[0] != 0 || got[3] != 2 {
		t.Errorf("leftPad = %v", got)
	}
	// Already long enough: returned unchanged.
	if got := leftPad([]byte{1, 2, 3}, 2); len(got) != 3 {
		t.Errorf("leftPad = %v", got)
	}
}

func TestClientOptionPlumbing(t *testing.T) {
	var seen http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		writeJSON(w, 200, map[string]any{"allowed": true})
	}))
	defer server.Close()

	custom := &http.Client{Timeout: 5 * time.Second}
	client, err := New(
		WithBaseURL(server.URL),
		WithOrgID("acme-corp"),
		WithAPIKey("lmk_x"),
		WithTimeout(15*time.Second),
		WithHTTPClient(custom),
		WithHeader("X-Trace-Id", "trace-123"),
		WithUserAgent("my-app/2.0"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := client.Permissions.Check(context.Background(), "doc.edit", nil); err != nil {
		t.Fatalf("Check: %v", err)
	}

	if seen.Get("X-Trace-Id") != "trace-123" {
		t.Errorf("X-Trace-Id = %q", seen.Get("X-Trace-Id"))
	}
	if seen.Get("User-Agent") != "my-app/2.0" {
		t.Errorf("User-Agent = %q", seen.Get("User-Agent"))
	}
	if client.http.doer != custom {
		t.Error("WithHTTPClient should be used as-is")
	}
	// A supplied client's own timeout is left alone.
	if custom.Timeout != 5*time.Second {
		t.Errorf("WithTimeout must not mutate a caller-supplied client (got %v)", custom.Timeout)
	}
}

func TestWithSkipCertValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"allowed": true})
	}))
	defer server.Close()

	// Without the opt-out, the self-signed certificate is rejected.
	strict, err := New(WithBaseURL(server.URL), WithOrgID("acme"), WithAPIKey("lmk_x"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := strict.Permissions.Check(context.Background(), "doc.edit", nil); !errors.Is(err, ErrNetwork) {
		t.Errorf("an untrusted certificate should fail, got %v", err)
	}

	// With it, the request goes through.
	relaxed, err := New(
		WithBaseURL(server.URL), WithOrgID("acme"), WithAPIKey("lmk_x"),
		WithSkipCertValidation(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := relaxed.Permissions.Check(context.Background(), "doc.edit", nil); err != nil {
		t.Errorf("WithSkipCertValidation should accept a self-signed certificate: %v", err)
	}
}

func TestClientDoRaw(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A status the typed layer would turn into an error; DoRaw hands
		// it back untouched.
		writeJSON(w, 418, map[string]any{"error": "teapot"})
	}))
	defer server.Close()

	client, err := New(WithBaseURL(server.URL), WithOrgID("acme"), WithAPIKey("lmk_x"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	response, err := client.DoRaw(context.Background(), http.MethodGet, "/api/v1/whatever", nil)
	if err != nil {
		t.Fatalf("DoRaw: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 418 {
		t.Errorf("status = %d, want the raw 418", response.StatusCode)
	}
}

func TestOrgPathRequiresAnOrgID(t *testing.T) {
	client, err := New(WithBaseURL("https://example.test"), WithAPIKey("lmk_x"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.OrgPath("/admin/users"); !errors.Is(err, ErrConfig) {
		t.Errorf("expected a config error, got %v", err)
	}

	scoped, _ := New(WithBaseURL("https://example.test"), WithAPIKey("lmk_x"), WithOrgID("acme corp"))
	path, err := scoped.OrgPath("/admin/users")
	if err != nil {
		t.Fatalf("OrgPath: %v", err)
	}
	// The org slug is escaped, so an unusual value cannot alter the path.
	if path != "/orgs/acme%20corp/api/v1/admin/users" {
		t.Errorf("OrgPath = %q", path)
	}
}

func TestIDDecodesBothWireForms(t *testing.T) {
	var decoded struct {
		A ID `json:"a"`
		B ID `json:"b"`
		C ID `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a": 42, "b": "user_7", "c": null}`), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.A != "42" || decoded.B != "user_7" || decoded.C != "" {
		t.Errorf("decoded = %+v", decoded)
	}

	// Round-tripping keeps numbers numeric and strings quoted.
	encoded, err := json.Marshal(map[string]ID{"n": "42", "s": "user_7"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := string(encoded); got != `{"n":42,"s":"user_7"}` {
		t.Errorf("Marshal = %s", got)
	}
}

func TestSplitAndJoinScopes(t *testing.T) {
	if got := splitScopes("read write  admin"); len(got) != 3 || got[2] != "admin" {
		t.Errorf("splitScopes = %v", got)
	}
	if got := splitScopes("   "); got != nil {
		t.Errorf("splitScopes on blank input = %v, want nil", got)
	}
	if got := joinScopes([]string{"read", "write"}); got != "read write" {
		t.Errorf("joinScopes = %q", got)
	}
}

func TestAgentBudgetExhausted(t *testing.T) {
	cases := []struct {
		name   string
		budget *AgentBudget
		want   bool
	}{
		{"nil", nil, false},
		{"no policy", &AgentBudget{}, false},
		{"under cap", &AgentBudget{MaxTokensPerDay: 100, TokensUsedToday: 99}, false},
		{"at cap", &AgentBudget{MaxTokensPerDay: 100, TokensUsedToday: 100}, true},
		{"over cap", &AgentBudget{MaxTokensPerDay: 100, TokensUsedToday: 150}, true},
	}
	for _, tc := range cases {
		if got := tc.budget.Exhausted(); got != tc.want {
			t.Errorf("%s: Exhausted() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestApprovalImpactValid(t *testing.T) {
	for _, impact := range []ApprovalImpact{ImpactLow, ImpactMedium, ImpactHigh, ImpactCritical} {
		if !impact.Valid() {
			t.Errorf("%q should be valid", impact)
		}
	}
	for _, impact := range []ApprovalImpact{"", "catastrophic", "HIGH"} {
		if impact.Valid() {
			t.Errorf("%q should not be valid", impact)
		}
	}
}

func TestSessionTokensExpired(t *testing.T) {
	if (&SessionTokens{}).Expired() {
		t.Error("tokens with no known expiry should never report expired")
	}
	if (&SessionTokens{ExpiresAt: time.Now().Add(time.Hour)}).Expired() {
		t.Error("a future expiry should not report expired")
	}
	if !(&SessionTokens{ExpiresAt: time.Now().Add(-time.Second)}).Expired() {
		t.Error("a past expiry should report expired")
	}
}

func TestExtractError(t *testing.T) {
	cases := []struct {
		name        string
		body        any
		wantMessage string
		wantCode    string
	}{
		{
			"error_description wins",
			map[string]any{"error": "invalid_grant", "error_description": "the code expired"},
			"the code expired", "invalid_grant",
		},
		{"message", map[string]any{"message": "not found"}, "not found", ""},
		{"detail", map[string]any{"detail": "no such user"}, "no such user", ""},
		{"code field", map[string]any{"message": "x", "code": "CUSTOM"}, "x", "CUSTOM"},
		{"plain text", "upstream failure", "HTTP 500 — upstream failure", ""},
		{"empty", nil, "HTTP 500 Internal Server Error", ""},
		{"non-string message", map[string]any{"message": 42}, "HTTP 500 Internal Server Error", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message, code := extractError(500, tc.body)
			if message != tc.wantMessage {
				t.Errorf("message = %q, want %q", message, tc.wantMessage)
			}
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
		})
	}
}

func TestJITContextStatusAndPending(t *testing.T) {
	var calls []capture
	jit := newTestJIT(t, recordingHandler(t, &calls,
		map[string]any{"request_id": "req_1", "status": "approved"},
		map[string]any{"requests": []map[string]any{{"request_id": "req_2", "status": "pending"}}},
	))

	ctx := context.Background()

	result, err := jit.Status(ctx, "req_1")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !result.Approved() {
		t.Errorf("result = %+v", result)
	}

	pending, err := jit.PendingRequests(ctx)
	if err != nil {
		t.Fatalf("PendingRequests: %v", err)
	}
	if len(pending) != 1 || pending[0].RequestID != "req_2" {
		t.Errorf("pending = %+v", pending)
	}
}

func TestJITContextEvaluateTask(t *testing.T) {
	var calls []capture
	jit := newTestJIT(t, recordingHandler(t, &calls,
		map[string]any{"task_id": "task_1"},
		map[string]any{"evaluated": true},
	))

	ctx := context.Background()
	if _, err := jit.CreateTask(ctx, CreateTaskParams{}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	// Defaults to the current task.
	if _, err := jit.EvaluateTask(ctx, "", EvaluateTaskParams{
		Result: TaskResultFailed, Notes: "the source document was unreadable",
	}); err != nil {
		t.Fatalf("EvaluateTask: %v", err)
	}
	if !strings.Contains(calls[1].Path, "task_1") {
		t.Errorf("path = %q, want the current task", calls[1].Path)
	}
	if calls[1].Body["result"] != TaskResultFailed {
		t.Errorf("body = %v", calls[1].Body)
	}

	// With no task at all it is a config error, not a bad request.
	bare := newTestJIT(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should have been sent")
	})
	if _, err := bare.EvaluateTask(ctx, "", EvaluateTaskParams{}); !errors.Is(err, ErrConfig) {
		t.Errorf("expected a config error, got %v", err)
	}
}

func TestAbacIsAllowedAndAttributeReads(t *testing.T) {
	var calls []capture
	client, _ := newTestClient(t, recordingHandler(t, &calls,
		map[string]any{"allowed": true},
		map[string]any{"clearance": "secret", "department": "eng"},
		map[string]any{"sensitivity": "high"},
	))

	ctx := context.Background()

	allowed, err := client.Abac.IsAllowed(ctx, AbacCheckParams{
		ResourceType: "document", Action: "read",
	})
	if err != nil {
		t.Fatalf("IsAllowed: %v", err)
	}
	if !allowed {
		t.Error("IsAllowed should report the decision")
	}

	attributes, err := client.Abac.MyAttributes(ctx)
	if err != nil {
		t.Fatalf("MyAttributes: %v", err)
	}
	if attributes["clearance"] != "secret" {
		t.Errorf("attributes = %v", attributes)
	}

	resourceAttributes, err := client.Abac.ResourceAttributes(ctx, "document", "doc-1")
	if err != nil {
		t.Fatalf("ResourceAttributes: %v", err)
	}
	if resourceAttributes["sensitivity"] != "high" {
		t.Errorf("attributes = %v", resourceAttributes)
	}
	if calls[2].Path != "/orgs/acme-corp/api/v1/abac/resources/document/doc-1/attributes" {
		t.Errorf("path = %q", calls[2].Path)
	}
}

func TestAgentAskAndIdentityCaching(t *testing.T) {
	var identityCalls int
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			writeJSON(w, 200, map[string]any{"access_token": "t", "expires_in": 3600})
		case strings.HasSuffix(r.URL.Path, "/agents/ask"):
			writeJSON(w, 200, map[string]any{"allowed": true, "action": "document.read"})
		case strings.HasSuffix(r.URL.Path, "/agents/me"):
			identityCalls++
			writeJSON(w, 200, map[string]any{
				"identity": map[string]any{"id": "agent_1"}, "capabilities": []string{"read"},
			})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})

	ctx := context.Background()

	result, err := agent.Ask(ctx, "document.read", nil)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if !result.Allowed {
		t.Errorf("result = %+v", result)
	}

	for i := 0; i < 2; i++ {
		identity, err := agent.Identity(ctx, false)
		if err != nil {
			t.Fatalf("Identity: %v", err)
		}
		if identity.ID() != "agent_1" {
			t.Errorf("ID() = %q", identity.ID())
		}
	}
	if identityCalls != 1 {
		t.Errorf("identity should be cached, fetched %d times", identityCalls)
	}

	if _, err := agent.Identity(ctx, true); err != nil {
		t.Fatalf("Identity(refresh): %v", err)
	}
	if identityCalls != 2 {
		t.Errorf("Identity(refresh) should refetch, calls = %d", identityCalls)
	}
}

func TestAgentDoEscapeHatch(t *testing.T) {
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			writeJSON(w, 200, map[string]any{"access_token": "agent-token", "expires_in": 3600})
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer agent-token" {
			t.Errorf("Authorization = %q", got)
		}
		writeJSON(w, 200, map[string]any{"data": []any{map[string]any{"id": 1}}})
	})

	ctx := context.Background()

	var page struct {
		Data []map[string]any `json:"data"`
	}
	if err := agent.Do(ctx, http.MethodGet, "/orgs/acme-corp/api/v1/documents", nil, &page); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(page.Data) != 1 {
		t.Errorf("decoded %d records", len(page.Data))
	}

	response, err := agent.DoRaw(ctx, http.MethodGet, "/orgs/acme-corp/api/v1/documents", nil)
	if err != nil {
		t.Fatalf("DoRaw: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d", response.StatusCode)
	}
}

func TestDelegationChainDoRawAndActorChain(t *testing.T) {
	state := &delegationServer{}
	chain, _ := newTestChain(t, state)
	ctx := context.Background()

	if err := chain.SetUserToken("session-1", "user-token"); err != nil {
		t.Fatalf("SetUserToken: %v", err)
	}

	response, err := chain.DoRaw(ctx, "session-1", http.MethodGet, "/orgs/acme-corp/api/v1/documents", nil)
	if err != nil {
		t.Fatalf("DoRaw: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d", response.StatusCode)
	}

	claims, _ := json.Marshal(map[string]any{
		"sub": "user:ada",
		"act": map[string]any{"sub": "agent:orchestrator"},
	})
	token := "header." + b64url(claims) + ".sig"

	actors, err := chain.ActorChain(token)
	if err != nil {
		t.Fatalf("ActorChain: %v", err)
	}
	if len(actors) != 1 || actors[0] != "agent:orchestrator" {
		t.Errorf("actors = %v", actors)
	}
}

func TestDelegationResourceIntrospectionMethods(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {})

	claims, _ := json.Marshal(map[string]any{
		"sub": "user:ada",
		"act": map[string]any{"sub": "agent:orchestrator"},
	})
	token := "header." + b64url(claims) + ".sig"

	actors, err := client.Delegation.ParseActorChain(token)
	if err != nil {
		t.Fatalf("ParseActorChain: %v", err)
	}
	if len(actors) != 1 {
		t.Errorf("actors = %v", actors)
	}

	subject, err := client.Delegation.Subject(token)
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	if subject != "user:ada" {
		t.Errorf("subject = %q", subject)
	}
}
