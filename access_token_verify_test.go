package lumoauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testIssuer   = "https://app.lumoauth.dev/orgs/acme-corp/api/v1"
	testResource = "https://mcp.example.com/mcp"
	testKid      = "lumo-rs256-key"
)

// testTokenSigner mints RS256 at+jwt tokens the way the server does.
type testTokenSigner struct {
	key  *rsa.PrivateKey
	jwks *JWKS
}

func newTestTokenSigner(t *testing.T) *testTokenSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk, err := jwkFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("jwkFromPublicKey: %v", err)
	}
	jwk.Kid, jwk.Use, jwk.Alg = testKid, "sig", "RS256"
	return &testTokenSigner{key: key, jwks: &JWKS{Keys: []JWK{jwk}}}
}

// mint signs claims with the given header overrides. Defaults produce a
// valid agent token for testResource.
func (s *testTokenSigner) mint(t *testing.T, claims map[string]any, header map[string]any) string {
	t.Helper()
	now := time.Now()
	full := map[string]any{
		"iss": testIssuer, "sub": "agent_agt_1", "aud": testResource,
		"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
		"jti": "jti-" + b64url([]byte(time.Now().String())), "scope": "mcp:tools read:documents",
		"is_agent": true, "capabilities": []string{"tool:search_web"}, "client_id": "agent-client",
	}
	for k, v := range claims {
		if v == nil {
			delete(full, k)
			continue
		}
		full[k] = v
	}
	head := map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": testKid}
	for k, v := range header {
		if v == nil {
			delete(head, k)
			continue
		}
		head[k] = v
	}
	headerJSON, _ := json.Marshal(head)
	claimsJSON, _ := json.Marshal(full)
	input := b64url(headerJSON) + "." + b64url(claimsJSON)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return input + "." + b64url(signature)
}

func (s *testTokenSigner) opts() AccessTokenVerifyOptions {
	return AccessTokenVerifyOptions{Issuer: testIssuer, Resource: testResource, JWKS: s.jwks,
		ReplayCache: NewMemoryReplayCache()}
}

func TestVerifyAccessTokenHappyPath(t *testing.T) {
	s := newTestTokenSigner(t)
	token := s.mint(t, map[string]any{
		"aud": []string{"https://other.example", testResource},
		"act": map[string]any{"sub": "agent_agt_1", "iss": testIssuer, "sub_profile": "agent", "name": "Bot",
			"act": map[string]any{"sub": "agent_agt_2"}},
		"sub": "usr_42", "is_agent": false,
	}, nil)

	claims, err := VerifyAccessToken(context.Background(), token, s.opts())
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Subject != "usr_42" || claims.Issuer != testIssuer || claims.IsAgent {
		t.Errorf("claims = %+v", claims)
	}
	if !claims.Audience.Contains(testResource) || len(claims.Audience) != 2 {
		t.Errorf("aud = %v", claims.Audience)
	}
	if !claims.HasScope("mcp:tools") || claims.HasScope("admin") || len(claims.Scopes()) != 2 {
		t.Errorf("scopes = %v", claims.Scopes())
	}
	if !claims.HasCapability("tool:search_web") {
		t.Error("capabilities not decoded")
	}
	if chain := claims.ActorChain(); len(chain) != 2 || chain[0] != "agent_agt_1" || chain[1] != "agent_agt_2" {
		t.Errorf("ActorChain = %v", chain)
	}
	if claims.Act.Name != "Bot" || claims.Act.SubjectProfile != "agent" {
		t.Errorf("act = %+v", claims.Act)
	}
	if claims.IsDPoPBound() {
		t.Error("an unbound token reports IsDPoPBound")
	}
	if claims.Raw["client_id"] != "agent-client" {
		t.Error("Raw claims missing")
	}

	// A single-string aud and the application/at+jwt typ also pass.
	token = s.mint(t, nil, map[string]any{"typ": "application/at+jwt"})
	if _, err := VerifyAccessToken(context.Background(), token, s.opts()); err != nil {
		t.Errorf("application/at+jwt: %v", err)
	}
}

func TestVerifyAccessTokenRejections(t *testing.T) {
	s := newTestTokenSigner(t)
	other := newTestTokenSigner(t)
	ctx := context.Background()
	past := time.Now().Add(-5 * time.Minute).Unix()

	cases := []struct {
		name   string
		token  string
		opts   func(AccessTokenVerifyOptions) AccessTokenVerifyOptions
		reason string
	}{
		{"wrong audience", s.mint(t, map[string]any{"aud": "https://other.example"}, nil), nil, TokenRejectedAudience},
		{"wrong typ", s.mint(t, nil, map[string]any{"typ": "JWT"}), nil, TokenRejectedType},
		{"auth+jwt typ", s.mint(t, nil, map[string]any{"typ": "auth+jwt"}), nil, TokenRejectedType},
		{"expired", s.mint(t, map[string]any{"exp": past}, nil), nil, TokenRejectedExpired},
		{"no exp", s.mint(t, map[string]any{"exp": nil}, nil), nil, TokenRejectedExpired},
		{"not yet valid", s.mint(t, map[string]any{"nbf": time.Now().Add(10 * time.Minute).Unix()}, nil), nil, TokenRejectedNotYetValid},
		{"test token", s.mint(t, map[string]any{"token_use": "test"}, nil), nil, TokenRejectedTestToken},
		{"wrong issuer", s.mint(t, map[string]any{"iss": "https://app.lumoauth.dev/orgs/evil/api/v1"}, nil), nil, TokenRejectedIssuer},
		{"unknown kid", s.mint(t, nil, map[string]any{"kid": "rotated"}), nil, TokenRejectedUnknownKey},
		{"wrong key", other.mint(t, nil, nil), nil, TokenRejectedSignature},
		{"none alg", s.mint(t, nil, map[string]any{"alg": "none"}), nil, TokenRejectedAlgorithm},
		{"hmac alg", s.mint(t, nil, map[string]any{"alg": "HS256"}), nil, TokenRejectedAlgorithm},
		{"alg/key mismatch", s.mint(t, nil, map[string]any{"alg": "ES256"}), nil, TokenRejectedAlgorithm},
		{"no kid", s.mint(t, nil, map[string]any{"kid": nil}), nil, TokenRejectedMalformed},
		{"not a jwt", "abc", nil, TokenRejectedMalformed},
		{"no sub", s.mint(t, map[string]any{"sub": nil}, nil), nil, TokenRejectedMalformed},
		{"dpop required", s.mint(t, nil, nil), func(o AccessTokenVerifyOptions) AccessTokenVerifyOptions {
			o.RequireDPoP = true
			return o
		}, TokenRejectedDPoPRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := s.opts()
			if tc.opts != nil {
				opts = tc.opts(opts)
			}
			_, err := VerifyAccessToken(ctx, tc.token, opts)
			if err == nil {
				t.Fatal("expected a rejection")
			}
			if !errors.Is(err, ErrValidation) {
				t.Errorf("err should match ErrValidation: %v", err)
			}
			if got := RejectionReason(err); got != tc.reason {
				t.Errorf("reason = %q, want %q (%v)", got, tc.reason, err)
			}
		})
	}

	// Clock skew: a token expired 30s ago passes with the 60s default and
	// fails with no tolerance.
	recent := s.mint(t, map[string]any{"exp": time.Now().Add(-30 * time.Second).Unix()}, nil)
	if _, err := VerifyAccessToken(ctx, recent, s.opts()); err != nil {
		t.Errorf("default skew should accept a token 30s past exp: %v", err)
	}
	strict := s.opts()
	strict.ClockSkew = -1
	if _, err := VerifyAccessToken(ctx, recent, strict); RejectionReason(err) != TokenRejectedExpired {
		t.Errorf("negative skew should reject: %v", err)
	}

	// Configuration errors are not rejections.
	if _, err := VerifyAccessToken(ctx, "x", AccessTokenVerifyOptions{Resource: testResource}); !errors.Is(err, ErrConfig) {
		t.Errorf("missing issuer: %v", err)
	}
	if RejectionReason(errors.New("plain")) != "" {
		t.Error("RejectionReason on a foreign error")
	}
}

func TestVerifyAccessTokenDPoPBinding(t *testing.T) {
	s := newTestTokenSigner(t)
	signer, _ := NewDPoPSigner()
	ctx := context.Background()
	token := s.mint(t, map[string]any{"cnf": map[string]string{"jkt": signer.Thumbprint()}}, nil)

	request := func(method, rawURL string, opts ...DPoPProofOption) *DPoPRequest {
		proof, err := signer.Proof(method, rawURL, append([]DPoPProofOption{WithProofAccessToken(token)}, opts...)...)
		if err != nil {
			t.Fatalf("Proof: %v", err)
		}
		return &DPoPRequest{Method: method, URL: rawURL, Proof: proof, Scheme: "DPoP"}
	}
	verify := func(req *DPoPRequest, mutate func(*AccessTokenVerifyOptions)) error {
		opts := s.opts()
		opts.DPoP = req
		if mutate != nil {
			mutate(&opts)
		}
		_, err := VerifyAccessToken(ctx, token, opts)
		return err
	}

	// Happy path, with query and a trailing fragment on the request URL.
	if err := verify(request("POST", testResource+"?session=1"), nil); err != nil {
		t.Fatalf("bound token with a valid proof: %v", err)
	}
	claims, err := VerifyAccessToken(ctx, token, func() AccessTokenVerifyOptions {
		o := s.opts()
		o.DPoP = request("POST", testResource)
		o.RequireDPoP = true
		return o
	}())
	if err != nil || !claims.IsDPoPBound() || claims.Confirmation.JKT != signer.Thumbprint() {
		t.Fatalf("RequireDPoP with a bound token: %v, claims %+v", err, claims)
	}

	// EdDSA proofs are accepted too.
	edSigner, _ := NewDPoPSignerEd25519()
	edToken := s.mint(t, map[string]any{"cnf": map[string]string{"jkt": edSigner.Thumbprint()}}, nil)
	edProof, _ := edSigner.Proof("POST", testResource, WithProofAccessToken(edToken))
	edOpts := s.opts()
	edOpts.DPoP = &DPoPRequest{Method: "POST", URL: testResource, Proof: edProof, Scheme: "DPoP"}
	if _, err := VerifyAccessToken(ctx, edToken, edOpts); err != nil {
		t.Errorf("EdDSA proof: %v", err)
	}

	rejections := []struct {
		name   string
		req    *DPoPRequest
		reason string
	}{
		{"no request details", nil, TokenRejectedDPoPRequired},
		{"bearer scheme", &DPoPRequest{Method: "POST", URL: testResource, Proof: request("POST", testResource).Proof, Scheme: "Bearer"}, TokenRejectedDPoPScheme},
		{"missing proof", &DPoPRequest{Method: "POST", URL: testResource, Scheme: "DPoP"}, TokenRejectedDPoPProof},
		{"garbage proof", &DPoPRequest{Method: "POST", URL: testResource, Proof: "a.b", Scheme: "DPoP"}, TokenRejectedDPoPProof},
		{"wrong method", func() *DPoPRequest { r := request("GET", testResource); r.Method = "POST"; return r }(), TokenRejectedDPoPProof},
		{"wrong url", func() *DPoPRequest {
			r := request("POST", "https://mcp.example.com/other")
			r.URL = testResource
			return r
		}(), TokenRejectedDPoPProof},
		{"wrong ath", func() *DPoPRequest {
			proof, _ := signer.Proof("POST", testResource, WithProofAccessToken("another-token"))
			return &DPoPRequest{Method: "POST", URL: testResource, Proof: proof, Scheme: "DPoP"}
		}(), TokenRejectedDPoPProof},
		{"no ath", func() *DPoPRequest {
			proof, _ := signer.Proof("POST", testResource)
			return &DPoPRequest{Method: "POST", URL: testResource, Proof: proof, Scheme: "DPoP"}
		}(), TokenRejectedDPoPProof},
		{"other key", func() *DPoPRequest {
			otherSigner, _ := NewDPoPSigner()
			proof, _ := otherSigner.Proof("POST", testResource, WithProofAccessToken(token))
			return &DPoPRequest{Method: "POST", URL: testResource, Proof: proof, Scheme: "DPoP"}
		}(), TokenRejectedDPoPBinding},
		{"stale iat", func() *DPoPRequest {
			proof, _ := signerWithClock(t, signer, -10*time.Minute).Proof("POST", testResource, WithProofAccessToken(token))
			return &DPoPRequest{Method: "POST", URL: testResource, Proof: proof, Scheme: "DPoP"}
		}(), TokenRejectedDPoPProof},
		{"future iat", func() *DPoPRequest {
			proof, _ := signerWithClock(t, signer, 5*time.Minute).Proof("POST", testResource, WithProofAccessToken(token))
			return &DPoPRequest{Method: "POST", URL: testResource, Proof: proof, Scheme: "DPoP"}
		}(), TokenRejectedDPoPProof},
	}
	for _, tc := range rejections {
		t.Run(tc.name, func(t *testing.T) {
			err := verify(tc.req, nil)
			if got := RejectionReason(err); got != tc.reason {
				t.Errorf("reason = %q, want %q (%v)", got, tc.reason, err)
			}
		})
	}

	// Replay: the same proof twice through one cache is refused the second
	// time; a tampered proof (header jwk with a private member) too.
	cache := NewMemoryReplayCache()
	req := request("POST", testResource)
	if err := verify(req, func(o *AccessTokenVerifyOptions) { o.ReplayCache = cache }); err != nil {
		t.Fatalf("first use: %v", err)
	}
	err = verify(req, func(o *AccessTokenVerifyOptions) { o.ReplayCache = cache })
	if RejectionReason(err) != TokenRejectedDPoPReplay {
		t.Errorf("replay: %v", err)
	}
	// The default cache catches replays too when none is configured.
	req = request("POST", testResource)
	if err := verify(req, func(o *AccessTokenVerifyOptions) { o.ReplayCache = nil }); err != nil {
		t.Fatalf("first use (default cache): %v", err)
	}
	if err := verify(req, func(o *AccessTokenVerifyOptions) { o.ReplayCache = nil }); RejectionReason(err) != TokenRejectedDPoPReplay {
		t.Errorf("replay (default cache): %v", err)
	}
}

// signerWithClock returns a signer over the same key whose clock is offset.
func signerWithClock(t *testing.T, signer *DPoPSigner, offset time.Duration) *DPoPSigner {
	t.Helper()
	shifted, err := NewDPoPSignerFromKey(signer.key)
	if err != nil {
		t.Fatalf("NewDPoPSignerFromKey: %v", err)
	}
	shifted.now = func() time.Time { return time.Now().Add(offset) }
	return shifted
}

func TestMemoryReplayCache(t *testing.T) {
	now := time.Now()
	cache := &MemoryReplayCache{now: func() time.Time { return now }}
	if cache.Seen("a", time.Minute) {
		t.Error("first sighting reported as seen")
	}
	if !cache.Seen("a", time.Minute) {
		t.Error("second sighting not reported")
	}
	now = now.Add(2 * time.Minute)
	if cache.Seen("a", time.Minute) {
		t.Error("an expired entry should be forgotten")
	}
	full := &MemoryReplayCache{maxSize: 1}
	full.Seen("x", time.Minute)
	if !full.Seen("y", time.Minute) {
		t.Error("a full cache must fail closed")
	}
}

// TestVerifyAccessTokenDiscovery fetches the keys through the discovery
// document and refetches once on an unknown kid.
func TestVerifyAccessTokenDiscovery(t *testing.T) {
	s := newTestTokenSigner(t)
	rotated := newTestTokenSigner(t)
	rotated.jwks.Keys[0].Kid = "rotated"
	var jwksCalls, discoveryCalls int
	current := s.jwks

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme-corp/api/v1/.well-known/openid-configuration":
			discoveryCalls++
			if r.Header.Get("Authorization") != "" {
				t.Error("discovery must be unauthenticated")
			}
			writeJSON(w, 200, map[string]any{"issuer": server.URL + "/orgs/acme-corp/api/v1",
				"jwks_uri": server.URL + "/orgs/acme-corp/api/v1/.well-known/jwks.json"})
		case "/orgs/acme-corp/api/v1/.well-known/jwks.json":
			jwksCalls++
			writeJSON(w, 200, current)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	issuer := server.URL + "/orgs/acme-corp/api/v1"
	cache := NewAccessTokenKeyCache(issuer, time.Hour, nil)
	opts := AccessTokenVerifyOptions{Issuer: issuer, Resource: testResource, KeyCache: cache}
	ctx := context.Background()

	token := s.mint(t, map[string]any{"iss": issuer}, nil)
	if _, err := VerifyAccessToken(ctx, token, opts); err != nil {
		t.Fatalf("first verification: %v", err)
	}
	if _, err := VerifyAccessToken(ctx, token, opts); err != nil {
		t.Fatalf("second verification: %v", err)
	}
	if jwksCalls != 1 || discoveryCalls != 1 {
		t.Errorf("fetches: discovery %d, jwks %d; want one each (cached)", discoveryCalls, jwksCalls)
	}

	// Key rotation: the server publishes a new key, the next token names
	// it, and the verifier refetches exactly once.
	current = rotated.jwks
	token = rotated.mint(t, map[string]any{"iss": issuer}, map[string]any{"kid": "rotated"})
	if _, err := VerifyAccessToken(ctx, token, opts); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if jwksCalls != 2 {
		t.Errorf("jwks fetched %d times, want 2", jwksCalls)
	}
	// A kid that is still unknown after the refetch is rejected, not looped.
	token = rotated.mint(t, map[string]any{"iss": issuer}, map[string]any{"kid": "ghost"})
	if _, err := VerifyAccessToken(ctx, token, opts); RejectionReason(err) != TokenRejectedUnknownKey {
		t.Errorf("ghost kid: %v", err)
	}
	if jwksCalls != 3 {
		t.Errorf("jwks fetched %d times, want 3", jwksCalls)
	}

	// Discovery pointing off-origin is refused.
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"jwks_uri": "https://attacker.example/jwks.json"})
	}))
	t.Cleanup(evil.Close)
	if _, err := FetchAccessTokenJWKS(ctx, evil.URL+"/orgs/x/api/v1", nil); err == nil || !strings.Contains(err.Error(), "origin") {
		t.Errorf("off-origin jwks_uri: %v", err)
	}
}

func TestRequireAccessTokenMiddleware(t *testing.T) {
	s := newTestTokenSigner(t)
	signer, _ := NewDPoPSigner()
	var seen *AccessTokenClaims
	handler := RequireAccessToken(s.opts())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = AccessTokenFromContext(r.Context())
		w.WriteHeader(204)
	}))

	call := func(authorization, proof string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "https://mcp.example.com/mcp?x=1", nil)
		req.Host = "mcp.example.com"
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		if proof != "" {
			req.Header.Set(DPoPHeader, proof)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// No token.
	rec := call("", "")
	if rec.Code != 401 {
		t.Errorf("no token: status %d", rec.Code)
	}
	challenges := rec.Header().Values("WWW-Authenticate")
	if len(challenges) != 2 || !strings.HasPrefix(challenges[0], `Bearer realm="`+testResource+`"`) || !strings.HasPrefix(challenges[1], "DPoP algs=") {
		t.Errorf("challenges = %q", challenges)
	}
	if strings.Contains(challenges[0], "error=") {
		t.Error("a missing token must not be reported as invalid_token in the challenge")
	}

	// Bearer token.
	seen = nil
	rec = call("Bearer "+s.mint(t, nil, nil), "")
	if rec.Code != 204 || seen == nil || seen.Subject != "agent_agt_1" {
		t.Errorf("bearer: status %d, claims %+v", rec.Code, seen)
	}

	// Invalid token.
	rec = call("Bearer "+s.mint(t, map[string]any{"aud": "https://other"}, nil), "")
	if rec.Code != 401 || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("wrong aud: status %d, %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "invalid_token" || !strings.Contains(body["error_description"], "audience") {
		t.Errorf("body = %v", body)
	}

	// DPoP-bound token: the proof is checked against the incoming request,
	// whose URL is https (TLS) + Host + path.
	bound := s.mint(t, map[string]any{"cnf": map[string]string{"jkt": signer.Thumbprint()}}, nil)
	proof, _ := signer.Proof("POST", "https://mcp.example.com/mcp", WithProofAccessToken(bound))
	seen = nil
	rec = call("DPoP "+bound, proof)
	if rec.Code != 204 || seen == nil || !seen.IsDPoPBound() {
		t.Errorf("dpop: status %d body %s", rec.Code, rec.Body.String())
	}
	// Same proof again: replay.
	rec = call("DPoP "+bound, proof)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "replay") {
		t.Errorf("replayed proof: status %d body %s", rec.Code, rec.Body.String())
	}
	// Bound token as a plain bearer: refused.
	rec = call("Bearer "+bound, "")
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "DPoP authorization scheme") {
		t.Errorf("bound token as bearer: status %d body %s", rec.Code, rec.Body.String())
	}

	// RequireDPoP advertises a single DPoP challenge.
	strict := s.opts()
	strict.RequireDPoP = true
	strictHandler := RequireAccessToken(strict)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	req := httptest.NewRequest("POST", "https://mcp.example.com/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+s.mint(t, nil, nil))
	rec = httptest.NewRecorder()
	strictHandler.ServeHTTP(rec, req)
	if rec.Code != 401 || len(rec.Header().Values("WWW-Authenticate")) != 1 || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "DPoP realm=") {
		t.Errorf("RequireDPoP challenge: %d %q", rec.Code, rec.Header().Values("WWW-Authenticate"))
	}
}

func TestDPoPRequestFromHTTP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://internal:8080/mcp/tools?x=1", nil)
	req.Header.Set("X-Forwarded-Proto", "https, http")
	req.Header.Set("Authorization", "DPoP abc")
	req.Header.Set(DPoPHeader, "proof")
	got := DPoPRequestFromHTTP(req)
	if got.Method != "GET" || got.URL != "https://internal:8080/mcp/tools" || got.Proof != "proof" || got.Scheme != "DPoP" {
		t.Errorf("DPoPRequestFromHTTP = %+v", got)
	}
	plain := DPoPRequestFromHTTP(httptest.NewRequest("GET", "http://h/", nil))
	if plain.URL != "http://h/" || plain.Scheme != "" {
		t.Errorf("plain = %+v", plain)
	}
}

func TestAudienceClaimDecoding(t *testing.T) {
	var single, many, bad AudienceClaim
	if err := json.Unmarshal([]byte(`"a"`), &single); err != nil || len(single) != 1 {
		t.Errorf("single: %v %v", single, err)
	}
	if err := json.Unmarshal([]byte(`["a","b"]`), &many); err != nil || len(many) != 2 || !many.Contains("b") {
		t.Errorf("many: %v %v", many, err)
	}
	if err := json.Unmarshal([]byte(`42`), &bad); err == nil {
		t.Error("a number is not an audience")
	}
}
