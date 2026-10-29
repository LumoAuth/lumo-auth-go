package lumoauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// decodeProof splits a DPoP proof into its header and claims without
// verifying it; the signature is checked separately where it matters.
func decodeProof(t *testing.T, proof string) (header, claims map[string]any, parts []string) {
	t.Helper()
	parts = strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof has %d segments, want 3", len(parts))
	}
	var err error
	if header, err = decodeJWTSegment(parts[0]); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if claims, err = decodeJWTSegment(parts[1]); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	return header, claims, parts
}

// boundToken is an unsigned JWT with cnf.jkt, enough for the client-side
// scheme choice (DPoPBound reads the payload without verifying it).
func boundToken(jkt string) string {
	header := b64url([]byte(`{"alg":"RS256","typ":"at+jwt","kid":"k"}`))
	payload, _ := json.Marshal(map[string]any{"sub": "agent_agt_1", "cnf": map[string]string{"jkt": jkt}})
	return header + "." + b64url(payload) + ".sig"
}

func TestDPoPProofShapeES256(t *testing.T) {
	signer, err := NewDPoPSigner()
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	before := time.Now().Unix()
	proof, err := signer.Proof("post", "https://app.lumoauth.dev/orgs/acme/api/v1/oauth/token?x=1#frag",
		WithProofAccessToken("tok"), WithProofNonce("n-1"))
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	header, claims, parts := decodeProof(t, proof)

	if header["typ"] != "dpop+jwt" || header["alg"] != "ES256" {
		t.Errorf("header = %v", header)
	}
	jwk, _ := header["jwk"].(map[string]any)
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["x"] == nil || jwk["y"] == nil {
		t.Errorf("jwk = %v", jwk)
	}
	if _, leaked := jwk["d"]; leaked {
		t.Error("the proof header leaks the private key")
	}
	for _, member := range []string{"use", "kid", "alg"} {
		if _, present := jwk[member]; present {
			t.Errorf("jwk carries %s, which the proof should omit", member)
		}
	}

	if claims["htm"] != "POST" {
		t.Errorf("htm = %v", claims["htm"])
	}
	if claims["htu"] != "https://app.lumoauth.dev/orgs/acme/api/v1/oauth/token" {
		t.Errorf("htu = %v (query and fragment must be stripped)", claims["htu"])
	}
	if jti, _ := claims["jti"].(string); len(jti) < 16 {
		t.Errorf("jti = %q, want at least 16 characters", jti)
	}
	iat, _ := jsonInt64(claims["iat"])
	if iat < before || iat > time.Now().Unix() {
		t.Errorf("iat = %d, now = %d", iat, time.Now().Unix())
	}
	if claims["nonce"] != "n-1" {
		t.Errorf("nonce = %v", claims["nonce"])
	}
	sum := sha256.Sum256([]byte("tok"))
	if claims["ath"] != b64url(sum[:]) {
		t.Errorf("ath = %v", claims["ath"])
	}

	// The signature is raw r||s (64 bytes) and verifies with the header key.
	signature, err := b64urlDecode(parts[2])
	if err != nil || len(signature) != 64 {
		t.Fatalf("signature: %d bytes, err %v", len(signature), err)
	}
	public := signer.PublicJWK()
	key, err := public.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !verifyJWS("ES256", []byte(parts[0]+"."+parts[1]), signature, key) {
		t.Error("the proof signature does not verify")
	}

	// Two proofs never share a jti.
	again, _ := signer.Proof("POST", "https://app.lumoauth.dev/x")
	_, claims2, _ := decodeProof(t, again)
	if claims2["jti"] == claims["jti"] {
		t.Error("jti repeated across proofs")
	}
	if _, present := claims2["ath"]; present {
		t.Error("ath present without an access token")
	}
	if _, present := claims2["nonce"]; present {
		t.Error("nonce present without one remembered")
	}
}

func TestDPoPProofEdDSA(t *testing.T) {
	signer, err := NewDPoPSignerEd25519()
	if err != nil {
		t.Fatalf("NewDPoPSignerEd25519: %v", err)
	}
	proof, err := signer.Proof("GET", "https://mcp.example.com/mcp")
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	header, _, parts := decodeProof(t, proof)
	if header["alg"] != "EdDSA" {
		t.Errorf("alg = %v", header["alg"])
	}
	jwk, _ := header["jwk"].(map[string]any)
	if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
		t.Errorf("jwk = %v", jwk)
	}
	signature, _ := b64urlDecode(parts[2])
	public := signer.PublicJWK()
	key, _ := public.PublicKey()
	if !verifyJWS("EdDSA", []byte(parts[0]+"."+parts[1]), signature, key) {
		t.Error("the EdDSA proof signature does not verify")
	}
}

func TestDPoPSignerRejectsOtherKeys(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewDPoPSignerFromKey(p384); err == nil {
		t.Error("a P-384 key should be refused (ES256 needs P-256)")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := NewDPoPSignerFromKey(rsaKey); err == nil {
		t.Error("an RSA key should be refused")
	}
}

func TestDPoPThumbprintRFC7638(t *testing.T) {
	// RFC 7638 §3.1 example key and thumbprint.
	jwk := JWK{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
	}
	got, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Errorf("thumbprint = %s", got)
	}

	// An EC signer's thumbprint is SHA-256 over {"crv","kty","x","y"} in
	// that order with no whitespace — and it matches what a verifier
	// computes from the proof header.
	signer, _ := NewDPoPSigner()
	pub := signer.PublicJWK()
	canonical := `{"crv":"P-256","kty":"EC","x":"` + pub.X + `","y":"` + pub.Y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	if signer.Thumbprint() != b64url(sum[:]) {
		t.Errorf("EC thumbprint = %s, want %s", signer.Thumbprint(), b64url(sum[:]))
	}
	proof, _ := signer.Proof("GET", "https://x.example/")
	header, _, _ := decodeProof(t, proof)
	raw, _ := json.Marshal(header["jwk"])
	var fromHeader JWK
	_ = json.Unmarshal(raw, &fromHeader)
	fromHeaderJKT, _ := fromHeader.Thumbprint()
	if fromHeaderJKT != signer.Thumbprint() {
		t.Errorf("header jwk thumbprint %s != signer thumbprint %s", fromHeaderJKT, signer.Thumbprint())
	}
}

func TestDPoPSignerPEMRoundTrip(t *testing.T) {
	pemData, err := GenerateDPoPKeyPEM()
	if err != nil {
		t.Fatalf("GenerateDPoPKeyPEM: %v", err)
	}
	a, err := LoadDPoPSigner(pemData)
	if err != nil {
		t.Fatalf("LoadDPoPSigner: %v", err)
	}
	b, err := LoadDPoPSigner(pemData)
	if err != nil {
		t.Fatalf("LoadDPoPSigner (again): %v", err)
	}
	if a.Thumbprint() != b.Thumbprint() || a.Algorithm() != "ES256" {
		t.Errorf("loading the same PEM twice gave different keys: %s vs %s", a.Thumbprint(), b.Thumbprint())
	}
	if _, err := LoadDPoPSigner("not pem"); err == nil {
		t.Error("garbage PEM should fail")
	}
}

func TestDPoPNonceMemoryPerOrigin(t *testing.T) {
	signer, _ := NewDPoPSigner()
	signer.SetNonce("https://app.lumoauth.dev/orgs/acme/api/v1/oauth/token", "nonce-a")

	proof, _ := signer.Proof("POST", "https://app.lumoauth.dev/orgs/acme/api/v1/agents/me")
	_, claims, _ := decodeProof(t, proof)
	if claims["nonce"] != "nonce-a" {
		t.Errorf("same-origin proof nonce = %v", claims["nonce"])
	}
	proof, _ = signer.Proof("POST", "https://mcp.example.com/mcp")
	_, claims, _ = decodeProof(t, proof)
	if _, present := claims["nonce"]; present {
		t.Error("nonce leaked to another origin")
	}

	resp := &http.Response{Header: http.Header{},
		Request: httptest.NewRequest("GET", "https://mcp.example.com/tools", nil)}
	resp.Header.Set(DPoPNonceHeader, "nonce-b")
	if !signer.RememberNonce(resp) {
		t.Error("RememberNonce should report the header")
	}
	if signer.Nonce("https://mcp.example.com/other") != "nonce-b" {
		t.Errorf("Nonce = %q", signer.Nonce("https://mcp.example.com/other"))
	}
	proof, _ = signer.Proof("GET", "https://mcp.example.com/mcp", WithProofNonce(""))
	_, claims, _ = decodeProof(t, proof)
	if _, present := claims["nonce"]; present {
		t.Error("WithProofNonce(\"\") should omit the nonce")
	}

	// Concurrent use.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			signer.SetNonce("https://mcp.example.com", "n")
			_, _ = signer.Proof("GET", "https://mcp.example.com/mcp")
		}()
	}
	wg.Wait()
}

func TestDPoPAuthorizeRequest(t *testing.T) {
	signer, _ := NewDPoPSigner()

	req := httptest.NewRequest("POST", "https://mcp.example.com/mcp?x=1", nil)
	if err := signer.AuthorizeRequest(req, "opaque-bearer"); err != nil {
		t.Fatalf("AuthorizeRequest: %v", err)
	}
	if req.Header.Get("Authorization") != "Bearer opaque-bearer" || req.Header.Get(DPoPHeader) != "" {
		t.Errorf("unbound token: Authorization=%q DPoP=%q", req.Header.Get("Authorization"), req.Header.Get(DPoPHeader))
	}

	token := boundToken(signer.Thumbprint())
	if err := signer.AuthorizeRequest(req, token); err != nil {
		t.Fatalf("AuthorizeRequest (bound): %v", err)
	}
	if req.Header.Get("Authorization") != "DPoP "+token {
		t.Errorf("bound token: Authorization=%q", req.Header.Get("Authorization"))
	}
	_, claims, _ := decodeProof(t, req.Header.Get(DPoPHeader))
	if claims["htm"] != "POST" || claims["htu"] != "https://mcp.example.com/mcp" || claims["ath"] != DPoPAccessTokenHash(token) {
		t.Errorf("proof claims = %v", claims)
	}
	if !DPoPBound(token) || DPoPBound("opaque") {
		t.Error("DPoPBound misreports")
	}
}

// TestAgentDPoPNonceRetryAndBoundCalls exercises the full client path: the
// client-credentials request carries a proof, the server's use_dpop_nonce
// answer is retried once with the nonce, the bound token comes back with
// token_type DPoP, and later API calls present it with the DPoP scheme and
// a proof carrying ath. The MCP exchange also carries a proof.
func TestAgentDPoPNonceRetryAndBoundCalls(t *testing.T) {
	signer, _ := NewDPoPSigner()
	var tokenCalls int
	var sawNonce []string
	agentToken := boundToken(signer.Thumbprint())

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof := r.Header.Get(DPoPHeader)
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			tokenCalls++
			if proof == "" {
				t.Error("token request carries no DPoP proof")
			}
			if r.Header.Get("Authorization") != "" {
				t.Error("token request must not carry an Authorization header")
			}
			_, claims, _ := decodeProof(t, proof)
			if claims["htm"] != "POST" || claims["htu"] != server.URL+"/orgs/acme-corp/api/v1/oauth/token" {
				t.Errorf("token proof htm/htu = %v/%v", claims["htm"], claims["htu"])
			}
			if _, present := claims["ath"]; present {
				t.Error("token-endpoint proof must not carry ath")
			}
			nonce, _ := claims["nonce"].(string)
			sawNonce = append(sawNonce, nonce)
			_ = r.ParseForm()
			if nonce != "server-nonce-1" && nonce != "server-nonce-2" {
				w.Header().Set(DPoPNonceHeader, "server-nonce-1")
				writeJSON(w, 400, map[string]any{"error": "use_dpop_nonce",
					"error_description": "Authorization server requires a fresh nonce in the DPoP proof"})
				return
			}
			w.Header().Set(DPoPNonceHeader, "server-nonce-2")
			switch r.Form.Get("grant_type") {
			case "client_credentials":
				writeJSON(w, 200, map[string]any{"access_token": agentToken, "token_type": "DPoP", "expires_in": 3600})
			case GrantTypeTokenExchange:
				if r.Form.Get("subject_token") != agentToken || r.Form.Get("resource") != "https://mcp.example.com/mcp" {
					t.Errorf("exchange form = %v", r.Form)
				}
				writeJSON(w, 200, map[string]any{"access_token": boundToken(signer.Thumbprint()), "token_type": "DPoP", "expires_in": 300})
			default:
				t.Errorf("unexpected grant %q", r.Form.Get("grant_type"))
			}
		case strings.HasSuffix(r.URL.Path, "/agents/me"):
			if r.Header.Get("Authorization") != "DPoP "+agentToken {
				t.Errorf("Authorization = %q, want the DPoP scheme", r.Header.Get("Authorization"))
			}
			_, claims, _ := decodeProof(t, proof)
			if claims["ath"] != DPoPAccessTokenHash(agentToken) || claims["htm"] != "GET" {
				t.Errorf("resource proof claims = %v", claims)
			}
			if claims["nonce"] != "server-nonce-2" {
				t.Errorf("resource proof nonce = %v, want the latest token-endpoint nonce", claims["nonce"])
			}
			writeJSON(w, 200, map[string]any{"agent_id": "agt_1", "name": "Bot"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)

	agent, err := NewAgent(AgentConfig{
		BaseURL: server.URL, OrgID: "acme-corp", ClientID: "agent-client", ClientSecret: "agent-secret",
		DPoP: signer,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	if agent.DPoP() != signer {
		t.Error("Agent.DPoP should return the configured signer")
	}
	if agent.TokenType() != "" {
		t.Errorf("TokenType before auth = %q", agent.TokenType())
	}

	ctx := context.Background()
	if _, err := agent.Identity(ctx, false); err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if tokenCalls != 2 {
		t.Errorf("token endpoint called %d times, want 2 (nonce retry)", tokenCalls)
	}
	if len(sawNonce) != 2 || sawNonce[0] != "" || sawNonce[1] != "server-nonce-1" {
		t.Errorf("nonces seen = %q", sawNonce)
	}
	if agent.TokenType() != DPoPTokenType {
		t.Errorf("TokenType = %q", agent.TokenType())
	}

	mcp, err := agent.Mcp.TokenDetailed(ctx, "https://mcp.example.com/mcp", "")
	if err != nil {
		t.Fatalf("TokenDetailed: %v", err)
	}
	if mcp.TokenType != "DPoP" {
		t.Errorf("MCP token_type = %q", mcp.TokenType)
	}
	if tokenCalls != 3 {
		t.Errorf("token endpoint called %d times after the exchange, want 3 (nonce remembered, no retry)", tokenCalls)
	}
}

func TestDPoPNonceRetryOnlyOnce(t *testing.T) {
	signer, _ := NewDPoPSigner()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set(DPoPNonceHeader, "always-new")
		writeJSON(w, 400, map[string]any{"error": "use_dpop_nonce"})
	}))
	t.Cleanup(server.Close)

	client, err := New(WithBaseURL(server.URL), WithOrgID("acme"), WithAPIKey("k"), WithDPoP(signer))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.DPoP() != signer {
		t.Error("Client.DPoP should return the signer")
	}
	_, err = client.Auth.ClientCredentials(context.Background(), "id", "secret")
	if err == nil || ErrorCode(err) != "use_dpop_nonce" {
		t.Fatalf("err = %v", err)
	}
	if calls != 2 {
		t.Errorf("token endpoint called %d times, want exactly 2", calls)
	}
}

func TestClientWithoutDPoPSendsNoProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(DPoPHeader) != "" {
			t.Error("a client without a signer must not send a DPoP header")
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && r.URL.Path != "/orgs/acme/api/v1/oauth/token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		writeJSON(w, 200, map[string]any{"access_token": "t", "agent_id": "a"})
	}))
	t.Cleanup(server.Close)
	client, _ := New(WithBaseURL(server.URL), WithOrgID("acme"), WithAccessToken(boundToken("jkt")))
	if _, err := client.Agents.Me(context.Background()); err != nil {
		t.Fatalf("Me: %v", err)
	}
	if _, err := client.Auth.ClientCredentials(context.Background(), "id", "secret"); err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
}

func TestAPIConfigRefusesBoundToken(t *testing.T) {
	signer, _ := NewDPoPSigner()
	client, _ := New(WithBaseURL("https://x.example"), WithOrgID("acme"),
		WithAccessToken(boundToken(signer.Thumbprint())), WithDPoP(signer))
	if _, err := client.APIConfig(context.Background()); err == nil || ErrorCode(err) != CodeConfig {
		t.Errorf("APIConfig with a bound token: err = %v, want a config error", err)
	}
}
