package lumoauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const assertionAgentID = "agt_0123456789abcdef"

func splitAssertion(t *testing.T, token string) (map[string]any, map[string]any, []byte, []byte) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	decode := func(part string) map[string]any {
		raw, err := b64urlDecode(part)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]any{}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	signature, err := b64urlDecode(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	return decode(parts[0]), decode(parts[1]), []byte(parts[0] + "." + parts[1]), signature
}

func verifyAssertion(t *testing.T, signer *ClientAssertionSigner, input, signature []byte) bool {
	t.Helper()
	jwk, err := signer.PublicJWK()
	if err != nil {
		t.Fatal(err)
	}
	public, err := jwk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := public.(ed25519.PublicKey); ok {
		return ed25519.Verify(key, input, signature)
	}
	h := signer.hash.New()
	h.Write(input)
	digest := h.Sum(nil)
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		size := (key.Curve.Params().BitSize + 7) / 8
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		return len(signature) == 2*size && ecdsa.Verify(key, digest, r, s)
	case *rsa.PublicKey:
		if strings.HasPrefix(signer.alg, "PS") {
			return rsa.VerifyPSS(key, signer.hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
		return rsa.VerifyPKCS1v15(key, signer.hash, digest, signature) == nil
	}
	return false
}

func TestClientAssertionHasTheClaimsTheServerChecksAndVerifies(t *testing.T) {
	issuer := IssuerFor("https://auth.example.test/", "acme")
	if issuer != "https://auth.example.test/orgs/acme/api/v1" {
		t.Fatalf("IssuerFor = %q", issuer)
	}
	for _, alg := range []string{"ES256", "ES384", "ES512", "EdDSA", "RS256", "PS256", "PS512"} {
		t.Run(alg, func(t *testing.T) {
			signer, err := GenerateClientAssertionSigner(alg, "k1")
			if err != nil {
				t.Fatal(err)
			}
			before := time.Now().Unix()
			token, err := signer.Assertion(assertionAgentID, issuer)
			if err != nil {
				t.Fatal(err)
			}
			header, claims, input, signature := splitAssertion(t, token)
			if header["alg"] != alg || header["typ"] != ClientAssertionTyp || header["kid"] != "k1" {
				t.Fatalf("header = %v", header)
			}
			if claims["iss"] != assertionAgentID || claims["sub"] != assertionAgentID || claims["aud"] != issuer {
				t.Fatalf("claims = %v", claims)
			}
			iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
			if iat < before || exp-iat != 60 {
				t.Fatalf("iat %d exp %d", iat, exp)
			}
			if jti, _ := claims["jti"].(string); len(jti) < 16 {
				t.Fatalf("jti too short: %q", jti)
			}
			if !verifyAssertion(t, signer, input, signature) {
				t.Fatal("signature does not verify with the public JWK")
			}
			jwk, _ := signer.PublicJWK()
			if jwk.Alg != alg || jwk.Use != "sig" || jwk.Kid != "k1" {
				t.Fatalf("jwk = %+v", jwk)
			}
		})
	}
}

func TestClientAssertionJTIsAreUniqueAndPEMRoundTrips(t *testing.T) {
	signer, err := GenerateClientAssertionSigner("ES256", "k1")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		token, _ := signer.Assertion(assertionAgentID, "https://issuer")
		_, claims, _, _ := splitAssertion(t, token)
		seen[claims["jti"].(string)] = true
	}
	if len(seen) != 20 {
		t.Fatalf("expected 20 unique jtis, got %d", len(seen))
	}
	pemData, err := signer.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadClientAssertionSigner(pemData, ClientAssertionOptions{KeyID: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := signer.JWKS()
	b, _ := loaded.JWKS()
	if a.Keys[0] != b.Keys[0] {
		t.Fatalf("JWKS differ: %+v vs %+v", a, b)
	}
}

func TestClientAssertionSignerRefusesMisfits(t *testing.T) {
	ec, _ := GenerateClientAssertionSigner("ES256", "")
	if _, err := NewClientAssertionSigner(ec.key, ClientAssertionOptions{Algorithm: "ES384"}); err == nil {
		t.Fatal("ES384 on a P-256 key must be refused")
	}
	if _, err := NewClientAssertionSigner(ec.key, ClientAssertionOptions{Lifetime: 11 * time.Minute}); err == nil {
		t.Fatal("a lifetime above 10 minutes must be refused")
	}
	if _, err := GenerateClientAssertionSigner("HS256", ""); err == nil {
		t.Fatal("HS256 must be refused")
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClientAssertionSigner(small, ClientAssertionOptions{}); err == nil {
		t.Fatal("a 1024-bit RSA key must be refused")
	}
	var _ crypto.Signer = small
}

func TestAgentAuthenticatesWithAnAssertionAndNoSecret(t *testing.T) {
	t.Setenv(EnvAgentClientSecret, "left-over-secret")
	signer, err := GenerateClientAssertionSigner("EdDSA", "agent-key")
	if err != nil {
		t.Fatal(err)
	}
	var form url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme/api/v1/oauth/token" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = r.ParseForm()
		form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	agent, err := NewAgent(AgentConfig{BaseURL: server.URL, OrgID: "acme", ClientID: assertionAgentID, PrivateKey: signer})
	if err != nil {
		t.Fatal(err)
	}
	token, err := agent.Authenticate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != "at-1" {
		t.Fatalf("token = %q", token)
	}
	if form.Get("grant_type") != "client_credentials" || form.Get("client_id") != assertionAgentID || form.Get("client_assertion_type") != ClientAssertionType {
		t.Fatalf("form = %v", form)
	}
	if form.Has("client_secret") {
		t.Fatal("one authentication method per request: no client_secret with an assertion")
	}
	header, claims, input, signature := splitAssertion(t, form.Get("client_assertion"))
	if header["kid"] != "agent-key" || claims["aud"] != IssuerFor(server.URL, "acme") {
		t.Fatalf("header %v claims %v", header, claims)
	}
	if !verifyAssertion(t, signer, input, signature) {
		t.Fatal("the assertion does not verify")
	}
}

func TestAgentReadsThePrivateKeyFromTheEnvironment(t *testing.T) {
	signer, _ := GenerateClientAssertionSigner("ES256", "")
	pemData, _ := signer.PrivateKeyPEM()
	t.Setenv(EnvAgentClientID, assertionAgentID)
	t.Setenv(EnvAgentPrivateKey, pemData)
	t.Setenv(EnvAgentKeyID, "env-key")
	t.Setenv(EnvOrgID, "acme")

	agent, err := NewAgent(AgentConfig{BaseURL: "https://auth.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := agent.ClientAssertion()
	if err != nil {
		t.Fatal(err)
	}
	header, _, _, _ := splitAssertion(t, token)
	if header["kid"] != "env-key" || header["alg"] != "ES256" {
		t.Fatalf("header = %v", header)
	}
}

func TestAgentRefusesASecretTogetherWithAPrivateKey(t *testing.T) {
	signer, _ := GenerateClientAssertionSigner("ES256", "")
	if _, err := NewAgent(AgentConfig{BaseURL: "https://auth.example.test", OrgID: "acme", ClientID: assertionAgentID, ClientSecret: "s", PrivateKey: signer}); err == nil {
		t.Fatal("a secret and a private key together must be refused")
	}
}

func TestCustomIssuerIsTheAudience(t *testing.T) {
	signer, _ := GenerateClientAssertionSigner("ES256", "")
	agent, err := NewAgent(AgentConfig{BaseURL: "https://auth.acme.com", OrgID: "acme", ClientID: assertionAgentID, PrivateKey: signer, Issuer: "https://auth.acme.com"})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := agent.ClientAssertion()
	_, claims, _, _ := splitAssertion(t, token)
	if claims["aud"] != "https://auth.acme.com" {
		t.Fatalf("aud = %v", claims["aud"])
	}
}
