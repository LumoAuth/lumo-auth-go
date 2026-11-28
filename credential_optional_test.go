package lumoauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ── GO-7: a client without a credential ───────────────────────────────

func TestNewWithoutCredentialBuildsAddresses(t *testing.T) {
	t.Setenv(EnvAPIKey, "")

	// Without the option, New still refuses, and says how to opt in.
	if _, err := New(WithOrgID("acme-corp")); !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "WithoutCredential") {
		t.Fatalf("New without a credential: err = %v, want a config error that names WithoutCredential", err)
	}

	client, err := New(WithBaseURL("https://app.lumoauth.dev"), WithOrgID("acme-corp"), WithoutCredential())
	if err != nil {
		t.Fatalf("New(WithoutCredential): %v", err)
	}
	authorize, err := client.Auth.AuthorizationURL(AuthorizationURLParams{
		ClientID: "client_1", RedirectURI: "https://app.example.com/callback", State: "s",
	})
	if err != nil || !strings.HasPrefix(authorize, "https://app.lumoauth.dev/orgs/acme-corp/api/v1/oauth/authorize?") {
		t.Errorf("AuthorizationURL = %q, %v", authorize, err)
	}
	if issuer, err := client.Issuer(); err != nil || issuer != "https://app.lumoauth.dev/orgs/acme-corp/api/v1" {
		t.Errorf("Issuer = %q, %v", issuer, err)
	}
	if logout, err := client.Auth.EndSessionURL(EndSessionURLParams{IDTokenHint: "h"}); err != nil || !strings.Contains(logout, "/oauth/logout?id_token_hint=h") {
		t.Errorf("EndSessionURL = %q, %v", logout, err)
	}

	// On a custom domain no organization ID is needed either.
	custom, err := New(WithCustomDomain("auth.acme.com"), WithoutCredential())
	if err != nil {
		t.Fatalf("New(custom domain, WithoutCredential): %v", err)
	}
	if got, _ := custom.Auth.AuthorizationURL(AuthorizationURLParams{ClientID: "c", RedirectURI: "https://app.example.com/cb"}); !strings.HasPrefix(got, "https://auth.acme.com/api/v1/oauth/authorize?") {
		t.Errorf("custom-domain AuthorizationURL = %q", got)
	}
	if issuer, _ := custom.Issuer(); issuer != "https://auth.acme.com" {
		t.Errorf("custom-domain Issuer = %q", issuer)
	}
}

func TestClientWithoutCredentialSendsNone(t *testing.T) {
	t.Setenv(EnvAPIKey, "")
	var tokenForm url.Values
	var protected http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			_ = r.ParseForm()
			tokenForm = r.Form
			writeJSON(w, 200, map[string]any{"access_token": "at", "token_type": "Bearer"})
		default:
			protected = r.Header.Clone()
			writeJSON(w, 401, map[string]any{"error": "unauthorized", "error_description": "Authentication required"})
		}
	}))
	t.Cleanup(server.Close)

	client, err := New(WithBaseURL(server.URL), WithOrgID("acme-corp"), WithoutCredential())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// GO-8: an application that holds only a private key reaches the
	// assertion grant without a stand-in credential.
	signer, err := GenerateClientAssertionSigner("ES256", "app-key-1")
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := client.Issuer()
	assertion, err := signer.Assertion("client_1", issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Auth.ClientCredentialsWithAssertion(ctx, "client_1", assertion); err != nil {
		t.Fatalf("ClientCredentialsWithAssertion: %v", err)
	}
	if tokenForm.Get("client_assertion") != assertion {
		t.Errorf("token form = %v", tokenForm)
	}

	// A call that needs a credential goes out without one, and the server's
	// refusal is the usual authentication error.
	_, err = client.Permissions.Check(ctx, "documents.read", nil)
	if !errors.Is(err, ErrAuthentication) {
		t.Errorf("err = %v, want ErrAuthentication", err)
	}
	if protected.Get("Authorization") != "" || protected.Get("X-API-Key") != "" {
		t.Errorf("no credential should be sent: %v", protected)
	}
	if _, err := client.APIConfig(ctx); !errors.Is(err, ErrConfig) {
		t.Errorf("APIConfig without a credential: err = %v, want a config error", err)
	}
}

// ── GO-8: an expected DPoP nonce on the resource server ───────────────

func TestVerifyAccessTokenDPoPNonce(t *testing.T) {
	s := newTestTokenSigner(t)
	signer, _ := NewDPoPSigner()
	token := s.mint(t, map[string]any{"cnf": map[string]string{"jkt": signer.Thumbprint()}}, nil)
	ctx := context.Background()

	verify := func(proofNonce, expected string) error {
		opts := []DPoPProofOption{WithProofAccessToken(token)}
		if proofNonce != "" {
			opts = append(opts, WithProofNonce(proofNonce))
		}
		proof, err := signer.Proof("POST", testResource, opts...)
		if err != nil {
			t.Fatal(err)
		}
		o := s.opts()
		o.DPoP = &DPoPRequest{Method: "POST", URL: testResource, Proof: proof, Scheme: "DPoP", Nonce: expected}
		_, err = VerifyAccessToken(ctx, token, o)
		return err
	}

	if err := verify("n-1", "n-1"); err != nil {
		t.Errorf("matching nonce: %v", err)
	}
	if err := verify("", ""); err != nil {
		t.Errorf("no nonce expected: %v", err)
	}
	if err := verify("n-1", ""); err != nil {
		t.Errorf("a nonce that nobody expects is not checked: %v", err)
	}
	for name, proofNonce := range map[string]string{"missing": "", "stale": "n-0"} {
		if err := verify(proofNonce, "n-1"); RejectionReason(err) != TokenRejectedDPoPNonce {
			t.Errorf("%s nonce: reason %q (%v), want %q", name, RejectionReason(err), err, TokenRejectedDPoPNonce)
		}
	}
}

func TestRequireAccessTokenAsksForTheNonce(t *testing.T) {
	s := newTestTokenSigner(t)
	signer, _ := NewDPoPSigner()
	token := s.mint(t, map[string]any{"cnf": map[string]string{"jkt": signer.Thumbprint()}}, nil)

	opts := s.opts()
	opts.DPoPNonce = func(*http.Request) string { return "rs-nonce-7" }
	handler := RequireAccessToken(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))

	call := func(proofOpts ...DPoPProofOption) *httptest.ResponseRecorder {
		proof, _ := signer.Proof("POST", "https://mcp.example.com/mcp", append([]DPoPProofOption{WithProofAccessToken(token)}, proofOpts...)...)
		req := httptest.NewRequest("POST", "https://mcp.example.com/mcp", nil)
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set(DPoPHeader, proof)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Without the nonce: RFC 9449 §9 use_dpop_nonce with the nonce to use.
	rec := call()
	if rec.Code != 401 || rec.Header().Get(DPoPNonceHeader) != "rs-nonce-7" ||
		!strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
		t.Fatalf("status %d, DPoP-Nonce %q, challenge %q", rec.Code, rec.Header().Get(DPoPNonceHeader), rec.Header().Values("WWW-Authenticate"))
	}
	if !strings.Contains(rec.Body.String(), "use_dpop_nonce") {
		t.Errorf("body = %s", rec.Body.String())
	}

	// With the nonce the request goes through.
	if rec := call(WithProofNonce("rs-nonce-7")); rec.Code != 204 {
		t.Errorf("with the nonce: status %d body %s", rec.Code, rec.Body.String())
	}
}

// ── SDK-EXCH: client authentication on the token exchange ─────────────

func TestTokenExchangeClientAuthentication(t *testing.T) {
	type seen struct {
		form   url.Values
		header http.Header
	}
	var requests []seen
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		requests = append(requests, seen{r.PostForm, r.Header.Clone()})
		writeJSON(w, 200, map[string]any{"access_token": "exchanged", "token_type": "Bearer",
			"issued_token_type": TokenTypeAccessToken})
	})
	ctx := context.Background()
	base := TokenExchangeParams{SubjectToken: "user-token", Resource: "https://api.example.com/"}

	// client_secret_basic (the default for a secret).
	basic := base
	basic.ClientID, basic.ClientSecret = "client_1", "s3cret"
	if _, err := client.Auth.TokenExchange(ctx, basic); err != nil {
		t.Fatalf("basic: %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("client_1:s3cret"))
	if got := requests[0].header.Get("Authorization"); got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
	if requests[0].form.Has("client_secret") || requests[0].form.Has("client_id") {
		t.Errorf("basic: the secret must not also be in the body: %v", requests[0].form)
	}
	if requests[0].header.Get("X-API-Key") != "" {
		t.Error("the client's API key must not be sent to the token endpoint")
	}

	// client_secret_post.
	post := basic
	post.ClientAuthMethod = ClientSecretPost
	if _, err := client.Auth.TokenExchange(ctx, post); err != nil {
		t.Fatalf("post: %v", err)
	}
	if f := requests[1].form; f.Get("client_id") != "client_1" || f.Get("client_secret") != "s3cret" || requests[1].header.Get("Authorization") != "" {
		t.Errorf("post: form %v, Authorization %q", f, requests[1].header.Get("Authorization"))
	}

	// private_key_jwt.
	jwt := base
	jwt.ClientID, jwt.ClientAssertion = "client_1", "eyJ.assertion.sig"
	if _, err := client.Auth.TokenExchange(ctx, jwt); err != nil {
		t.Fatalf("assertion: %v", err)
	}
	if f := requests[2].form; f.Get("client_assertion") != "eyJ.assertion.sig" || f.Get("client_assertion_type") != ClientAssertionType ||
		f.Get("client_id") != "client_1" || f.Has("client_secret") {
		t.Errorf("assertion form = %v", f)
	}

	// No client authentication: the agent on-behalf-of exchange, as before.
	agent := base
	agent.ActorToken = "agent-token"
	if _, err := client.Auth.TokenExchange(ctx, agent); err != nil {
		t.Fatalf("agent: %v", err)
	}
	if f := requests[3].form; f.Has("client_id") || f.Has("client_secret") || requests[3].header.Get("Authorization") != "" {
		t.Errorf("an exchange without client authentication must send none: %v", f)
	}

	for name, params := range map[string]TokenExchangeParams{
		"secret without client ID": {SubjectToken: "t", ClientSecret: "s"},
		"secret and assertion":     {SubjectToken: "t", ClientID: "c", ClientSecret: "s", ClientAssertion: "a"},
		"unknown method":           {SubjectToken: "t", ClientID: "c", ClientSecret: "s", ClientAuthMethod: "tls_client_auth"},
		"method without a secret":  {SubjectToken: "t", ClientID: "c", ClientAssertion: "a", ClientAuthMethod: ClientSecretPost},
	} {
		if _, err := client.Auth.TokenExchange(ctx, params); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
}

func TestTokenExchangeBasicAuthKeepsTheDPoPProof(t *testing.T) {
	signer, _ := NewDPoPSigner()
	var got http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		writeJSON(w, 200, map[string]any{"access_token": "exchanged", "token_type": "DPoP"})
	}))
	t.Cleanup(server.Close)
	client, err := New(WithBaseURL(server.URL), WithOrgID("acme-corp"), WithoutCredential(), WithDPoP(signer))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Auth.TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: "user-token", ClientID: "client_1", ClientSecret: "s3cret",
	}); err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if got.Get(DPoPHeader) == "" || !strings.HasPrefix(got.Get("Authorization"), "Basic ") {
		t.Errorf("headers = %v, want a DPoP proof and Basic authentication", got)
	}
}

func TestClientCredentialsWithBasicAuthentication(t *testing.T) {
	var got *http.Request
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r
		writeJSON(w, 200, map[string]any{"access_token": "at"})
	})
	if _, err := client.Auth.ClientCredentialsWithParams(context.Background(), ClientCredentialsParams{
		ClientID: "client_1", ClientSecret: "s3cret", ClientAuthMethod: ClientSecretBasic,
	}); err != nil {
		t.Fatal(err)
	}
	if id, secret, ok := got.BasicAuth(); !ok || id != "client_1" || secret != "s3cret" || got.PostForm.Has("client_secret") {
		t.Errorf("basic auth = %v %q %q, form %v", ok, id, secret, got.PostForm)
	}
}
