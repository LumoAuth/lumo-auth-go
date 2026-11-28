package lumoauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The consent flow of SRV-47: the person signs in to an APPLICATION of the
// organization, the application redeems the code (PKCE, its own client ID
// and secret), the agent exchanges the person's token, and the application
// revokes the person's refresh token.

var testApplication = DelegationApplication{
	ClientID:      "client_app_1",
	ClientSecret:  "app-secret",
	RedirectURI:   "https://app.example.com/agent/callback",
	OfflineAccess: true,
}

func newTestAppChain(t *testing.T, state *delegationServer, app DelegationApplication) *DelegationChain {
	t.Helper()
	state.t = t
	server := httptest.NewServer(state.handler())
	t.Cleanup(server.Close)
	agent, err := NewAgent(AgentConfig{
		BaseURL: server.URL, OrgID: "acme-corp",
		ClientID: "agt_0123456789abcdef", ClientSecret: "agent-secret",
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	chain, err := NewDelegationChainForApplication(agent, app)
	if err != nil {
		t.Fatalf("NewDelegationChainForApplication: %v", err)
	}
	return chain
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestNewDelegationChainForApplicationValidates(t *testing.T) {
	agent, err := NewAgent(AgentConfig{BaseURL: "https://app.lumoauth.dev", OrgID: "acme-corp",
		ClientID: "agt_0123456789abcdef", ClientSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	for name, app := range map[string]DelegationApplication{
		"no client ID":             {RedirectURI: "https://app.example.com/cb"},
		"an agent ID":              {ClientID: "agt_0123456789abcdef", RedirectURI: "https://app.example.com/cb"},
		"no redirect URI":          {ClientID: "client_app_1"},
		"relative redirect":        {ClientID: "client_app_1", RedirectURI: "/cb"},
		"redirect with a fragment": {ClientID: "client_app_1", RedirectURI: "https://app.example.com/cb#x"},
	} {
		if _, err := NewDelegationChainForApplication(agent, app); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: err = %v, want a config error", name, err)
		}
	}
}

func TestDelegationConsentThroughAnApplication(t *testing.T) {
	state := &delegationServer{}
	chain := newTestAppChain(t, state, testApplication)
	ctx := context.Background()

	// 1. The consent URL names the application, with PKCE and offline_access.
	consent, err := chain.ConsentURL("session-1", []string{"documents:read"}, "")
	if err != nil {
		t.Fatalf("ConsentURL: %v", err)
	}
	parsed, _ := url.Parse(consent)
	query := parsed.Query()
	if parsed.Path != "/orgs/acme-corp/api/v1/oauth/authorize" {
		t.Errorf("path = %q", parsed.Path)
	}
	if query.Get("client_id") != "client_app_1" || query.Get("redirect_uri") != testApplication.RedirectURI {
		t.Errorf("client_id / redirect_uri = %q / %q, want the application's", query.Get("client_id"), query.Get("redirect_uri"))
	}
	if query.Get("scope") != "openid documents:read offline_access" {
		t.Errorf("scope = %q", query.Get("scope"))
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Errorf("PKCE is missing: %v", query)
	}
	if query.Get("response_type") != "code" {
		t.Errorf("response_type = %q", query.Get("response_type"))
	}
	// The state is random (not derived from the session ID) and readable.
	if got := query.Get("state"); got == "" || strings.Contains(got, "session-1") || got != chain.ConsentState("session-1") {
		t.Errorf("state = %q, ConsentState = %q", got, chain.ConsentState("session-1"))
	}

	// 2. The application redeems the code: its client ID, its secret and
	// the verifier of this consent; never the agent's credentials.
	if err := chain.HandleConsentCallback(ctx, "session-1", "auth-code"); err != nil {
		t.Fatalf("HandleConsentCallback: %v", err)
	}
	form := state.codeForms[0]
	if form.Get("client_id") != "client_app_1" || form.Get("client_secret") != "app-secret" {
		t.Errorf("code redemption authenticated as %q / %q, want the application", form.Get("client_id"), form.Get("client_secret"))
	}
	if form.Get("redirect_uri") != testApplication.RedirectURI || form.Get("code") != "auth-code" {
		t.Errorf("code form = %v", form)
	}
	if s256(form.Get("code_verifier")) != query.Get("code_challenge") {
		t.Error("the code verifier does not match the challenge of the consent URL")
	}
	if chain.ConsentState("session-1") != "" {
		t.Error("a redeemed consent must be forgotten (the code and verifier are single-use)")
	}

	// 3. The agent exchanges the person's token with its own token.
	if _, err := chain.Exchange(ctx, "session-1"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	exchange := state.exchangeForms[0]
	if exchange.Get("subject_token") != "user-token" || exchange.Get("actor_token") != "agent-token" {
		t.Errorf("exchange form = %v", exchange)
	}

	// 4. Revoke: the application revokes the person's refresh token.
	if err := chain.Revoke(ctx, "session-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoke := state.revokeForms[0]
	if revoke.Get("token") != "user-refresh" || revoke.Get("token_type_hint") != "refresh_token" ||
		revoke.Get("client_id") != "client_app_1" || revoke.Get("client_secret") != "app-secret" {
		t.Errorf("revoke form = %v, want the refresh token, revoked as the application", revoke)
	}
	if len(chain.ActiveSessions()) != 0 || chain.HasDelegation("session-1") {
		t.Error("local state must be cleared")
	}
}

func TestDelegationConsentWithAPublicApplication(t *testing.T) {
	state := &delegationServer{}
	app := DelegationApplication{ClientID: "client_spa", RedirectURI: "http://localhost:4230/cb"}
	chain := newTestAppChain(t, state, app)
	ctx := context.Background()

	consent, err := chain.ConsentURL("s", []string{"documents:read"}, "my-state")
	if err != nil {
		t.Fatal(err)
	}
	query, _ := url.ParseQuery(consent[strings.Index(consent, "?")+1:])
	if query.Get("scope") != "openid documents:read" || query.Get("state") != "my-state" {
		t.Errorf("scope / state = %q / %q (no offline_access unless asked for)", query.Get("scope"), query.Get("state"))
	}
	if err := chain.HandleConsentCallback(ctx, "s", "code"); err != nil {
		t.Fatal(err)
	}
	if f := state.codeForms[0]; f.Get("client_id") != "client_spa" || f.Has("client_secret") || f.Get("code_verifier") == "" {
		t.Errorf("a public application redeems with client_id and PKCE only: %v", f)
	}
}

func TestDelegationConsentRefusals(t *testing.T) {
	state := &delegationServer{}
	chain := newTestAppChain(t, state, testApplication)
	ctx := context.Background()

	if _, err := chain.ConsentURL("s", nil, ""); !errors.Is(err, ErrValidation) {
		t.Errorf("no scopes: err = %v, want a validation error (the exchange would grant nothing)", err)
	}
	if err := chain.HandleConsentCallback(ctx, "never-started", "code"); !errors.Is(err, ErrConfig) {
		t.Errorf("a callback without a consent of this chain: err = %v, want a config error", err)
	}
	if len(state.codeForms) != 0 {
		t.Error("no code may be redeemed without the verifier of this chain's consent")
	}
}

func TestDelegationChainRefreshesAsTheApplication(t *testing.T) {
	state := &delegationServer{}
	chain := newTestAppChain(t, state, testApplication)
	ctx := context.Background()
	if _, err := chain.ConsentURL("s", []string{"documents:read"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := chain.HandleConsentCallback(ctx, "s", "code"); err != nil {
		t.Fatal(err)
	}
	// Let the person's token lapse.
	chain.mu.Lock()
	chain.userTokens["s"].expiresAt = time.Now().Add(-time.Minute)
	chain.mu.Unlock()
	if _, err := chain.Exchange(ctx, "s"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(state.refreshForms) != 1 {
		t.Fatalf("refreshes = %d, want 1 for an expired token", len(state.refreshForms))
	}
	if f := state.refreshForms[0]; f.Get("client_id") != "client_app_1" || f.Get("client_secret") != "app-secret" {
		t.Errorf("refresh as %q / %q, want the application", f.Get("client_id"), f.Get("client_secret"))
	}
}

func TestDelegationRevokeSaysWhenItOnlyForgets(t *testing.T) {
	state := &delegationServer{}
	chain := newTestAppChain(t, state, testApplication)
	ctx := context.Background()

	// A token registered with SetUserToken has no refresh token here.
	if err := chain.SetUserToken("s", "user-token"); err != nil {
		t.Fatal(err)
	}
	err := chain.Revoke(ctx, "s")
	if !errors.Is(err, ErrDelegationNotRevoked) || !errors.Is(err, ErrConfig) {
		t.Errorf("err = %v, want ErrDelegationNotRevoked (a config error)", err)
	}
	if len(state.revokeForms) != 0 || len(chain.ActiveSessions()) != 0 {
		t.Errorf("revocations = %d, sessions = %v: nothing to send, local state cleared", len(state.revokeForms), chain.ActiveSessions())
	}

	// With the application's tokens (SetUserTokens) Revoke ends the grant.
	if err := chain.SetUserTokens("s", &TokenResponse{AccessToken: "user-token", RefreshToken: "app-refresh", ExpiresIn: 600}); err != nil {
		t.Fatal(err)
	}
	if err := chain.Revoke(ctx, "s"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if f := state.revokeForms[0]; f.Get("token") != "app-refresh" || f.Get("client_id") != "client_app_1" {
		t.Errorf("revoke form = %v", f)
	}

	// Forget removes a session on purpose, without any call.
	_ = chain.SetUserToken("s2", "user-token")
	chain.Forget("s2")
	if len(chain.ActiveSessions()) != 0 || len(state.revokeForms) != 1 {
		t.Error("Forget must drop the session without a request")
	}
	// An unknown session has nothing to revoke.
	if err := chain.Revoke(ctx, "unknown"); err != nil {
		t.Errorf("unknown session: %v", err)
	}
}

func TestDeprecatedConsentRefusesAnAgentID(t *testing.T) {
	state := &delegationServer{}
	state.t = t
	server := httptest.NewServer(state.handler())
	t.Cleanup(server.Close)
	agent, err := NewAgent(AgentConfig{BaseURL: server.URL, OrgID: "acme-corp",
		ClientID: "agt_0123456789abcdef", ClientSecret: "agent-secret"})
	if err != nil {
		t.Fatal(err)
	}
	chain := NewDelegationChain(agent, "https://agent.example.com/callback")
	// The server answers "Unknown Application" for an agent ID: say so here.
	if _, err := chain.ConsentURL("s", []string{"documents:read"}, ""); !errors.Is(err, ErrConfig) ||
		!strings.Contains(err.Error(), "NewDelegationChainForApplication") {
		t.Errorf("err = %v, want a config error that names NewDelegationChainForApplication", err)
	}
	if err := chain.HandleConsentCallback(context.Background(), "s", "code"); !errors.Is(err, ErrConfig) {
		t.Errorf("callback with an agent ID: err = %v, want a config error", err)
	}
	if len(state.codeForms) != 0 {
		t.Error("the agent's credentials must never redeem a code")
	}

	client, _ := New(WithBaseURL(server.URL), WithOrgID("acme-corp"), WithoutCredential())
	if _, err := client.Delegation.ConsentURL(ConsentURLParams{ClientID: "agt_0123456789abcdef", RedirectURI: "https://x/cb"}); !errors.Is(err, ErrValidation) {
		t.Errorf("Delegation.ConsentURL with an agent ID: err = %v, want a validation error", err)
	}
}

func TestApplicationConsentURL(t *testing.T) {
	client, _ := New(WithBaseURL("https://app.lumoauth.dev"), WithOrgID("acme-corp"), WithoutCredential())
	got, err := client.Delegation.ApplicationConsentURL(ApplicationConsentParams{
		ClientID: "client_app_1", RedirectURI: "https://app.example.com/cb",
		Scopes: []string{"documents:read"}, State: "st", CodeChallenge: "challenge", OfflineAccess: true,
	})
	if err != nil {
		t.Fatalf("ApplicationConsentURL: %v", err)
	}
	parsed, _ := url.Parse(got)
	q := parsed.Query()
	if q.Get("client_id") != "client_app_1" || q.Get("scope") != "openid documents:read offline_access" ||
		q.Get("code_challenge") != "challenge" || q.Get("code_challenge_method") != "S256" || q.Get("state") != "st" {
		t.Errorf("URL = %s", got)
	}
	if q.Has("access_type") {
		t.Error("access_type is not a LumoAuth parameter; offline_access asks for the refresh token")
	}
	for name, p := range map[string]ApplicationConsentParams{
		"agent ID":     {ClientID: "agt_1", RedirectURI: "https://a/cb", Scopes: []string{"x:y"}, State: "s", CodeChallenge: "c"},
		"no challenge": {ClientID: "c", RedirectURI: "https://a/cb", Scopes: []string{"x:y"}, State: "s"},
		"no state":     {ClientID: "c", RedirectURI: "https://a/cb", Scopes: []string{"x:y"}, CodeChallenge: "c"},
		"no scopes":    {ClientID: "c", RedirectURI: "https://a/cb", State: "s", CodeChallenge: "c"},
		"no redirect":  {ClientID: "c", Scopes: []string{"x:y"}, State: "s", CodeChallenge: "c"},
	} {
		if _, err := client.Delegation.ApplicationConsentURL(p); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
}
