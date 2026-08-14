package lumoauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// delegationServer answers the token endpoint by grant type, so a test can
// distinguish the agent's own authentication, the consent-code exchange,
// the delegation exchange, and revocation.
type delegationServer struct {
	t *testing.T

	mu             sync.Mutex
	exchangeForms  []url.Values
	codeForms      []url.Values
	refreshForms   []url.Values
	revokeForms    []url.Values
	delegatedCalls []string

	// exchangeStatus and exchangeBody override the delegation exchange
	// response, for the error paths.
	exchangeStatus int
	exchangeBody   map[string]any
	// userTokenExpiresIn controls the consent exchange's expires_in.
	userTokenExpiresIn int
	// refreshedAccessToken is returned by the refresh grant.
	refreshedAccessToken string
}

func (s *delegationServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()

		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			_ = r.ParseForm()
			switch r.Form.Get("grant_type") {
			case "client_credentials":
				writeJSON(w, 200, map[string]any{"access_token": "agent-token", "expires_in": 3600})

			case "authorization_code":
				s.codeForms = append(s.codeForms, r.Form)
				expiresIn := s.userTokenExpiresIn
				if expiresIn == 0 {
					expiresIn = 3600
				}
				writeJSON(w, 200, map[string]any{
					"access_token":  "user-token",
					"refresh_token": "user-refresh",
					"expires_in":    expiresIn,
					"scope":         "read:documents",
				})

			case "refresh_token":
				s.refreshForms = append(s.refreshForms, r.Form)
				token := s.refreshedAccessToken
				if token == "" {
					token = "user-token-2"
				}
				writeJSON(w, 200, map[string]any{"access_token": token, "expires_in": 3600})

			case GrantTypeTokenExchange:
				s.exchangeForms = append(s.exchangeForms, r.Form)
				if s.exchangeStatus != 0 {
					writeJSON(w, s.exchangeStatus, s.exchangeBody)
					return
				}
				writeJSON(w, 200, map[string]any{"access_token": "delegated-token", "expires_in": 3600})

			default:
				s.t.Errorf("unexpected grant_type %q", r.Form.Get("grant_type"))
			}

		case strings.HasSuffix(r.URL.Path, "/oauth/revoke"):
			_ = r.ParseForm()
			s.revokeForms = append(s.revokeForms, r.Form)
			w.WriteHeader(http.StatusNoContent)

		default:
			s.delegatedCalls = append(s.delegatedCalls, r.Header.Get("Authorization"))
			writeJSON(w, 200, map[string]any{"data": []any{}})
		}
	}
}

func newTestChain(t *testing.T, state *delegationServer) (*DelegationChain, *httptest.Server) {
	t.Helper()
	state.t = t

	server := httptest.NewServer(state.handler())
	t.Cleanup(server.Close)

	agent, err := NewAgent(AgentConfig{
		BaseURL: server.URL, OrgID: "acme-corp",
		ClientID: "agent-client", ClientSecret: "agent-secret",
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	return NewDelegationChain(agent, "https://agent.example.com/callback"), server
}

func TestDelegationChainConsentURL(t *testing.T) {
	chain, server := newTestChain(t, &delegationServer{})

	got, err := chain.ConsentURL("session-1", []string{"read:documents", "write:documents"}, "")
	if err != nil {
		t.Fatalf("ConsentURL: %v", err)
	}

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parsing the URL: %v", err)
	}
	if !strings.HasPrefix(got, server.URL) {
		t.Errorf("the consent URL should point at the instance: %q", got)
	}
	if parsed.Path != "/orgs/acme-corp/api/v1/oauth/authorize" {
		t.Errorf("path = %q", parsed.Path)
	}

	query := parsed.Query()
	if query.Get("scope") != "read:documents write:documents" {
		t.Errorf("scope = %q", query.Get("scope"))
	}
	if query.Get("state") != "session:session-1" {
		t.Errorf("state = %q, want the session-derived default", query.Get("state"))
	}
	// Offline access is what gets the agent a refresh token.
	if query.Get("access_type") != "offline" || query.Get("prompt") != "consent" {
		t.Errorf("the consent URL must request offline access: %v", query)
	}
}

func TestDelegationChainConsentURLRequiresRedirectURI(t *testing.T) {
	state := &delegationServer{t: t}
	server := httptest.NewServer(state.handler())
	defer server.Close()

	agent, _ := NewAgent(AgentConfig{
		BaseURL: server.URL, OrgID: "acme-corp", ClientID: "c", ClientSecret: "s",
	})
	chain := NewDelegationChain(agent, "")

	if _, err := chain.ConsentURL("session-1", nil, ""); !errors.Is(err, ErrConfig) {
		t.Errorf("expected a config error without a redirect URI, got %v", err)
	}
}

func TestDelegationChainFullFlow(t *testing.T) {
	state := &delegationServer{}
	chain, _ := newTestChain(t, state)
	ctx := context.Background()

	if err := chain.HandleConsentCallback(ctx, "session-1", "auth-code"); err != nil {
		t.Fatalf("HandleConsentCallback: %v", err)
	}
	if len(state.codeForms) != 1 {
		t.Fatalf("the consent code was not exchanged")
	}
	if state.codeForms[0].Get("client_secret") != "agent-secret" {
		t.Error("the consent exchange must authenticate as a confidential client")
	}

	token, err := chain.Exchange(ctx, "session-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if token != "delegated-token" {
		t.Errorf("token = %q", token)
	}

	form := state.exchangeForms[0]
	if form.Get("subject_token") != "user-token" {
		t.Errorf("subject_token = %q, want the user's token", form.Get("subject_token"))
	}
	if form.Get("actor_token") != "agent-token" {
		t.Errorf("actor_token = %q, want the agent's token", form.Get("actor_token"))
	}

	if !chain.HasDelegation("session-1") {
		t.Error("HasDelegation should report the cached token")
	}
	if sessions := chain.ActiveSessions(); len(sessions) != 1 || sessions[0] != "session-1" {
		t.Errorf("ActiveSessions = %v", sessions)
	}

	// Delegated requests carry the delegated token, and reuse it.
	var page struct {
		Data []any `json:"data"`
	}
	if err := chain.Do(ctx, "session-1", http.MethodGet, "/orgs/acme-corp/api/v1/documents", nil, &page); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(state.delegatedCalls) != 1 || state.delegatedCalls[0] != "Bearer delegated-token" {
		t.Errorf("delegated calls = %v", state.delegatedCalls)
	}
	if len(state.exchangeForms) != 1 {
		t.Errorf("the cached delegated token should be reused, exchanges = %d", len(state.exchangeForms))
	}
}

func TestDelegationChainExchangesOnDemand(t *testing.T) {
	state := &delegationServer{}
	chain, _ := newTestChain(t, state)
	ctx := context.Background()

	if err := chain.HandleConsentCallback(ctx, "session-1", "auth-code"); err != nil {
		t.Fatalf("HandleConsentCallback: %v", err)
	}

	// Do without a prior Exchange must perform one itself.
	if err := chain.Do(ctx, "session-1", http.MethodGet, "/orgs/acme-corp/api/v1/documents", nil, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(state.exchangeForms) != 1 {
		t.Errorf("Do should exchange on demand, exchanges = %d", len(state.exchangeForms))
	}
}

func TestDelegationChainSetUserToken(t *testing.T) {
	state := &delegationServer{}
	chain, _ := newTestChain(t, state)
	ctx := context.Background()

	if err := chain.SetUserToken("session-1", "preexisting-user-token"); err != nil {
		t.Fatalf("SetUserToken: %v", err)
	}
	if _, err := chain.Exchange(ctx, "session-1"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(state.codeForms) != 0 {
		t.Error("SetUserToken should skip the consent exchange entirely")
	}
	if state.exchangeForms[0].Get("subject_token") != "preexisting-user-token" {
		t.Errorf("subject_token = %q", state.exchangeForms[0].Get("subject_token"))
	}
}

func TestDelegationChainRefreshesAnExpiredUserToken(t *testing.T) {
	state := &delegationServer{
		userTokenExpiresIn:   60,
		refreshedAccessToken: "user-token-refreshed",
	}
	chain, _ := newTestChain(t, state)
	ctx := context.Background()

	if err := chain.HandleConsentCallback(ctx, "session-1", "auth-code"); err != nil {
		t.Fatalf("HandleConsentCallback: %v", err)
	}

	// Simulate the token's lifetime elapsing, which no amount of test
	// setup can otherwise reach inside one run.
	chain.mu.Lock()
	chain.userTokens["session-1"].expiresAt = time.Now().Add(-time.Minute)
	chain.mu.Unlock()

	if _, err := chain.Exchange(ctx, "session-1"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if len(state.refreshForms) != 1 {
		t.Fatalf("an expired user token should be refreshed first, refreshes = %d", len(state.refreshForms))
	}
	if state.refreshForms[0].Get("refresh_token") != "user-refresh" {
		t.Errorf("refresh_token = %q", state.refreshForms[0].Get("refresh_token"))
	}
	if got := state.exchangeForms[0].Get("subject_token"); got != "user-token-refreshed" {
		t.Errorf("subject_token = %q, want the refreshed token", got)
	}
}

func TestDelegationChainUnknownSession(t *testing.T) {
	chain, _ := newTestChain(t, &delegationServer{})

	_, err := chain.Exchange(context.Background(), "never-seen")
	if !errors.Is(err, ErrConfig) {
		t.Errorf("expected a config error for an unknown session, got %v", err)
	}
	if !strings.Contains(err.Error(), "SetUserToken") {
		t.Errorf("the error should say how to fix it: %v", err)
	}
}

func TestDelegationChainNestedDelegation(t *testing.T) {
	state := &delegationServer{}
	chain, _ := newTestChain(t, state)
	ctx := context.Background()

	if err := chain.HandleConsentCallback(ctx, "session-1", "auth-code"); err != nil {
		t.Fatalf("HandleConsentCallback: %v", err)
	}

	if _, err := chain.DelegateToSubAgent(ctx, "session-1", "sub-agent-token", "read:documents"); err != nil {
		t.Fatalf("DelegateToSubAgent: %v", err)
	}

	// Two exchanges: user→agent, then that result→sub-agent.
	if len(state.exchangeForms) != 2 {
		t.Fatalf("exchanges = %d, want 2", len(state.exchangeForms))
	}
	nested := state.exchangeForms[1]
	if nested.Get("subject_token") != "delegated-token" {
		t.Errorf("the nested subject should be the existing delegated token, got %q",
			nested.Get("subject_token"))
	}
	if nested.Get("actor_token") != "sub-agent-token" {
		t.Errorf("actor_token = %q", nested.Get("actor_token"))
	}
	if nested.Get("scope") != "read:documents" {
		t.Errorf("scope = %q, want the narrowed scope", nested.Get("scope"))
	}
}

func TestDelegationChainDepthLimit(t *testing.T) {
	state := &delegationServer{
		exchangeStatus: http.StatusForbidden,
		exchangeBody: map[string]any{
			"error":     "delegation_depth_exceeded",
			"max_depth": 3,
		},
	}
	chain, _ := newTestChain(t, state)
	ctx := context.Background()

	if err := chain.SetUserToken("session-1", "user-token"); err != nil {
		t.Fatalf("SetUserToken: %v", err)
	}

	_, err := chain.Exchange(ctx, "session-1")
	if err == nil {
		t.Fatal("expected an error when the chain is too deep")
	}
	if !strings.Contains(err.Error(), "too deep") || !strings.Contains(err.Error(), "3") {
		t.Errorf("the error should explain the depth limit: %v", err)
	}
}

func TestDelegationChainOtherExchangeErrorsAreAnnotated(t *testing.T) {
	state := &delegationServer{
		exchangeStatus: http.StatusForbidden,
		exchangeBody: map[string]any{
			"error":             "insufficient_scope",
			"error_description": "agent lacks delegate:on_behalf",
		},
	}
	chain, _ := newTestChain(t, state)

	if err := chain.SetUserToken("session-1", "user-token"); err != nil {
		t.Fatalf("SetUserToken: %v", err)
	}

	_, err := chain.Exchange(context.Background(), "session-1")
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("the underlying status should be preserved, got %v", err)
	}
	if !strings.Contains(err.Error(), "token exchange failed") {
		t.Errorf("the error should say which step failed: %v", err)
	}
	if !strings.Contains(err.Error(), "delegate:on_behalf") {
		t.Errorf("the server's description should survive: %v", err)
	}
}

func TestDelegationChainRevoke(t *testing.T) {
	state := &delegationServer{}
	chain, _ := newTestChain(t, state)
	ctx := context.Background()

	if err := chain.HandleConsentCallback(ctx, "session-1", "auth-code"); err != nil {
		t.Fatalf("HandleConsentCallback: %v", err)
	}
	if _, err := chain.Exchange(ctx, "session-1"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if err := chain.Revoke(ctx, "session-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if len(state.revokeForms) != 1 {
		t.Fatalf("revocations = %d, want 1", len(state.revokeForms))
	}
	if state.revokeForms[0].Get("token") != "user-refresh" {
		t.Errorf("the refresh token should be revoked, got %q", state.revokeForms[0].Get("token"))
	}
	if state.revokeForms[0].Get("token_type_hint") != "refresh_token" {
		t.Errorf("token_type_hint = %q", state.revokeForms[0].Get("token_type_hint"))
	}

	if chain.HasDelegation("session-1") {
		t.Error("local state must be cleared after revocation")
	}
	if len(chain.ActiveSessions()) != 0 {
		t.Errorf("ActiveSessions = %v, want empty", chain.ActiveSessions())
	}
}

func TestDelegationChainRevokeClearsStateEvenWhenTheServerFails(t *testing.T) {
	state := &delegationServer{t: t}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/revoke") {
			writeJSON(w, 500, map[string]any{"error": "server_error"})
			return
		}
		state.handler()(w, r)
	}))
	defer server.Close()

	agent, _ := NewAgent(AgentConfig{
		BaseURL: server.URL, OrgID: "acme-corp", ClientID: "c", ClientSecret: "s",
	})
	chain := NewDelegationChain(agent, "https://agent.example.com/callback")
	ctx := context.Background()

	if err := chain.HandleConsentCallback(ctx, "session-1", "auth-code"); err != nil {
		t.Fatalf("HandleConsentCallback: %v", err)
	}

	err := chain.Revoke(ctx, "session-1")
	if err == nil {
		t.Error("a failing revocation should be reported")
	}
	// A revoked session must never keep serving requests from cache, even
	// when the server-side revocation failed.
	if chain.HasDelegation("session-1") || len(chain.ActiveSessions()) != 0 {
		t.Error("local delegation state must be cleared regardless of the server's answer")
	}
}

func TestDelegationChainRevokeAll(t *testing.T) {
	state := &delegationServer{}
	chain, _ := newTestChain(t, state)
	ctx := context.Background()

	for _, session := range []string{"session-1", "session-2", "session-3"} {
		if err := chain.HandleConsentCallback(ctx, session, "auth-code"); err != nil {
			t.Fatalf("HandleConsentCallback(%s): %v", session, err)
		}
	}
	if len(chain.ActiveSessions()) != 3 {
		t.Fatalf("ActiveSessions = %v", chain.ActiveSessions())
	}

	if err := chain.RevokeAll(ctx); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	if len(chain.ActiveSessions()) != 0 {
		t.Errorf("ActiveSessions = %v, want empty", chain.ActiveSessions())
	}
	if len(state.revokeForms) != 3 {
		t.Errorf("revocations = %d, want 3", len(state.revokeForms))
	}
}

func TestDelegationChainIsConcurrencySafe(t *testing.T) {
	state := &delegationServer{}
	chain, _ := newTestChain(t, state)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		session := "session-" + string(rune('a'+i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := chain.SetUserToken(session, "user-token"); err != nil {
				t.Errorf("SetUserToken: %v", err)
				return
			}
			if _, err := chain.Exchange(ctx, session); err != nil {
				t.Errorf("Exchange: %v", err)
			}
			_ = chain.HasDelegation(session)
			_ = chain.ActiveSessions()
		}()
	}
	wg.Wait()

	if len(chain.ActiveSessions()) != 8 {
		t.Errorf("ActiveSessions = %d, want 8", len(chain.ActiveSessions()))
	}
}
