package lumoauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestAgent builds an Agent pointed at a test server.
func newTestAgent(t *testing.T, handler http.HandlerFunc) (*Agent, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	agent, err := NewAgent(AgentConfig{
		BaseURL:      server.URL,
		OrgID:        "acme-corp",
		ClientID:     "agent-client",
		ClientSecret: "agent-secret",
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	return agent, server
}

func TestNewAgentRequiresCredentials(t *testing.T) {
	t.Setenv(EnvAgentClientID, "")
	t.Setenv(EnvAgentClientSecret, "")

	_, err := NewAgent(AgentConfig{BaseURL: "https://example.test", OrgID: "acme"})
	if !errors.Is(err, ErrConfig) {
		t.Errorf("expected a config error without credentials, got %v", err)
	}
	if !strings.Contains(err.Error(), EnvAgentClientID) {
		t.Errorf("the error should name the environment variables: %v", err)
	}
}

func TestNewAgentReadsEnvironment(t *testing.T) {
	t.Setenv(EnvBaseURL, "https://env.example.test")
	t.Setenv(EnvOrgID, "env-org")
	t.Setenv(EnvAgentClientID, "env-client")
	t.Setenv(EnvAgentClientSecret, "env-secret")

	agent, err := NewAgent(AgentConfig{})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	if agent.BaseURL() != "https://env.example.test" || agent.OrgID() != "env-org" {
		t.Errorf("agent = %s / %s", agent.BaseURL(), agent.OrgID())
	}
	if agent.ClientID() != "env-client" {
		t.Errorf("ClientID = %q", agent.ClientID())
	}
}

func TestAgentAuthenticatesLazily(t *testing.T) {
	var tokenCalls, askCalls int
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			tokenCalls++
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" {
				t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
			}
			if r.Form.Get("client_id") != "agent-client" {
				t.Errorf("client_id = %q", r.Form.Get("client_id"))
			}
			writeJSON(w, 200, map[string]any{
				"access_token": "agent-token", "expires_in": 3600, "scope": "read:documents",
			})
		case strings.HasSuffix(r.URL.Path, "/agents/ask"):
			askCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer agent-token" {
				t.Errorf("Authorization = %q", got)
			}
			writeJSON(w, 200, map[string]any{"allowed": true, "action": "document.read"})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})

	// No network call happens until the first API call.
	if tokenCalls != 0 {
		t.Error("NewAgent should not authenticate eagerly")
	}

	ctx := context.Background()
	allowed, err := agent.IsAllowed(ctx, "document.read", nil)
	if err != nil {
		t.Fatalf("IsAllowed: %v", err)
	}
	if !allowed {
		t.Error("IsAllowed should report the server's decision")
	}
	if tokenCalls != 1 || askCalls != 1 {
		t.Errorf("token calls = %d, ask calls = %d; want 1 and 1", tokenCalls, askCalls)
	}

	// The cached token is reused.
	if _, err := agent.IsAllowed(ctx, "document.read", nil); err != nil {
		t.Fatalf("IsAllowed: %v", err)
	}
	if tokenCalls != 1 {
		t.Errorf("a valid token should be reused, but authenticated %d times", tokenCalls)
	}
	if scopes := agent.TokenScopes(); len(scopes) != 1 || scopes[0] != "read:documents" {
		t.Errorf("TokenScopes = %v", scopes)
	}
}

func TestAgentRefreshesBeforeExpiry(t *testing.T) {
	var tokenCalls int
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			tokenCalls++
			// A lifetime shorter than the refresh buffer means the token
			// is always treated as due for renewal.
			writeJSON(w, 200, map[string]any{"access_token": "token", "expires_in": 30})
			return
		}
		writeJSON(w, 200, map[string]any{"allowed": true})
	})

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := agent.IsAllowed(ctx, "document.read", nil); err != nil {
			t.Fatalf("IsAllowed: %v", err)
		}
	}
	if tokenCalls != 2 {
		t.Errorf("a token inside the refresh buffer should be renewed each time, got %d calls", tokenCalls)
	}
}

func TestAgentConcurrentCallersShareOneTokenRequest(t *testing.T) {
	var mu sync.Mutex
	var tokenCalls int

	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			mu.Lock()
			tokenCalls++
			mu.Unlock()
			// Slow enough that every goroutine piles up behind it.
			time.Sleep(50 * time.Millisecond)
			writeJSON(w, 200, map[string]any{"access_token": "shared-token", "expires_in": 3600})
			return
		}
		writeJSON(w, 200, map[string]any{"allowed": true})
	})

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := agent.IsAllowed(ctx, "document.read", nil); err != nil {
				t.Errorf("IsAllowed: %v", err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if tokenCalls != 1 {
		t.Errorf("8 concurrent callers triggered %d token requests, want 1", tokenCalls)
	}
}

func TestAgentAuthenticationFailureSurfaces(t *testing.T) {
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, map[string]any{
			"error":             "invalid_client",
			"error_description": "unknown client",
		})
	})

	_, err := agent.IsAllowed(context.Background(), "document.read", nil)
	if !errors.Is(err, ErrAuthentication) {
		t.Errorf("expected an authentication error, got %v", err)
	}
	if !strings.Contains(err.Error(), "unknown client") {
		t.Errorf("the server's description should surface: %v", err)
	}
}

func TestAgentCapabilitiesAndBudget(t *testing.T) {
	var infoCalls int
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			writeJSON(w, 200, map[string]any{"access_token": "t", "expires_in": 3600})
		case strings.HasSuffix(r.URL.Path, "/oauth/userinfo"):
			infoCalls++
			writeJSON(w, 200, map[string]any{
				"sub":          "agent_1",
				"capabilities": []string{"read:documents", "tool:search_web"},
				"budget_policy": map[string]any{
					"max_tokens_per_day": 100000,
					"tokens_used_today":  100000,
				},
			})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})

	ctx := context.Background()

	has, err := agent.HasCapability(ctx, "tool:search_web")
	if err != nil {
		t.Fatalf("HasCapability: %v", err)
	}
	if !has {
		t.Error("HasCapability should find a declared capability")
	}

	has, err = agent.HasCapability(ctx, "tool:send_email")
	if err != nil {
		t.Fatalf("HasCapability: %v", err)
	}
	if has {
		t.Error("HasCapability should not invent capabilities")
	}
	if infoCalls != 1 {
		t.Errorf("agent info should be cached, fetched %d times", infoCalls)
	}

	// RequireCapability is the guard form.
	if err := agent.RequireCapability(ctx, "tool:search_web"); err != nil {
		t.Errorf("RequireCapability on a held capability: %v", err)
	}
	err = agent.RequireCapability(ctx, "tool:send_email")
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("expected ErrPermissionDenied, got %v", err)
	}
	if !strings.Contains(err.Error(), "tool:send_email") {
		t.Errorf("the error should name the capability: %v", err)
	}
	// No request was made, so there is no HTTP status to report.
	if StatusCode(err) != 0 {
		t.Errorf("a client-side capability check should not fabricate an HTTP status, got %d",
			StatusCode(err))
	}

	// Budget.
	if err := agent.CheckBudget(ctx); !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("an exhausted budget should match ErrBudgetExceeded, got %v", err)
	}

	// A forced refresh re-reads it.
	if _, err := agent.Info(ctx, true); err != nil {
		t.Fatalf("Info: %v", err)
	}
	if infoCalls != 2 {
		t.Errorf("Info(refresh) should refetch, calls = %d", infoCalls)
	}
}

func TestAgentRegisterUsesItsOwnClientID(t *testing.T) {
	var calls []capture
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			writeJSON(w, 200, map[string]any{"access_token": "t", "expires_in": 3600})
			return
		}
		recordingHandler(t, &calls, map[string]any{"agent_id": "agent_1"})(w, r)
	})

	if _, err := agent.Register(context.Background(), RegisterParams{Name: "Analyser"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if calls[0].Body["client_id"] != "agent-client" {
		t.Errorf("client_id = %v, want the agent's own", calls[0].Body["client_id"])
	}
}

func TestAgentMCPToken(t *testing.T) {
	var exchanges int
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == GrantTypeTokenExchange {
			exchanges++
			if r.Form.Get("audience") != "urn:mcp:financial-data" {
				t.Errorf("audience = %q", r.Form.Get("audience"))
			}
			if r.Form.Get("subject_token") != "agent-token" {
				t.Errorf("subject_token = %q, want the agent's token", r.Form.Get("subject_token"))
			}
			writeJSON(w, 200, map[string]any{"access_token": "mcp-token"})
			return
		}
		writeJSON(w, 200, map[string]any{"access_token": "agent-token", "expires_in": 3600})
	})

	token, err := agent.MCPToken(context.Background(), "urn:mcp:financial-data")
	if err != nil {
		t.Fatalf("MCPToken: %v", err)
	}
	if token != "mcp-token" {
		t.Errorf("token = %q", token)
	}
	if exchanges != 1 {
		t.Errorf("exchanges = %d, want 1", exchanges)
	}
}

func TestAgentSatisfiesTokenSourceInterfaces(t *testing.T) {
	// The wrappers accept an agent through these interfaces; a signature
	// change that broke them would otherwise surface only at a call site.
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {})

	var _ TokenSource = agent
	var _ ConfidentialClient = agent
}

func TestAgentClientExposesRemainingNamespaces(t *testing.T) {
	var calls []capture
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			writeJSON(w, 200, map[string]any{"access_token": "t", "expires_in": 3600})
			return
		}
		recordingHandler(t, &calls, map[string]any{"allowed": true})(w, r)
	})

	// Zanzibar and ABAC are reachable through Client(), not on the Agent.
	if _, err := agent.Client().Zanzibar.Check(context.Background(),
		"document:readme", "viewer", "agent:analyser"); err != nil {
		t.Fatalf("Zanzibar.Check: %v", err)
	}
	if calls[0].Path != "/api/v1/authz/zanzibar/check" {
		t.Errorf("path = %q", calls[0].Path)
	}
}
