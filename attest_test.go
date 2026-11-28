package lumoauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// attestAnswer is the server's 200 answer of POST /agents/{agentId}/attest.
func attestAnswer(tokenType, scope string) map[string]any {
	answer := map[string]any{
		"access_token": "eyJ.agent-token.sig",
		"token_type":   tokenType,
		"expires_in":   900,
		"identity": map[string]any{
			"provider": "github", "subject": "repo:acme/app:ref:refs/heads/main",
			"issuer": "https://token.actions.githubusercontent.com", "audience_generic": false,
		},
	}
	if scope != "" {
		answer["scope"] = scope
	}
	return answer
}

func TestAgentsAttest(t *testing.T) {
	ctx := context.Background()

	t.Run("sends the attestation token and no credential of the client", func(t *testing.T) {
		var got *http.Request
		var body map[string]any
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			got = r.Clone(context.Background())
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeJSON(w, 200, attestAnswer("Bearer", "reports:read reports:write"))
		}, WithAccessToken("some-user-token"))

		result, err := client.Agents.Attest(ctx, AttestParams{
			AgentID:          "agt_7f3c2a19b84e5d60",
			AttestationToken: "eyJ.workload.sig",
			Scopes:           []string{"reports:read", "reports:write"},
		})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if got.Method != http.MethodPost || got.URL.Path != "/orgs/acme-corp/api/v1/agents/agt_7f3c2a19b84e5d60/attest" {
			t.Errorf("request = %s %s", got.Method, got.URL.Path)
		}
		// The endpoint is public: the attestation token is the credential.
		if got.Header.Get("X-API-Key") != "" || got.Header.Get("Authorization") != "" || got.Header.Get(DPoPHeader) != "" {
			t.Errorf("no credential may be sent: %v", got.Header)
		}
		if body["attestation_token"] != "eyJ.workload.sig" || body["scope"] != "reports:read reports:write" {
			t.Errorf("body = %v", body)
		}
		if result.AccessToken != "eyJ.agent-token.sig" || result.TokenType != "Bearer" || result.ExpiresIn != 900 {
			t.Errorf("result = %+v", result)
		}
		if got := result.Scopes(); len(got) != 2 || got[1] != "reports:write" {
			t.Errorf("Scopes() = %v", got)
		}
		if result.Identity.Provider != "github" || result.Identity.Subject == "" || result.Identity.AudienceGeneric {
			t.Errorf("identity = %+v", result.Identity)
		}
		if result.Raw["identity"] == nil {
			t.Error("Raw should hold the whole answer")
		}
	})

	t.Run("without scopes the body names none", func(t *testing.T) {
		var body map[string]any
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeJSON(w, 200, attestAnswer("Bearer", ""))
		})
		result, err := client.Agents.Attest(ctx, AttestParams{AgentID: "agt_1", AttestationToken: "jwt"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if _, sent := body["scope"]; sent {
			t.Errorf("scope should be left out: %v", body)
		}
		if result.Scope != "" || len(result.Scopes()) != 0 {
			t.Errorf("result scope = %q", result.Scope)
		}
	})

	t.Run("a rejected attestation is an authentication error", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 401, map[string]any{"error": "attestation_rejected", "error_description": "Workload attestation was rejected."})
		})
		_, err := client.Agents.Attest(ctx, AttestParams{AgentID: "agt_1", AttestationToken: "jwt"})
		if !errors.Is(err, ErrAuthentication) || ErrorCode(err) != "attestation_rejected" {
			t.Errorf("err = %v (code %q)", err, ErrorCode(err))
		}
	})

	t.Run("a spent budget is a budget error", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, 429, map[string]any{"error": "budget_exceeded", "error_description": "Agent budget exceeded"})
		})
		_, err := client.Agents.Attest(ctx, AttestParams{AgentID: "agt_1", AttestationToken: "jwt"})
		if !errors.Is(err, ErrBudgetExceeded) || !errors.Is(err, ErrRateLimited) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("an answer without an access token is refused", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{"token_type": "Bearer"})
		})
		if _, err := client.Agents.Attest(ctx, AttestParams{AgentID: "agt_1", AttestationToken: "jwt"}); !errors.Is(err, ErrValidation) {
			t.Errorf("err = %v, want a validation error", err)
		}
	})

	t.Run("validates its arguments before calling out", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			t.Error("no request should have been sent")
		})
		for _, params := range []AttestParams{
			{AttestationToken: "jwt"},
			{AgentID: "agt_1"},
			{AgentID: "agt_1", AttestationToken: "jwt", Scopes: []string{"two words"}},
		} {
			if _, err := client.Agents.Attest(ctx, params); !errors.Is(err, ErrValidation) {
				t.Errorf("%+v: err = %v, want a validation error", params, err)
			}
		}
	})
}

func TestAgentsAttestWithDPoP(t *testing.T) {
	signer, _ := NewDPoPSigner()
	calls := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		proof := r.Header.Get(DPoPHeader)
		if proof == "" {
			t.Fatal("the attestation carries no DPoP proof")
		}
		_, claims, _ := decodeProof(t, proof)
		if claims["htm"] != "POST" || claims["htu"] != server.URL+"/orgs/acme-corp/api/v1/agents/agt_1/attest" {
			t.Errorf("proof htm/htu = %v/%v", claims["htm"], claims["htu"])
		}
		if _, present := claims["ath"]; present {
			t.Error("the proof must not carry ath: no access token is presented")
		}
		if claims["nonce"] != "attest-nonce" {
			// As at the token endpoint: the first proof has no nonce.
			w.Header().Set(DPoPNonceHeader, "attest-nonce")
			writeJSON(w, 400, map[string]any{"error": "use_dpop_nonce"})
			return
		}
		writeJSON(w, 200, attestAnswer("DPoP", "reports:read"))
	}))
	t.Cleanup(server.Close)

	client, err := New(WithBaseURL(server.URL), WithOrgID("acme-corp"), WithAPIKey("k"), WithDPoP(signer))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Agents.Attest(context.Background(), AttestParams{AgentID: "agt_1", AttestationToken: "jwt"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if result.TokenType != DPoPTokenType || calls != 2 {
		t.Errorf("token_type = %q after %d calls, want DPoP after the nonce retry", result.TokenType, calls)
	}
}

func TestAttestWorkload(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Header.Get("X-API-Key") != "" {
			t.Error("AttestWorkload must not send an API key from the environment")
		}
		writeJSON(w, 200, attestAnswer("Bearer", ""))
	}))
	t.Cleanup(server.Close)

	// No credential at all: the workload has none.
	t.Setenv(EnvBaseURL, server.URL)
	t.Setenv(EnvOrgID, "acme-corp")
	t.Setenv(EnvAPIKey, "lmk_should_not_be_sent")
	t.Setenv(EnvCustomDomain, "")
	result, err := AttestWorkload(context.Background(), AttestWorkloadOptions{
		AgentID: "agt_1", AttestationToken: "jwt",
	})
	if err != nil {
		t.Fatalf("AttestWorkload: %v", err)
	}
	if path != "/orgs/acme-corp/api/v1/agents/agt_1/attest" || result.AccessToken == "" {
		t.Errorf("path %q, result %+v", path, result)
	}

	// The organization is required on the platform host.
	t.Setenv(EnvOrgID, "")
	if _, err := AttestWorkload(context.Background(), AttestWorkloadOptions{AgentID: "agt_1", AttestationToken: "jwt"}); !errors.Is(err, ErrConfig) {
		t.Errorf("without an organization: err = %v, want a config error", err)
	}
}

func TestAttestOnACustomDomain(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		writeJSON(w, 200, attestAnswer("Bearer", ""))
	}))
	t.Cleanup(server.Close)
	domain := "http://" + strings.TrimPrefix(server.URL, "http://")
	if u, _ := url.Parse(domain); u.Hostname() != "127.0.0.1" {
		t.Skip("the test server is not on a loopback address")
	}
	if _, err := AttestWorkload(context.Background(), AttestWorkloadOptions{
		CustomDomain: domain, AgentID: "agt_1", AttestationToken: "jwt",
	}); err != nil {
		t.Fatalf("AttestWorkload: %v", err)
	}
	if got != "/api/v1/agents/agt_1/attest" {
		t.Errorf("path on a custom domain = %q", got)
	}
}

func TestClientCredentialsWithAResource(t *testing.T) {
	ctx := context.Background()
	var forms []url.Values
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		forms = append(forms, r.Form)
		writeJSON(w, 200, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600})
	})

	if _, err := client.Auth.ClientCredentialsWithParams(ctx, ClientCredentialsParams{
		ClientID: "cid", ClientSecret: "secret",
		Scopes: []string{"reports:read"}, Resource: "https://api.example.com/",
	}); err != nil {
		t.Fatalf("ClientCredentialsWithParams: %v", err)
	}
	form := forms[0]
	if form.Get("grant_type") != "client_credentials" || form.Get("client_secret") != "secret" ||
		form.Get("scope") != "reports:read" || form.Get("resource") != "https://api.example.com/" {
		t.Errorf("form = %v", form)
	}

	// A private_key_jwt client sends its assertion instead of a secret.
	if _, err := client.Auth.ClientCredentialsWithParams(ctx, ClientCredentialsParams{
		ClientID: "cid", ClientAssertion: "eyJ.assertion.sig", Resource: "https://api.example.com/",
	}); err != nil {
		t.Fatalf("with an assertion: %v", err)
	}
	if f := forms[1]; f.Get("client_assertion") != "eyJ.assertion.sig" || f.Get("client_assertion_type") != ClientAssertionType ||
		f.Get("client_secret") != "" || f.Get("resource") != "https://api.example.com/" {
		t.Errorf("assertion form = %v", f)
	}

	// The variadic form is unchanged and sends no resource.
	if _, err := client.Auth.ClientCredentials(ctx, "cid", "secret", "a", "b"); err != nil {
		t.Fatal(err)
	}
	if f := forms[2]; f.Get("scope") != "a b" || f.Has("resource") {
		t.Errorf("ClientCredentials form = %v", f)
	}

	for name, params := range map[string]ClientCredentialsParams{
		"no client ID":         {ClientSecret: "s"},
		"no secret":            {ClientID: "c"},
		"secret and assertion": {ClientID: "c", ClientSecret: "s", ClientAssertion: "a"},
		"relative resource":    {ClientID: "c", ClientSecret: "s", Resource: "/api"},
	} {
		if _, err := client.Auth.ClientCredentialsWithParams(ctx, params); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
}
