package lumoauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestClient builds a Client pointed at a test server, with the given
// options applied on top.
func newTestClient(t *testing.T, handler http.HandlerFunc, opts ...Option) (*Client, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	base := []Option{
		WithBaseURL(server.URL),
		WithOrgID("acme-corp"),
		WithAPIKey("lmk_test_key"),
	}
	client, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, server
}

// writeJSON is the test servers' response helper.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func TestCredentialInjection(t *testing.T) {
	t.Run("API keys travel in X-API-Key, never Authorization", func(t *testing.T) {
		var got http.Header
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Clone()
			writeJSON(w, 200, map[string]any{"allowed": true})
		})

		if _, err := client.Permissions.Check(context.Background(), "doc.edit", nil); err != nil {
			t.Fatalf("Check: %v", err)
		}
		if got.Get("X-API-Key") != "lmk_test_key" {
			t.Errorf("X-API-Key = %q, want the API key", got.Get("X-API-Key"))
		}
		if got.Get("Authorization") != "" {
			t.Error("an API key must not also be sent as a bearer token — the server rejects both")
		}
	})

	t.Run("a token provider wins over an API key", func(t *testing.T) {
		var got http.Header
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Clone()
			writeJSON(w, 200, map[string]any{"allowed": true})
		}, WithAccessToken("bearer-token-value"))

		if _, err := client.Permissions.Check(context.Background(), "doc.edit", nil); err != nil {
			t.Fatalf("Check: %v", err)
		}
		if got.Get("Authorization") != "Bearer bearer-token-value" {
			t.Errorf("Authorization = %q", got.Get("Authorization"))
		}
		if got.Get("X-API-Key") != "" {
			t.Error("both credentials were sent; exactly one is allowed")
		}
	})

	t.Run("the token provider is called per request", func(t *testing.T) {
		var calls int
		var seen []string
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			seen = append(seen, r.Header.Get("Authorization"))
			writeJSON(w, 200, map[string]any{"allowed": true})
		}, WithTokenProvider(func(context.Context) (string, error) {
			calls++
			return "token-" + string(rune('0'+calls)), nil
		}))

		ctx := context.Background()
		for i := 0; i < 2; i++ {
			if _, err := client.Permissions.Check(ctx, "doc.edit", nil); err != nil {
				t.Fatalf("Check: %v", err)
			}
		}
		if len(seen) != 2 || seen[0] == seen[1] {
			t.Errorf("expected a fresh token per request, saw %v", seen)
		}
	})

	t.Run("a token provider error surfaces to the caller", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			t.Error("the request should not have been sent")
		}, WithTokenProvider(func(context.Context) (string, error) {
			return "", NewConfigError("no credentials configured")
		}))

		_, err := client.Permissions.Check(context.Background(), "doc.edit", nil)
		if !errors.Is(err, ErrConfig) {
			t.Errorf("expected the provider's config error, got %v", err)
		}
	})

	t.Run("an explicit header is not overwritten", func(t *testing.T) {
		var got string
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("Authorization")
			writeJSON(w, 200, map[string]any{"sub": "user_1"})
		})

		if _, err := client.Auth.UserInfo(context.Background(), "explicit-token"); err != nil {
			t.Fatalf("UserInfo: %v", err)
		}
		if got != "Bearer explicit-token" {
			t.Errorf("Authorization = %q, want the explicitly passed token", got)
		}
	})
}

func TestStatusToTypedErrors(t *testing.T) {
	cases := []struct {
		status   int
		body     any
		sentinel error
		wantMsg  string
	}{
		{401, map[string]any{"error": "invalid_token"}, ErrAuthentication, "invalid_token"},
		{403, map[string]any{"message": "not your document"}, ErrPermissionDenied, "not your document"},
		{404, map[string]any{"detail": "no such document"}, ErrNotFound, "no such document"},
		{429, map[string]any{"error_description": "slow down"}, ErrRateLimited, "slow down"},
		{500, map[string]any{"error": "boom"}, ErrAPI, "boom"},
		{503, nil, ErrAPI, "HTTP 503"},
	}

	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.body == nil {
					w.WriteHeader(tc.status)
					return
				}
				writeJSON(w, tc.status, tc.body)
			})

			_, err := client.Permissions.Check(context.Background(), "doc.edit", nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("errors.Is(err, %v) = false (err: %v)", tc.sentinel, err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("message %q should contain %q", err.Error(), tc.wantMsg)
			}
			if StatusCode(err) != tc.status {
				t.Errorf("StatusCode = %d, want %d", StatusCode(err), tc.status)
			}
		})
	}
}

func TestErrorBodyIsPreserved(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 403, map[string]any{
			"error":             "insufficient_scope",
			"error_description": "needs document.admin",
			"required_scope":    "document.admin",
		})
	})

	_, err := client.Permissions.Check(context.Background(), "doc.edit", nil)
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected an *APIError, got %v", err)
	}

	body, ok := apiErr.Body.(map[string]any)
	if !ok {
		t.Fatalf("Body should decode to a map, got %T", apiErr.Body)
	}
	if body["required_scope"] != "document.admin" {
		t.Errorf("the full error body should be preserved: %v", body)
	}
	if apiErr.Code != "insufficient_scope" {
		t.Errorf("Code = %q, want the server's error code", apiErr.Code)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	t.Run("delay seconds", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "42")
			writeJSON(w, 429, map[string]any{"error": "rate_limited"})
		})

		_, err := client.Permissions.Check(context.Background(), "doc.edit", nil)
		apiErr, _ := AsAPIError(err)
		if apiErr == nil || apiErr.RetryAfter != 42*time.Second {
			t.Errorf("RetryAfter = %v, want 42s", apiErr.RetryAfter)
		}
	})

	t.Run("http date", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", time.Now().Add(2*time.Minute).UTC().Format(http.TimeFormat))
			writeJSON(w, 429, map[string]any{"error": "rate_limited"})
		})

		_, err := client.Permissions.Check(context.Background(), "doc.edit", nil)
		apiErr, _ := AsAPIError(err)
		if apiErr == nil || apiErr.RetryAfter <= 0 || apiErr.RetryAfter > 2*time.Minute {
			t.Errorf("RetryAfter = %v, want roughly 2m", apiErr.RetryAfter)
		}
	})

	t.Run("absent or malformed", func(t *testing.T) {
		if got := parseRetryAfter(""); got != 0 {
			t.Errorf("empty Retry-After = %v, want 0", got)
		}
		if got := parseRetryAfter("soon"); got != 0 {
			t.Errorf("malformed Retry-After = %v, want 0", got)
		}
		if got := parseRetryAfter("-5"); got != 0 {
			t.Errorf("negative Retry-After = %v, want 0", got)
		}
	})
}

func TestNetworkFailureIsWrapped(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {})
	server.Close() // nothing is listening any more

	_, err := client.Permissions.Check(context.Background(), "doc.edit", nil)
	if !errors.Is(err, ErrNetwork) {
		t.Errorf("a transport failure should match ErrNetwork, got %v", err)
	}
}

func TestContextCancellationIsWrapped(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		writeJSON(w, 200, map[string]any{"allowed": true})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := client.Permissions.Check(ctx, "doc.edit", nil)
	if !errors.Is(err, ErrNetwork) {
		t.Errorf("a cancelled context should surface as a network error, got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Error("the context cause should stay reachable through Unwrap")
	}
}

func TestNoContentAndEmptyBodies(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// A 204 must not be a decode failure.
	err := client.Abac.SetUserAttribute(context.Background(), "user-1", "clearance", "secret")
	if err != nil {
		t.Errorf("a 204 response should succeed, got %v", err)
	}
}

func TestFormEncodedTokenRequests(t *testing.T) {
	var contentType, body string
	var authHeader, apiKeyHeader string

	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		authHeader = r.Header.Get("Authorization")
		apiKeyHeader = r.Header.Get("X-API-Key")
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		writeJSON(w, 200, map[string]any{"access_token": "at", "expires_in": 3600})
	})

	if _, err := client.Auth.ClientCredentials(context.Background(), "cid", "secret", "read"); err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}

	if contentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want form encoding", contentType)
	}
	for _, want := range []string{"grant_type=client_credentials", "client_id=cid", "scope=read"} {
		if !strings.Contains(body, want) {
			t.Errorf("form body %q should contain %q", body, want)
		}
	}
	// Token endpoints authenticate through the body; sending the client's
	// own credentials as well would be ambiguous.
	if authHeader != "" || apiKeyHeader != "" {
		t.Errorf("token requests must not carry client credentials as headers (got auth=%q key=%q)",
			authHeader, apiKeyHeader)
	}
}

func TestQueryParameters(t *testing.T) {
	var query string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		writeJSON(w, 200, []map[string]any{})
	})

	if _, err := client.Abac.AttributeDefinitions(context.Background(), AttributeTypeUser); err != nil {
		t.Fatalf("AttributeDefinitions: %v", err)
	}
	if query != "type=user" {
		t.Errorf("query = %q, want type=user", query)
	}
}

func TestOrgScopedRoutesRequireAnOrgID(t *testing.T) {
	client, err := New(WithBaseURL("https://example.test"), WithAPIKey("lmk_x"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = client.Agents.Ask(context.Background(), "document.read", nil)
	if !errors.Is(err, ErrConfig) {
		t.Errorf("a missing org ID should be a config error, got %v", err)
	}
	if !strings.Contains(err.Error(), "LUMOAUTH_ORG_ID") {
		t.Errorf("the error should say how to fix it: %v", err)
	}

	// Unscoped routes still work without one.
	if _, err := client.Permissions.Check(context.Background(), "doc.edit", nil); errors.Is(err, ErrConfig) {
		t.Error("bearer-scoped routes should not require an org ID")
	}
}

func TestNewRequiresACredential(t *testing.T) {
	t.Setenv(EnvAPIKey, "")

	_, err := New(WithBaseURL("https://example.test"))
	if !errors.Is(err, ErrConfig) {
		t.Errorf("New without a credential should fail with a config error, got %v", err)
	}
}

func TestNewReadsEnvironment(t *testing.T) {
	t.Setenv(EnvBaseURL, "https://env.example.test")
	t.Setenv(EnvOrgID, "env-org")
	t.Setenv(EnvAPIKey, "lmk_env")

	client, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.BaseURL() != "https://env.example.test" {
		t.Errorf("BaseURL = %q", client.BaseURL())
	}
	if client.OrgID() != "env-org" {
		t.Errorf("OrgID = %q", client.OrgID())
	}

	// Explicit options beat the environment.
	client, err = New(WithBaseURL("https://explicit.test"), WithOrgID("explicit-org"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.BaseURL() != "https://explicit.test" || client.OrgID() != "explicit-org" {
		t.Errorf("options should win over the environment: %s / %s", client.BaseURL(), client.OrgID())
	}
}

func TestTrailingSlashesAreNormalized(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		writeJSON(w, 200, map[string]any{"allowed": true})
	}))
	defer server.Close()

	client, err := New(WithBaseURL(server.URL+"///"), WithAPIKey("lmk_x"), WithOrgID("acme"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Permissions.Check(context.Background(), "doc.edit", nil); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if path != "/api/v1/authz/check" {
		t.Errorf("path = %q — a trailing slash on the base URL leaked into the request", path)
	}
}

func TestAPIConfigEscapeHatch(t *testing.T) {
	t.Run("with an API key", func(t *testing.T) {
		client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {})

		cfg, err := client.APIConfig(context.Background())
		if err != nil {
			t.Fatalf("APIConfig: %v", err)
		}
		if cfg.BaseURL != server.URL {
			t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, server.URL)
		}
		if cfg.DefaultHeader["X-API-Key"] != "lmk_test_key" {
			t.Errorf("headers = %v, want an X-API-Key entry", cfg.DefaultHeader)
		}
		if _, both := cfg.DefaultHeader["Authorization"]; both {
			t.Error("the generated client must receive exactly one credential header")
		}
	})

	t.Run("with a bearer token", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {},
			WithAccessToken("bearer-value"))

		cfg, err := client.APIConfig(context.Background())
		if err != nil {
			t.Fatalf("APIConfig: %v", err)
		}
		if cfg.DefaultHeader["Authorization"] != "Bearer bearer-value" {
			t.Errorf("headers = %v", cfg.DefaultHeader)
		}
		if _, both := cfg.DefaultHeader["X-API-Key"]; both {
			t.Error("the generated client must receive exactly one credential header")
		}
	})
}

func TestDoEscapeHatch(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme-corp/api/v1/admin/users" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		writeJSON(w, 200, map[string]any{"data": []map[string]any{{"id": "user_1"}}})
	})

	path, err := client.OrgPath("/admin/users")
	if err != nil {
		t.Fatalf("OrgPath: %v", err)
	}

	var page struct {
		Data []map[string]any `json:"data"`
	}
	if err := client.Do(context.Background(), http.MethodGet, path, nil, &page); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(page.Data) != 1 {
		t.Errorf("decoded %d records, want 1", len(page.Data))
	}
}

func TestUserAgentIsSent(t *testing.T) {
	var agent string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		agent = r.Header.Get("User-Agent")
		writeJSON(w, 200, map[string]any{"allowed": true})
	})

	if _, err := client.Permissions.Check(context.Background(), "doc.edit", nil); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !strings.HasPrefix(agent, "lumoauth-go/") {
		t.Errorf("User-Agent = %q, want a lumoauth-go prefix", agent)
	}
}
