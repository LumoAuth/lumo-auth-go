package lumoauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Custom domains, against the cross-SDK vector
// (sdk-contract/vectors/custom-domain.json) and with a test server in the
// place of the organization's own domain. A test server listens on
// http://127.0.0.1:<port>, which the option accepts, so every behaviour
// test sends real requests and looks at the paths that arrive.

// ── The vector ────────────────────────────────────────────────────────

type customDomainVector struct {
	Platform struct {
		BaseURL string `json:"base_url"`
		OrgID   string `json:"org_id"`
	} `json:"platform"`
	CustomDomain struct {
		CustomDomain string `json:"custom_domain"`
	} `json:"custom_domain"`
	Derived map[string]struct {
		Platform     string `json:"platform"`
		CustomDomain string `json:"custom_domain"`
	} `json:"derived"`
	Values struct {
		Valid []struct {
			Input      string `json:"input"`
			Normalized string `json:"normalized"`
		} `json:"valid"`
		Invalid []string `json:"invalid"`
		NotSet  []string `json:"not_set"`
	} `json:"custom_domain_values"`
	Routes []struct {
		Route           string            `json:"route"`
		Params          map[string]string `json:"params"`
		PlatformURL     string            `json:"platform_url"`
		CustomDomainURL string            `json:"custom_domain_url"`
	} `json:"routes"`
	AAuth struct {
		IssuerMetadataURL struct {
			Platform     string `json:"platform"`
			CustomDomain string `json:"custom_domain"`
		} `json:"issuer_metadata_url"`
		Document       map[string]any `json:"issuer_metadata_document_on_the_custom_domain"`
		ExpectedIssuer struct {
			Platform     string `json:"platform"`
			CustomDomain string `json:"custom_domain"`
		} `json:"expected_issuer"`
		Accepted string `json:"token_with_issuer_accepted_on_a_custom_domain"`
		Refused  string `json:"token_with_issuer_refused_on_a_custom_domain"`
	} `json:"aauth"`
}

func loadCustomDomainVector(t *testing.T) *customDomainVector {
	t.Helper()
	var vector customDomainVector
	loadContract(t, contractDir(t), "vectors/custom-domain.json", &vector)
	if len(vector.Routes) == 0 || len(vector.Derived) == 0 || len(vector.Values.Valid) == 0 ||
		len(vector.Values.Invalid) == 0 || len(vector.Values.NotSet) == 0 {
		t.Fatal("the custom domain vector has an empty case list")
	}
	return &vector
}

// vectorClients builds the two clients of the vector: one on the platform
// host with the organization ID, one on the custom domain without it.
func vectorClients(t *testing.T, vector *customDomainVector) (platform, custom *Client) {
	t.Helper()
	t.Setenv(EnvOrgID, "")
	t.Setenv(EnvBaseURL, "")
	t.Setenv(EnvCustomDomain, "")
	platform, err := New(WithAPIKey("lmk_x"), WithBaseURL(vector.Platform.BaseURL), WithOrgID(vector.Platform.OrgID))
	if err != nil {
		t.Fatalf("New (platform): %v", err)
	}
	custom, err = New(WithAPIKey("lmk_x"), WithCustomDomain(vector.CustomDomain.CustomDomain))
	if err != nil {
		t.Fatalf("New (custom domain): %v", err)
	}
	return platform, custom
}

func TestContractCustomDomainValues(t *testing.T) {
	vector := loadCustomDomainVector(t)
	t.Setenv(EnvCustomDomain, "")
	t.Setenv(EnvOrgID, "")

	for _, c := range vector.Values.Valid {
		got, err := normalizeCustomDomain(c.Input)
		if err != nil || got != c.Normalized {
			t.Errorf("normalizeCustomDomain(%q) = %q, %v; want %q", c.Input, got, err, c.Normalized)
		}
		client, err := New(WithAPIKey("lmk_x"), WithCustomDomain(c.Input))
		if err != nil {
			t.Errorf("New with the custom domain %q: %v", c.Input, err)
			continue
		}
		if client.CustomDomain() != c.Normalized || client.BaseURL() != c.Normalized {
			t.Errorf("%q: CustomDomain() = %q, BaseURL() = %q; want %q", c.Input, client.CustomDomain(), client.BaseURL(), c.Normalized)
		}
		if issuer, err := client.Issuer(); err != nil || issuer != c.Normalized {
			t.Errorf("%q: Issuer() = %q, %v; want the bare domain %q", c.Input, issuer, err, c.Normalized)
		}
	}

	for _, input := range vector.Values.Invalid {
		if got, err := normalizeCustomDomain(input); !errors.Is(err, ErrConfig) || got != "" {
			t.Errorf("normalizeCustomDomain(%q) = %q, %v; want a configuration error", input, got, err)
		}
		// The error is raised when the client or helper is created.
		for name, err := range customDomainConstructorErrors(t, input) {
			if !errors.Is(err, ErrConfig) {
				t.Errorf("%s with the custom domain %q: expected a configuration error, got %v", name, input, err)
			}
		}
	}

	for _, input := range vector.Values.NotSet {
		if got, err := normalizeCustomDomain(input); err != nil || got != "" {
			t.Errorf("normalizeCustomDomain(%q) = %q, %v; want \"not set\"", input, got, err)
		}
		client, err := New(WithAPIKey("lmk_x"), WithBaseURL(vector.Platform.BaseURL),
			WithOrgID(vector.Platform.OrgID), WithCustomDomain(input))
		if err != nil {
			t.Errorf("New with the custom domain %q: %v", input, err)
			continue
		}
		if client.CustomDomain() != "" || client.BaseURL() != vector.Platform.BaseURL {
			t.Errorf("%q must mean \"not set\": CustomDomain() = %q, BaseURL() = %q", input, client.CustomDomain(), client.BaseURL())
		}
	}
}

// customDomainConstructorErrors passes one custom domain value to every
// constructor and helper that takes the option, and returns their errors.
func customDomainConstructorErrors(t *testing.T, value string) map[string]error {
	t.Helper()
	keypair, err := GenerateKeypair("agent-key")
	if err != nil {
		t.Fatal(err)
	}
	errs := map[string]error{}
	_, errs["New"] = New(WithAPIKey("lmk_x"), WithCustomDomain(value))
	_, errs["NewAgent"] = NewAgent(AgentConfig{CustomDomain: value, ClientID: "c", ClientSecret: "s"})
	_, errs["NewWebAuth"] = NewWebAuth(WebConfig{CustomDomain: value, ClientID: "c", SessionSecret: testSessionSecret})
	_, errs["NewAAuthClient"] = NewAAuthClient(AAuthConfig{
		CustomDomain: value, AgentIdentifier: "https://my-agent.example.com", PrivateKeyPEM: keypair.PrivateKeyPEM,
	})
	_, errs["NewAccessTokenKeyCacheForCustomDomain"] = NewAccessTokenKeyCacheForCustomDomain(value, 0, nil)
	_, errs["NewJWKSCacheForCustomDomain"] = NewJWKSCacheForCustomDomain(value, 0, nil)
	_, errs["VerifyAccessToken"] = VerifyAccessToken(context.Background(), "a.b.c",
		AccessTokenVerifyOptions{CustomDomain: value, Resource: testResource})
	_, errs["VerifyAuthToken"] = VerifyAuthToken(context.Background(), "a.b.c",
		VerifyOptions{CustomDomain: value, Resource: testResource})
	_, errs["NewJITContext"] = NewJITContext(fixedSource{baseURL: "https://app.lumoauth.dev", orgID: "acme-corp", customDomain: value})
	// NewDelegationChain returns no error: the first address does.
	_, errs["NewDelegationChain"] = NewDelegationChain(
		fixedSource{baseURL: "https://app.lumoauth.dev", orgID: "acme-corp", customDomain: value},
		"https://agent.example.com/callback").ConsentURL("session-1", nil, "")
	return errs
}

// fixedSource is a TokenSource and ConfidentialClient that an application
// wrote itself, with the optional CustomDomain method.
type fixedSource struct {
	baseURL, orgID, customDomain string
}

func (s fixedSource) BaseURL() string                             { return s.baseURL }
func (s fixedSource) OrgID() string                               { return s.orgID }
func (s fixedSource) CustomDomain() string                        { return s.customDomain }
func (s fixedSource) AccessToken(context.Context) (string, error) { return "source-token", nil }
func (s fixedSource) ClientID() string                            { return "source-client" }
func (s fixedSource) ClientSecret() string                        { return "source-secret" }

// plainSource is a TokenSource without the CustomDomain method.
type plainSource struct{ baseURL, orgID string }

func (s plainSource) BaseURL() string                             { return s.baseURL }
func (s plainSource) OrgID() string                               { return s.orgID }
func (s plainSource) AccessToken(context.Context) (string, error) { return "source-token", nil }

func TestContractCustomDomainRoutes(t *testing.T) {
	vector := loadCustomDomainVector(t)
	platform, custom := vectorClients(t, vector)

	// The organization ID given next to a custom domain is never put in a
	// path, and a base URL given next to it is never used.
	customWithOrg, err := New(WithAPIKey("lmk_x"), WithCustomDomain(vector.CustomDomain.CustomDomain),
		WithOrgID(vector.Platform.OrgID), WithBaseURL("https://unused.invalid"))
	if err != nil {
		t.Fatal(err)
	}

	var features struct {
		SDKs map[string]struct {
			KnownMissingRoutes map[string]string `json:"known_missing_routes"`
		} `json:"sdks"`
	}
	loadContract(t, contractDir(t), "features.json", &features)
	knownMissing := features.SDKs["go"].KnownMissingRoutes

	// The servers that receive the routes as real requests.
	var platformPaths, customPaths []string
	record := func(paths *[]string) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*paths = append(*paths, r.URL.EscapedPath())
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(server.Close)
		return server
	}
	platformServer, customServer := record(&platformPaths), record(&customPaths)
	wirePlatform, err := New(WithAPIKey("lmk_x"), WithBaseURL(platformServer.URL), WithOrgID(vector.Platform.OrgID))
	if err != nil {
		t.Fatal(err)
	}
	wireCustom, err := New(WithAPIKey("lmk_x"), WithCustomDomain(customServer.URL), WithBaseURL(platformServer.URL))
	if err != nil {
		t.Fatal(err)
	}

	covered := map[string]bool{}
	for _, c := range vector.Routes {
		if _, missing := knownMissing[c.Route]; missing {
			continue
		}
		if _, ok := Routes[c.Route]; !ok {
			// TestContractRoutes reports a contract route that the
			// registry lacks.
			t.Logf("the registry has no route %s", c.Route)
			continue
		}
		covered[c.Route] = true

		t.Run(c.Route, func(t *testing.T) {
			if got, err := platform.http.routeURL(c.Route, c.Params); err != nil || got != c.PlatformURL {
				t.Errorf("platform URL = %q, %v; want %q", got, err, c.PlatformURL)
			}
			if got, err := custom.http.routeURL(c.Route, c.Params); err != nil || got != c.CustomDomainURL {
				t.Errorf("custom domain URL = %q, %v; want %q", got, err, c.CustomDomainURL)
			}
			if got, err := customWithOrg.http.routeURL(c.Route, c.Params); err != nil || got != c.CustomDomainURL {
				t.Errorf("custom domain URL with an organization ID = %q, %v; want %q", got, err, c.CustomDomainURL)
			}

			// The same route as a request through the transport.
			platformPaths, customPaths = nil, nil
			ctx := context.Background()
			if err := wirePlatform.http.call(ctx, c.Route, c.Params, &request{}, nil); err != nil {
				t.Fatalf("call on the platform host: %v", err)
			}
			if err := wireCustom.http.call(ctx, c.Route, c.Params, &request{}, nil); err != nil {
				t.Fatalf("call on the custom domain: %v", err)
			}
			wantPlatform, wantCustom := mustPath(t, c.PlatformURL), mustPath(t, c.CustomDomainURL)
			if len(platformPaths) != 1 || platformPaths[0] != wantPlatform {
				t.Errorf("the platform host got %v, want [%s]", platformPaths, wantPlatform)
			}
			if len(customPaths) != 1 || customPaths[0] != wantCustom {
				t.Errorf("the custom domain got %v, want [%s]", customPaths, wantCustom)
			}
		})
	}

	// Every route of the registry is in the vector, so none is addressed
	// by a rule that no test has seen.
	for _, name := range RouteNames() {
		if !covered[name] {
			t.Errorf("the route %s of the registry is not in the custom domain vector", name)
		}
	}
}

func mustPath(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return parsed.EscapedPath()
}

func TestContractCustomDomainDerived(t *testing.T) {
	vector := loadCustomDomainVector(t)
	platform, custom := vectorClients(t, vector)
	domain := vector.CustomDomain.CustomDomain

	withoutQuery := func(rawURL string, err error) (string, error) {
		base, _, _ := strings.Cut(rawURL, "?")
		return base, err
	}
	authorizeParams := AuthorizationURLParams{ClientID: "web-client", RedirectURI: "https://app.example.com/auth/callback"}

	// The addresses that this SDK builds itself, each for both forms.
	builders := map[string]func(client *Client, onCustomDomain bool) (string, error){
		"issuer": func(client *Client, _ bool) (string, error) { return client.Issuer() },
		"openid_configuration": func(client *Client, onCustomDomain bool) (string, error) {
			opts := AccessTokenVerifyOptions{}
			if onCustomDomain {
				opts.CustomDomain = client.CustomDomain()
			} else {
				issuer, err := client.Issuer()
				if err != nil {
					return "", err
				}
				opts.Issuer = issuer
			}
			_, discoveryURL, err := opts.trustedIssuer()
			return discoveryURL, err
		},
		"authorization_endpoint": func(client *Client, _ bool) (string, error) {
			return withoutQuery(client.Auth.AuthorizationURL(authorizeParams))
		},
		"end_session_endpoint": func(client *Client, _ bool) (string, error) {
			return client.http.routeURL(RouteOAuthLogout, nil)
		},
	}
	// The addresses that this SDK never builds.
	notBuilt := map[string]string{
		"authorization_server_metadata": "the SDK reads the OpenID Connect discovery document only",
		"jwks":                          "the SDK reads jwks_uri from the discovery document",
		"hosted_login_page":             "the web sign-in helper starts at the authorization endpoint",
	}

	names := make([]string, 0, len(vector.Derived))
	for name := range vector.Derived {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		want := vector.Derived[name]
		build, ok := builders[name]
		if !ok {
			if reason, known := notBuilt[name]; known {
				t.Logf("%s is not built by this SDK: %s", name, reason)
			} else {
				t.Logf("%s is a derived address that this test does not know", name)
			}
			continue
		}
		if got, err := build(platform, false); err != nil || got != want.Platform {
			t.Errorf("%s on the platform host = %q, %v; want %q", name, got, err, want.Platform)
		}
		if got, err := build(custom, true); err != nil || got != want.CustomDomain {
			t.Errorf("%s on the custom domain = %q, %v; want %q", name, got, err, want.CustomDomain)
		}
	}
	if _, ok := vector.Derived["issuer"]; !ok {
		t.Fatal("the vector has no derived issuer")
	}

	// The issuer has more than one reader. They all give the same value.
	issuer := vector.Derived["issuer"]
	if got := IssuerFor(vector.Platform.BaseURL, vector.Platform.OrgID); got != issuer.Platform {
		t.Errorf("IssuerFor = %q, want %q", got, issuer.Platform)
	}
	for onCustomDomain, want := range map[bool]string{false: issuer.Platform, true: issuer.CustomDomain} {
		agentCfg := AgentConfig{ClientID: assertionAgentID}
		if onCustomDomain {
			agentCfg.CustomDomain = domain
		} else {
			agentCfg.BaseURL, agentCfg.OrgID = vector.Platform.BaseURL, vector.Platform.OrgID
		}

		// The audience of a client assertion is the issuer. (AAuth has its
		// own issuer rule: see TestContractCustomDomainAAuth.)
		signer, err := GenerateClientAssertionSigner("EdDSA", "agent-key")
		if err != nil {
			t.Fatal(err)
		}
		agentCfg.PrivateKey = signer
		agent, err := NewAgent(agentCfg)
		if err != nil {
			t.Fatal(err)
		}
		assertion, err := agent.ClientAssertion()
		if err != nil {
			t.Fatal(err)
		}
		if _, claims, _, _ := splitAssertion(t, assertion); claims["aud"] != want {
			t.Errorf("client assertion aud = %v, want %q", claims["aud"], want)
		}
	}
}

// ── The test server in the place of the custom domain ─────────────────

type domainCall struct {
	Method string
	Path   string
	Host   string
	Header http.Header
	Form   url.Values
	Raw    []byte
}

// domainServer records every request and answers with one body that is
// good enough for every call of the SDK: a token, a decision, a task, a
// verified Personal Agent Protocol result.
func domainServer(t *testing.T, calls *[]domainCall) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		call := domainCall{Method: r.Method, Path: r.URL.EscapedPath(), Host: r.Host, Header: r.Header.Clone(), Raw: raw}
		if strings.Contains(r.Header.Get("Content-Type"), "form-urlencoded") {
			call.Form, _ = url.ParseQuery(string(raw))
		}
		*calls = append(*calls, call)
		writeJSON(w, 200, map[string]any{
			"allowed": true, "access_token": "domain-token", "token_type": "Bearer", "expires_in": 3600,
			"task_id": "task_1", "request_id": "req_1", "status": "approved", "sub": "user_1",
			"active": true, "client_id": "https://agent.example/agent.json", "user_id": "usr_1",
			"session": map[string]any{"id": 1, "sid": "sid-1", "new": true}, "ended": true,
			"request_type": "auth", "auth_token": "auth-jwt",
		})
	}))
	t.Cleanup(server.Close)
	return server
}

// assertPrefixLess checks the paths that the custom domain received: the
// expected ones, in order, and none with an /orgs/ segment.
func assertPrefixLess(t *testing.T, calls []domainCall, want ...string) {
	t.Helper()
	got := make([]string, len(calls))
	for i, call := range calls {
		got[i] = call.Path
		if strings.Contains(call.Path, "/orgs/") {
			t.Errorf("a request to the custom domain carries an /orgs/ segment: %s", call.Path)
		}
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("paths = %v\nwant    %v", got, want)
	}
}

// noRequests is a base URL whose server fails the test when it is used.
func noRequests(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the base URL got %s %s although a custom domain is set", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func cleanDomainEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvOrgID, "")
	t.Setenv(EnvBaseURL, "")
	t.Setenv(EnvCustomDomain, "")
	t.Setenv(EnvAPIKey, "")
}

// ── One call per namespace ────────────────────────────────────────────

func TestCustomDomainNamespaces(t *testing.T) {
	cleanDomainEnv(t)
	ctx := context.Background()
	var calls []domainCall
	server := domainServer(t, &calls)

	// No organization ID, and a base URL that must stay unused.
	client, err := New(WithCustomDomain(server.URL), WithBaseURL(noRequests(t)),
		WithAccessToken("user-token"), WithClientCredentials("shop-api", "shop-secret"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.OrgID() != "" || client.BaseURL() != server.URL {
		t.Fatalf("OrgID() = %q, BaseURL() = %q", client.OrgID(), client.BaseURL())
	}

	namespaces := []struct {
		name string
		call func() error
		want []string
	}{
		{"permissions", func() error {
			_, err := client.Permissions.Check(ctx, "document.edit", nil)
			return err
		}, []string{"/api/v1/authz/check"}},
		{"zanzibar", func() error {
			_, err := client.Zanzibar.Check(ctx, "document:readme", "viewer", "user:bob")
			return err
		}, []string{"/api/v1/authz/zanzibar/check"}},
		{"abac", func() error {
			_, err := client.Abac.Check(ctx, AbacCheckParams{ResourceType: "document", Action: "read"})
			return err
		}, []string{"/api/v1/abac/check"}},
		{"auth: token", func() error {
			_, err := client.Auth.ClientCredentials(ctx, "client", "secret")
			return err
		}, []string{"/api/v1/oauth/token"}},
		{"auth: userinfo", func() error {
			_, err := client.Auth.UserInfo(ctx, "user-token")
			return err
		}, []string{"/api/v1/oauth/userinfo"}},
		{"auth: revoke", func() error {
			return client.Auth.Revoke(ctx, RevokeParams{Token: "refresh", ClientID: "client"})
		}, []string{"/api/v1/oauth/revoke"}},
		{"agents", func() error {
			_, err := client.Agents.Ask(ctx, "document:read", nil)
			return err
		}, []string{"/api/v1/agents/ask"}},
		{"agents: MCP tool", func() error {
			_, err := client.Agents.AuthorizeMcpTool(ctx, "mcp_0123", "send_invoice")
			return err
		}, []string{"/api/v1/agents/me/mcp/authorize"}},
		{"approvals", func() error {
			_, err := client.Approvals.Status(ctx, "tok_abc")
			return err
		}, []string{"/api/v1/agents/me/approvals/tok_abc/status"}},
		{"jit", func() error {
			_, err := client.Jit.CreateTask(ctx, CreateTaskParams{Name: "Analyse the report"})
			return err
		}, []string{"/api/v1/jit/task"}},
		{"mcp: tool check", func() error {
			_, err := client.Mcp.AuthorizeTool(ctx, McpToolAuthorizeParams{
				ServerID: "mcp_0123", SubjectType: "user", SubjectID: "user_1", Tool: "send_invoice"})
			return err
		}, []string{"/api/v1/mcp/servers/mcp_0123/tools/authorize"}},
		{"mcp: token", func() error {
			_, err := client.Mcp.Token(ctx, "https://mcp.example.com/mcp", "")
			return err
		}, []string{"/api/v1/oauth/token"}},
		{"delegation", func() error {
			_, err := client.Delegation.Exchange(ctx, "subject-token", "actor-token")
			return err
		}, []string{"/api/v1/oauth/token"}},
		{"poppy: verify", func() error {
			_, err := client.Poppy.VerifyRequest(ctx, PoppyRequest{Method: "GET", URL: "https://shop.example.com/api/orders"}, nil)
			return err
		}, []string{"/api/v1/poppy/sessions/verify"}},
		{"poppy: status", func() error {
			_, err := client.Poppy.GetSessionStatus(ctx, "https://agent.example/agent.json", "sid-1")
			return err
		}, []string{"/api/v1/poppy/sessions/status"}},
		{"poppy: end", func() error {
			_, err := client.Poppy.EndSession(ctx, "https://agent.example/agent.json", "sid-1")
			return err
		}, []string{"/api/v1/poppy/sessions/end"}},
	}
	for _, namespace := range namespaces {
		t.Run(namespace.name, func(t *testing.T) {
			calls = nil
			if err := namespace.call(); err != nil {
				t.Fatalf("the call failed: %v", err)
			}
			assertPrefixLess(t, calls, namespace.want...)
		})
	}

	t.Run("the authorization URL", func(t *testing.T) {
		got, err := client.Auth.AuthorizationURL(AuthorizationURLParams{ClientID: "web", RedirectURI: "https://app.example.com/cb"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(got, server.URL+"/api/v1/oauth/authorize?") {
			t.Errorf("AuthorizationURL = %q", got)
		}
	})

	t.Run("the Personal Agent Protocol middleware", func(t *testing.T) {
		calls = nil
		protect, err := client.Poppy.Middleware(PoppyMiddlewareOptions{PublicOrigin: "https://shop.example.com"})
		if err != nil {
			t.Fatalf("Middleware needs no organization ID on a custom domain: %v", err)
		}
		handled := false
		recorder := httptest.NewRecorder()
		protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, handled = PoppyFromContext(r.Context())
		})).ServeHTTP(recorder, httptest.NewRequest("GET", "/api/orders", nil))
		if !handled {
			t.Errorf("the handler did not get a verified result: status %d", recorder.Code)
		}
		assertPrefixLess(t, calls, "/api/v1/poppy/sessions/verify")
	})
}

// ── Configuration ─────────────────────────────────────────────────────

func TestCustomDomainFromTheEnvironment(t *testing.T) {
	cleanDomainEnv(t)
	var calls []domainCall
	server := domainServer(t, &calls)
	t.Setenv(EnvCustomDomain, "  "+strings.ToUpper(server.URL)+"/ ")
	// The base URL from the environment and from the option both lose.
	t.Setenv(EnvBaseURL, noRequests(t))
	ctx := context.Background()

	client, err := New(WithAPIKey("lmk_x"), WithBaseURL(noRequests(t)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.CustomDomain() != server.URL {
		t.Fatalf("CustomDomain() = %q, want %q", client.CustomDomain(), server.URL)
	}
	if _, err := client.Abac.Check(ctx, AbacCheckParams{ResourceType: "document", Action: "read"}); err != nil {
		t.Fatalf("Check: %v", err)
	}

	agent, err := NewAgent(AgentConfig{ClientID: "c", ClientSecret: "s", BaseURL: noRequests(t)})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	if agent.CustomDomain() != server.URL || agent.BaseURL() != server.URL {
		t.Errorf("agent: CustomDomain() = %q, BaseURL() = %q", agent.CustomDomain(), agent.BaseURL())
	}
	if _, err := agent.Ask(ctx, "document:read", nil); err != nil {
		t.Fatalf("Ask: %v", err)
	}

	auth, err := NewWebAuth(WebConfig{ClientID: "web", SessionSecret: testSessionSecret})
	if err != nil {
		t.Fatalf("NewWebAuth without an organization: %v", err)
	}
	if auth.Client().CustomDomain() != server.URL {
		t.Errorf("WebAuth: CustomDomain() = %q", auth.Client().CustomDomain())
	}

	keypair, err := GenerateKeypair("agent-key")
	if err != nil {
		t.Fatal(err)
	}
	aauth, err := NewAAuthClient(AAuthConfig{AgentIdentifier: "https://my-agent.example.com", PrivateKeyPEM: keypair.PrivateKeyPEM})
	if err != nil {
		t.Fatalf("NewAAuthClient: %v", err)
	}
	if aauth.CustomDomain() != server.URL || aauth.BaseURL() != server.URL {
		t.Errorf("AAuth: CustomDomain() = %q, BaseURL() = %q", aauth.CustomDomain(), aauth.BaseURL())
	}
	// The AAuth issuer is never derived from the domain.
	if aauth.Issuer() != "" {
		t.Errorf("AAuth: Issuer() = %q before the metadata document was read", aauth.Issuer())
	}

	assertPrefixLess(t, calls, "/api/v1/abac/check", "/api/v1/oauth/token", "/api/v1/agents/ask")

	// An option wins over the environment variable.
	var otherCalls []domainCall
	other := domainServer(t, &otherCalls)
	client, err = New(WithAPIKey("lmk_x"), WithCustomDomain(other.URL))
	if err != nil {
		t.Fatal(err)
	}
	if client.CustomDomain() != other.URL {
		t.Errorf("CustomDomain() = %q, want the option's value %q", client.CustomDomain(), other.URL)
	}
}

func TestWithoutCustomDomainNothingChanges(t *testing.T) {
	cleanDomainEnv(t)
	var calls []domainCall
	server := domainServer(t, &calls)
	client, err := New(WithAPIKey("lmk_x"), WithBaseURL(server.URL), WithOrgID("acme-corp"))
	if err != nil {
		t.Fatal(err)
	}
	if client.CustomDomain() != "" {
		t.Errorf("CustomDomain() = %q", client.CustomDomain())
	}
	if issuer, err := client.Issuer(); err != nil || issuer != server.URL+"/orgs/acme-corp/api/v1" {
		t.Errorf("Issuer() = %q, %v", issuer, err)
	}
	if path, err := client.OrgPath("/admin/users"); err != nil || path != "/orgs/acme-corp/api/v1/admin/users" {
		t.Errorf("OrgPath = %q, %v", path, err)
	}
	ctx := context.Background()
	if _, err := client.Abac.Check(ctx, AbacCheckParams{ResourceType: "document", Action: "read"}); err != nil {
		t.Fatal(err)
	}
	// A path that the caller wrote is sent as it is.
	if err := client.Do(ctx, "GET", "/orgs/acme-corp/api/v1/admin/users", nil, nil); err != nil {
		t.Fatal(err)
	}
	if calls[0].Path != "/orgs/acme-corp/api/v1/abac/check" || calls[1].Path != "/orgs/acme-corp/api/v1/admin/users" {
		t.Errorf("paths = %s, %s", calls[0].Path, calls[1].Path)
	}

	// Without an organization ID the platform host still needs one.
	noOrg, err := New(WithAPIKey("lmk_x"), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noOrg.Abac.Check(ctx, AbacCheckParams{ResourceType: "document", Action: "read"}); !errors.Is(err, ErrConfig) {
		t.Errorf("expected a configuration error without an organization ID, got %v", err)
	}
	if _, err := noOrg.Issuer(); !errors.Is(err, ErrConfig) {
		t.Errorf("Issuer() without an organization ID: %v", err)
	}
	if _, err := NewWebAuth(WebConfig{BaseURL: server.URL, ClientID: "web", SessionSecret: testSessionSecret}); !errors.Is(err, ErrConfig) {
		t.Errorf("NewWebAuth without an organization and without a custom domain: %v", err)
	}
}

// ── Paths that the caller writes ──────────────────────────────────────

func TestCustomDomainEscapeHatches(t *testing.T) {
	cleanDomainEnv(t)
	ctx := context.Background()
	var calls []domainCall
	server := domainServer(t, &calls)

	withOrg, err := New(WithAPIKey("lmk_x"), WithCustomDomain(server.URL), WithOrgID("acme corp"))
	if err != nil {
		t.Fatal(err)
	}
	withoutOrg, err := New(WithAPIKey("lmk_x"), WithCustomDomain(server.URL))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("OrgPath", func(t *testing.T) {
		for _, client := range []*Client{withOrg, withoutOrg} {
			if path, err := client.OrgPath("/admin/users"); err != nil || path != "/api/v1/admin/users" {
				t.Errorf("OrgPath = %q, %v", path, err)
			}
		}
	})

	t.Run("Do", func(t *testing.T) {
		cases := []struct {
			client *Client
			path   string
			want   string
		}{
			// The prefix-less path is what a caller gives on a custom domain.
			{withoutOrg, "/api/v1/admin/users", "/api/v1/admin/users"},
			{withOrg, "/api/v1/admin/users", "/api/v1/admin/users"},
			// The segment of the client's own organization is removed, in
			// its encoded and in its plain spelling.
			{withOrg, "/orgs/acme%20corp/api/v1/admin/users", "/api/v1/admin/users"},
			{withOrg, "/orgs/acme%20corp/api/v1/admin/users?limit=5", "/api/v1/admin/users"},
			// Another organization, or an unknown one: never guessed.
			{withOrg, "/orgs/other/api/v1/admin/users", "/orgs/other/api/v1/admin/users"},
			{withOrg, "/orgs/acme%20corporation/api/v1/x", "/orgs/acme%20corporation/api/v1/x"},
			{withoutOrg, "/orgs/acme%20corp/api/v1/admin/users", "/orgs/acme%20corp/api/v1/admin/users"},
		}
		for _, c := range cases {
			calls = nil
			if err := c.client.Do(ctx, "GET", c.path, nil, nil); err != nil {
				t.Fatalf("Do(%q): %v", c.path, err)
			}
			if len(calls) != 1 || calls[0].Path != c.want {
				t.Errorf("Do(%q) sent %v, want %s", c.path, calls, c.want)
			}
		}

		// An absolute URL is used as it is.
		calls = nil
		if err := withOrg.Do(ctx, "GET", server.URL+"/orgs/acme%20corp/api/v1/x", nil, nil); err != nil {
			t.Fatal(err)
		}
		if calls[0].Path != "/orgs/acme%20corp/api/v1/x" {
			t.Errorf("an absolute URL was changed: %s", calls[0].Path)
		}
	})

	t.Run("APIConfig for the generated client", func(t *testing.T) {
		cfg, err := withOrg.APIConfig(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.BaseURL != server.URL {
			t.Errorf("BaseURL = %q", cfg.BaseURL)
		}
		// The generated client always sends the prefixed path.
		send := func(httpClient *http.Client, target string) string {
			calls = nil
			req, _ := http.NewRequest("GET", target, nil)
			original := req.URL.String()
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if req.URL.String() != original {
				t.Errorf("the transport changed the caller's request: %s", req.URL)
			}
			if len(calls) != 1 {
				t.Fatalf("%d calls", len(calls))
			}
			return calls[0].Path
		}
		if got := send(cfg.HTTPClient, server.URL+"/orgs/acme%20corp/api/v1/admin/users?limit=5"); got != "/api/v1/admin/users" {
			t.Errorf("own organization: path = %s", got)
		}
		if got := send(cfg.HTTPClient, server.URL+"/orgs/other/api/v1/admin/users"); got != "/orgs/other/api/v1/admin/users" {
			t.Errorf("another organization: path = %s", got)
		}
		// A request to another host is not touched.
		var elsewhere []domainCall
		other := domainServer(t, &elsewhere)
		calls = nil
		resp, err := cfg.HTTPClient.Get(other.URL + "/orgs/acme%20corp/api/v1/admin/users")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if len(elsewhere) != 1 || elsewhere[0].Path != "/orgs/acme%20corp/api/v1/admin/users" {
			t.Errorf("another host got %v", elsewhere)
		}

		// Without an organization ID the SDK cannot know the segment.
		cfg, err = withoutOrg.APIConfig(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got := send(cfg.HTTPClient, server.URL+"/orgs/acme%20corp/api/v1/admin/users"); got != "/orgs/acme%20corp/api/v1/admin/users" {
			t.Errorf("unknown organization: path = %s", got)
		}
	})
}

// ── Agent, DPoP, JIT, delegation ──────────────────────────────────────

func TestCustomDomainAgent(t *testing.T) {
	cleanDomainEnv(t)
	ctx := context.Background()

	t.Run("client credentials and calls, without an organization ID", func(t *testing.T) {
		var calls []domainCall
		server := domainServer(t, &calls)
		agent, err := NewAgent(AgentConfig{CustomDomain: server.URL, BaseURL: noRequests(t), ClientID: "c", ClientSecret: "s"})
		if err != nil {
			t.Fatalf("NewAgent: %v", err)
		}
		if _, err := agent.Ask(ctx, "document:read", nil); err != nil {
			t.Fatalf("Ask: %v", err)
		}
		if _, err := agent.MCPToken(ctx, "https://mcp.example.com/mcp"); err != nil {
			t.Fatalf("MCPToken: %v", err)
		}
		if _, err := agent.Approvals.Status(ctx, "tok_abc"); err != nil {
			t.Fatalf("Approvals.Status: %v", err)
		}
		assertPrefixLess(t, calls, "/api/v1/oauth/token", "/api/v1/agents/ask", "/api/v1/oauth/token",
			"/api/v1/agents/me/approvals/tok_abc/status")
	})

	t.Run("the audience of a client assertion is the bare domain", func(t *testing.T) {
		var calls []domainCall
		server := domainServer(t, &calls)
		signer, err := GenerateClientAssertionSigner("EdDSA", "agent-key")
		if err != nil {
			t.Fatal(err)
		}
		// An organization ID next to the custom domain changes nothing.
		agent, err := NewAgent(AgentConfig{CustomDomain: server.URL, OrgID: "acme-corp", ClientID: assertionAgentID, PrivateKey: signer})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := agent.Authenticate(ctx); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		assertPrefixLess(t, calls, "/api/v1/oauth/token")
		_, claims, input, signature := splitAssertion(t, calls[0].Form.Get("client_assertion"))
		if claims["aud"] != server.URL {
			t.Errorf("aud = %v, want the custom domain %q", claims["aud"], server.URL)
		}
		if !verifyAssertion(t, signer, input, signature) {
			t.Error("the assertion does not verify")
		}

		// An explicit Issuer still wins.
		agent, err = NewAgent(AgentConfig{CustomDomain: server.URL, ClientID: assertionAgentID, PrivateKey: signer, Issuer: "https://issuer.example"})
		if err != nil {
			t.Fatal(err)
		}
		assertion, err := agent.ClientAssertion()
		if err != nil {
			t.Fatal(err)
		}
		if _, claims, _, _ := splitAssertion(t, assertion); claims["aud"] != "https://issuer.example" {
			t.Errorf("aud = %v", claims["aud"])
		}
	})

	t.Run("the DPoP proof of a token request covers the address on the custom domain", func(t *testing.T) {
		var calls []domainCall
		server := domainServer(t, &calls)
		signer, err := NewDPoPSigner()
		if err != nil {
			t.Fatal(err)
		}
		agent, err := NewAgent(AgentConfig{CustomDomain: server.URL, ClientID: "c", ClientSecret: "s", DPoP: signer})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := agent.Authenticate(ctx); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		assertPrefixLess(t, calls, "/api/v1/oauth/token")
		_, claims, _ := decodeProof(t, calls[0].Header.Get(DPoPHeader))
		if claims["htm"] != "POST" || claims["htu"] != server.URL+"/api/v1/oauth/token" {
			t.Errorf("proof htm/htu = %v/%v", claims["htm"], claims["htu"])
		}
	})

	t.Run("JITContext and DelegationChain follow the agent", func(t *testing.T) {
		var calls []domainCall
		server := domainServer(t, &calls)
		agent, err := NewAgent(AgentConfig{CustomDomain: server.URL, ClientID: "c", ClientSecret: "s"})
		if err != nil {
			t.Fatal(err)
		}
		jit, err := NewJITContext(agent)
		if err != nil {
			t.Fatalf("NewJITContext: %v", err)
		}
		if _, err := jit.CreateTask(ctx, CreateTaskParams{Name: "Analyse the report"}); err != nil {
			t.Fatalf("CreateTask: %v", err)
		}

		chain := NewDelegationChain(agent, "https://agent.example.com/callback")
		consentURL, err := chain.ConsentURL("session-1", nil, "")
		if err != nil || !strings.HasPrefix(consentURL, server.URL+"/api/v1/oauth/authorize?") {
			t.Errorf("ConsentURL = %q, %v", consentURL, err)
		}
		if err := chain.HandleConsentCallback(ctx, "session-1", "auth-code"); err != nil {
			t.Fatalf("HandleConsentCallback: %v", err)
		}
		if _, err := chain.Exchange(ctx, "session-1"); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		assertPrefixLess(t, calls, "/api/v1/oauth/token", "/api/v1/jit/task", "/api/v1/oauth/token", "/api/v1/oauth/token")
	})

	t.Run("a token source of the application's own", func(t *testing.T) {
		var calls []domainCall
		server := domainServer(t, &calls)

		// With the CustomDomain method the paths have no prefix.
		jit, err := NewJITContext(fixedSource{baseURL: noRequests(t), customDomain: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jit.CreateTask(ctx, CreateTaskParams{Name: "task"}); err != nil {
			t.Fatal(err)
		}
		assertPrefixLess(t, calls, "/api/v1/jit/task")

		// Without it the source is on the platform host, as before.
		calls = nil
		jit, err = NewJITContext(plainSource{baseURL: server.URL, orgID: "acme-corp"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jit.CreateTask(ctx, CreateTaskParams{Name: "task"}); err != nil {
			t.Fatal(err)
		}
		if len(calls) != 1 || calls[0].Path != "/orgs/acme-corp/api/v1/jit/task" {
			t.Errorf("calls = %v", calls)
		}

		// A delegation chain whose source has an invalid custom domain
		// sends nothing.
		calls = nil
		chain := NewDelegationChain(fixedSource{baseURL: server.URL, orgID: "acme-corp", customDomain: "https://auth.acme.com/path"}, "https://agent.example.com/cb")
		if err := chain.HandleConsentCallback(ctx, "session-1", "code"); !errors.Is(err, ErrConfig) {
			t.Errorf("expected a configuration error, got %v", err)
		}
		if len(calls) != 0 {
			t.Errorf("a chain with an invalid custom domain sent %v", calls)
		}
	})
}

// ── Web sign-in ───────────────────────────────────────────────────────

func TestCustomDomainWebAuth(t *testing.T) {
	cleanDomainEnv(t)
	state := &webAuthServer{t: t}
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		state.handler()(w, r)
	}))
	t.Cleanup(server.Close)

	// No Organization: a custom domain needs none.
	auth, err := NewWebAuth(WebConfig{
		CustomDomain: server.URL, BaseURL: noRequests(t),
		ClientID: "web-client", ClientSecret: "web-secret",
		SessionSecret: testSessionSecret, CookieSecure: Bool(false),
	})
	if err != nil {
		t.Fatalf("NewWebAuth: %v", err)
	}

	loginRecorder := httptest.NewRecorder()
	auth.Router().ServeHTTP(loginRecorder, httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/login", nil))
	location := loginRecorder.Header().Get("Location")
	if !strings.HasPrefix(location, server.URL+"/api/v1/oauth/authorize?") {
		t.Fatalf("the sign-in redirect goes to %q", location)
	}

	// The callback exchanges the code and reads UserInfo on the domain.
	cookies := completeLogin(t, auth)
	want := []string{"/api/v1/oauth/token", "/api/v1/oauth/userinfo"}
	if strings.Join(paths, " ") != strings.Join(want, " ") {
		t.Errorf("paths = %v, want %v", paths, want)
	}

	// The client for the signed-in user follows the same rule.
	request := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	userClient, err := auth.ClientForRequest(request)
	if err != nil {
		t.Fatalf("ClientForRequest: %v", err)
	}
	if userClient.CustomDomain() != server.URL {
		t.Errorf("CustomDomain() = %q", userClient.CustomDomain())
	}

	// Sign-out revokes the refresh token on the domain.
	paths = nil
	logoutRequest := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/logout", nil)
	for _, cookie := range cookies {
		logoutRequest.AddCookie(cookie)
	}
	auth.Router().ServeHTTP(httptest.NewRecorder(), logoutRequest)
	if len(paths) != 1 || paths[0] != "/api/v1/oauth/revoke" {
		t.Errorf("sign-out paths = %v", paths)
	}
}

// ── AAuth ─────────────────────────────────────────────────────────────

// AAuth is the one exception to the issuer rule. Its routes are addressed
// on the custom domain like every other route, but LumoAuth names the
// AAuth issuer with the platform address on every host. The SDK reads it
// from the issuer metadata document and never derives it from the domain.

// routedTransport is a mocked transport: it answers the URLs that it knows
// with a JSON body and everything else with 404, and it records each URL.
type routedTransport struct {
	mu        sync.Mutex
	responses map[string]any
	requested []string
}

func (r *routedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.requested = append(r.requested, req.URL.String())
	body, known := r.responses[req.URL.String()]
	r.mu.Unlock()

	recorder := httptest.NewRecorder()
	if known {
		writeJSON(recorder, 200, body)
	} else {
		recorder.WriteHeader(http.StatusNotFound)
	}
	return recorder.Result(), nil
}

func (r *routedTransport) count(target string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, requested := range r.requested {
		if requested == target {
			n++
		}
	}
	return n
}

// resetAAuthIssuerCache empties the process-wide cache, so a test sees its
// own fetches whatever ran before it.
func resetAAuthIssuerCache() {
	sharedAAuthIssuers.mu.Lock()
	sharedAAuthIssuers.entries = map[string]aauthIssuerEntry{}
	sharedAAuthIssuers.mu.Unlock()
}

// aauthTokenMinter signs AAuth auth tokens for one resource.
type aauthTokenMinter struct {
	jwks *JWKS
	mint func(issuer string) string
}

func newAAuthTokenMinter(t *testing.T, resource string) *aauthTokenMinter {
	t.Helper()
	issuerKeypair, err := GenerateKeypair("issuer-key")
	if err != nil {
		t.Fatal(err)
	}
	issuerSigner, err := LoadPrivateKey(issuerKeypair.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	agentKeypair, err := GenerateKeypair("agent-key")
	if err != nil {
		t.Fatal(err)
	}
	return &aauthTokenMinter{jwks: &issuerKeypair.JWKS, mint: func(issuer string) string {
		return signTestJWT(t, issuerSigner.(ed25519.PrivateKey), "auth+jwt", "issuer-key", map[string]any{
			"iss": issuer, "aud": resource, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"jti": "token-123", "agent": "https://my-agent.example.com", "scope": "read",
			"cnf": map[string]any{"jwk": agentKeypair.JWK},
		})
	}}
}

func TestContractCustomDomainAAuth(t *testing.T) {
	vector := loadCustomDomainVector(t)
	cleanDomainEnv(t)
	resetAAuthIssuerCache()
	ctx := context.Background()
	want := vector.AAuth
	if want.IssuerMetadataURL.CustomDomain == "" || want.ExpectedIssuer.CustomDomain == "" || want.Accepted == "" ||
		want.Refused == "" || len(want.Document) == 0 {
		t.Fatal("the vector has no complete aauth section")
	}
	domain := vector.CustomDomain.CustomDomain
	const resource = "https://api.example.com"
	minter := newAAuthTokenMinter(t, resource)
	keypair, err := GenerateKeypair("agent-key")
	if err != nil {
		t.Fatal(err)
	}

	// The custom domain, as a mocked transport: the metadata document of
	// the vector, and the key set at the route aauth.jwks.
	customJWKS := ""
	for _, route := range vector.Routes {
		if route.Route == RouteAAuthJWKS {
			customJWKS = route.CustomDomainURL
		}
	}
	if customJWKS == "" {
		t.Fatal("the vector has no aauth.jwks route")
	}
	transport := &routedTransport{responses: map[string]any{
		want.IssuerMetadataURL.CustomDomain: want.Document,
		customJWKS:                          minter.jwks,
	}}
	mocked := &http.Client{Transport: transport}

	base := AAuthConfig{AgentIdentifier: "https://my-agent.example.com", PrivateKeyPEM: keypair.PrivateKeyPEM, HTTPClient: mocked}
	onPlatform, onDomain := base, base
	onPlatform.BaseURL, onPlatform.OrgID = vector.Platform.BaseURL, vector.Platform.OrgID
	onDomain.CustomDomain = domain
	platform, err := NewAAuthClient(onPlatform)
	if err != nil {
		t.Fatal(err)
	}
	custom, err := NewAAuthClient(onDomain)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the metadata document is addressed like every other route", func(t *testing.T) {
		if got, err := platform.routeURL(RouteAAuthIssuerMetadata); err != nil || got != want.IssuerMetadataURL.Platform {
			t.Errorf("platform = %q, %v; want %q", got, err, want.IssuerMetadataURL.Platform)
		}
		if got, err := custom.routeURL(RouteAAuthIssuerMetadata); err != nil || got != want.IssuerMetadataURL.CustomDomain {
			t.Errorf("custom domain = %q, %v; want %q", got, err, want.IssuerMetadataURL.CustomDomain)
		}
	})

	t.Run("the issuer that the agent addresses keeps the platform form", func(t *testing.T) {
		if got, err := platform.ResolveIssuer(ctx); err != nil || got != want.ExpectedIssuer.Platform || platform.Issuer() != got {
			t.Errorf("platform: ResolveIssuer = %q, %v; Issuer() = %q; want %q", got, err, platform.Issuer(), want.ExpectedIssuer.Platform)
		}
		if transport.count(want.IssuerMetadataURL.Platform) != 0 {
			t.Error("a client on the platform host read the metadata document")
		}

		// Never the domain, and never a default base URL: before the
		// document is read, the client has no issuer.
		if got := custom.Issuer(); got != "" {
			t.Errorf("custom domain: Issuer() = %q before the document was read", got)
		}
		for i := 0; i < 3; i++ {
			got, err := custom.ResolveIssuer(ctx)
			if err != nil || got != want.ExpectedIssuer.CustomDomain {
				t.Fatalf("custom domain: ResolveIssuer = %q, %v; want %q", got, err, want.ExpectedIssuer.CustomDomain)
			}
		}
		if got := custom.Issuer(); got != want.ExpectedIssuer.CustomDomain {
			t.Errorf("custom domain: Issuer() = %q after the document was read", got)
		}
		if got := custom.Issuer(); got == domain || strings.HasPrefix(got, DefaultBaseURL+"/orgs//") {
			t.Errorf("the AAuth issuer was derived: %q", got)
		}
		if n := transport.count(want.IssuerMetadataURL.CustomDomain); n != 1 {
			t.Errorf("the metadata document was read %d times, want 1", n)
		}
	})

	t.Run("a configured issuer is used as it is", func(t *testing.T) {
		configured := onDomain
		configured.Issuer = "https://eu.app.lumoauth.dev/orgs/acme-corp/api/v1"
		configured.HTTPClient = &http.Client{Transport: &routedTransport{}}
		client, err := NewAAuthClient(configured)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := client.ResolveIssuer(ctx); err != nil || got != configured.Issuer || client.Issuer() != configured.Issuer {
			t.Errorf("ResolveIssuer = %q, %v", got, err)
		}
		if requested := configured.HTTPClient.Transport.(*routedTransport).requested; len(requested) != 0 {
			t.Errorf("a configured issuer caused a request: %v", requested)
		}
	})

	t.Run("a document that cannot be read gives no issuer", func(t *testing.T) {
		for name, document := range map[string]any{
			"missing":      nil,
			"no issuer":    map[string]any{"aauth_version": "1.0"},
			"not a URL":    map[string]any{"issuer": "acme-corp"},
			"not a string": map[string]any{"issuer": 7},
		} {
			broken := onDomain
			responses := map[string]any{}
			if document != nil {
				responses[want.IssuerMetadataURL.CustomDomain] = document
			}
			broken.HTTPClient = &http.Client{Transport: &routedTransport{responses: responses}}
			client, err := NewAAuthClient(broken)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := client.ResolveIssuer(ctx); err == nil || got != "" || client.Issuer() != "" {
				t.Errorf("%s: ResolveIssuer = %q, %v; Issuer() = %q", name, got, err, client.Issuer())
			}
		}
	})

	t.Run("token verification", func(t *testing.T) {
		resetAAuthIssuerCache()
		before := transport.count(want.IssuerMetadataURL.CustomDomain)
		opts := VerifyOptions{CustomDomain: domain, Resource: resource, HTTPClient: mocked}

		for i := 0; i < 2; i++ {
			claims, err := VerifyAuthToken(ctx, minter.mint(want.Accepted), opts)
			if err != nil {
				t.Fatalf("a token whose issuer is %q: %v", want.Accepted, err)
			}
			if claims.Issuer != want.Accepted {
				t.Errorf("iss = %q", claims.Issuer)
			}
		}
		if _, err := VerifyAuthToken(ctx, minter.mint(want.Refused), opts); !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "untrusted issuer") {
			t.Errorf("a token whose issuer is %q must be refused, got %v", want.Refused, err)
		}
		// The issuer is read once and kept; the keys come from the domain.
		if n := transport.count(want.IssuerMetadataURL.CustomDomain) - before; n != 1 {
			t.Errorf("the metadata document was read %d times for three verifications, want 1", n)
		}
		if transport.count(customJWKS) == 0 {
			t.Errorf("the key set was not read from %s", customJWKS)
		}
		for _, requested := range transport.requested {
			if !strings.HasPrefix(requested, domain+"/") {
				t.Errorf("a request left the custom domain: %s", requested)
			}
		}
	})
}

func TestCustomDomainAAuthClient(t *testing.T) {
	cleanDomainEnv(t)
	ctx := context.Background()
	keypair, err := GenerateKeypair("agent-key")
	if err != nil {
		t.Fatal(err)
	}
	// The issuer that the organization has on the platform host.
	const platformIssuer = "https://app.lumoauth.test/orgs/acme-corp/api/v1"
	var calls []aauthCall
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		calls = append(calls, aauthCall{Path: r.URL.Path, Host: r.Host, RawBody: raw,
			AgentAuth: r.Header.Get("Agent-Auth"), Headers: r.Header.Clone()})
		switch {
		case strings.HasSuffix(r.URL.Path, "/jwks.json"):
			writeJSON(w, 200, keypair.JWKS)
		case strings.Contains(r.URL.Path, "/.well-known/"):
			writeJSON(w, 200, map[string]any{"issuer": platformIssuer})
		default:
			writeJSON(w, 200, map[string]any{"request_type": "auth", "auth_token": "auth-jwt", "expires_in": 900})
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewAAuthClient(AAuthConfig{
		AgentIdentifier: "https://my-agent.example.com", PrivateKeyPEM: keypair.PrivateKeyPEM,
		CustomDomain: server.URL, BaseURL: noRequests(t), Kid: "agent-key",
	})
	if err != nil {
		t.Fatalf("NewAAuthClient without an organization ID: %v", err)
	}
	if client.BaseURL() != server.URL || client.CustomDomain() != server.URL {
		t.Errorf("BaseURL() = %q, CustomDomain() = %q", client.BaseURL(), client.CustomDomain())
	}

	if _, err := client.RequestAuthToken(ctx, AuthTokenParams{ResourceToken: "resource-jwt", AgentToken: "agent-jwt"}); err != nil {
		t.Fatalf("RequestAuthToken: %v", err)
	}
	if calls[0].Path != "/api/v1/aauth/agent/token" {
		t.Errorf("token path = %q", calls[0].Path)
	}
	// The HTTP message signature covers the address on the custom domain.
	verifySentSignature(t, calls[0], keypair, http.MethodPost)

	if err := client.Revoke(ctx, "auth-jwt", "", "agent-jwt"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if consent, err := client.ConsentURL("req-token"); err != nil || consent != server.URL+"/api/v1/aauth/agent/auth?request_token=req-token" {
		t.Errorf("ConsentURL = %q, %v", consent, err)
	}
	if _, err := client.JWKS(ctx); err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	// The issuer comes from the metadata document, read once.
	if got := client.Issuer(); got != "" {
		t.Errorf("Issuer() = %q before the document was read", got)
	}
	for i := 0; i < 2; i++ {
		if got, err := client.ResolveIssuer(ctx); err != nil || got != platformIssuer {
			t.Fatalf("ResolveIssuer = %q, %v; want %q", got, err, platformIssuer)
		}
	}
	if got := client.Issuer(); got != platformIssuer {
		t.Errorf("Issuer() = %q after the document was read", got)
	}

	want := []string{"/api/v1/aauth/agent/token", "/api/v1/aauth/token/revoke", "/api/v1/aauth/jwks.json", "/api/v1/.well-known/aauth-issuer"}
	got := make([]string, len(calls))
	for i, call := range calls {
		got[i] = call.Path
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("paths = %v\nwant    %v", got, want)
	}

	// On the platform host nothing changed: the issuer is derived there.
	onPlatform, err := NewAAuthClient(AAuthConfig{
		AgentIdentifier: "https://my-agent.example.com", PrivateKeyPEM: keypair.PrivateKeyPEM,
		BaseURL: "https://app.lumoauth.test", OrgID: "acme-corp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := onPlatform.ResolveIssuer(ctx); err != nil || got != platformIssuer || onPlatform.Issuer() != platformIssuer {
		t.Errorf("platform: ResolveIssuer = %q, %v", got, err)
	}
	noOrg, err := NewAAuthClient(AAuthConfig{
		AgentIdentifier: "https://my-agent.example.com", PrivateKeyPEM: keypair.PrivateKeyPEM, BaseURL: "https://app.lumoauth.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noOrg.ResolveIssuer(ctx); !errors.Is(err, ErrConfig) {
		t.Errorf("platform without an organization ID: %v", err)
	}
}

func TestCustomDomainAuthTokenVerification(t *testing.T) {
	resetAAuthIssuerCache()
	ctx := context.Background()
	const resource = "https://api.example.com"
	const platformIssuer = "https://app.lumoauth.test/orgs/acme-corp/api/v1"
	minter := newAAuthTokenMinter(t, resource)

	var paths []string
	metadata := map[string]any{"issuer": platformIssuer}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/aauth/jwks.json":
			writeJSON(w, 200, minter.jwks)
		case "/api/v1/.well-known/aauth-issuer":
			writeJSON(w, 200, metadata)
		default:
			// A custom domain answers 404 for the prefixed paths.
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	opts := VerifyOptions{CustomDomain: strings.ToUpper(server.URL) + "/", Resource: resource}

	// The token names the platform form of the issuer, and it verifies.
	claims, err := VerifyAuthToken(ctx, minter.mint(platformIssuer), opts)
	if err != nil {
		t.Fatalf("a token that names the platform issuer: %v", err)
	}
	if claims.Issuer != platformIssuer {
		t.Errorf("iss = %q", claims.Issuer)
	}
	want := []string{"/api/v1/.well-known/aauth-issuer", "/api/v1/aauth/jwks.json"}
	if strings.Join(paths, " ") != strings.Join(want, " ") {
		t.Errorf("paths = %v, want %v", paths, want)
	}

	// A token that names the bare domain is refused, without a fetch: the
	// issuer is cached and no key is read for an untrusted issuer.
	paths = nil
	if _, err := VerifyAuthToken(ctx, minter.mint(server.URL), opts); !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "untrusted issuer") {
		t.Errorf("a token that names the custom domain: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("an untrusted issuer caused a fetch: %v", paths)
	}

	// An issuer that the caller configured is used as it is, and the
	// metadata document is not read.
	resetAAuthIssuerCache()
	paths = nil
	const configured = "https://eu.app.lumoauth.test/orgs/acme-corp/api/v1"
	explicit := VerifyOptions{CustomDomain: server.URL, Issuer: configured, Resource: resource}
	if _, err := VerifyAuthToken(ctx, minter.mint(configured), explicit); err != nil {
		t.Errorf("a token that names the configured issuer: %v", err)
	}
	if _, err := VerifyAuthToken(ctx, minter.mint(platformIssuer), explicit); err == nil {
		t.Error("a token that names another issuer than the configured one was accepted")
	}
	if strings.Join(paths, " ") != "/api/v1/aauth/jwks.json" {
		t.Errorf("paths = %v, want the key set only", paths)
	}

	// The cache for a custom domain reads the keys on the domain.
	cache, err := NewJWKSCacheForCustomDomain(server.URL, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := cache.Get(ctx)
	if err != nil || len(keys.Keys) != 1 {
		t.Fatalf("cache.Get: %v", err)
	}
	if _, err := VerifyAuthToken(ctx, minter.mint(platformIssuer), VerifyOptions{CustomDomain: server.URL, Resource: resource, JWKS: keys}); err != nil {
		t.Errorf("verification with cached keys: %v", err)
	}
	if _, err := NewJWKSCacheForCustomDomain("  ", 0, nil); !errors.Is(err, ErrConfig) {
		t.Errorf("an empty custom domain: %v", err)
	}

	// A metadata document without an issuer: nothing verifies.
	resetAAuthIssuerCache()
	metadata = map[string]any{"aauth_version": "1.0"}
	for _, issuer := range []string{platformIssuer, server.URL, ""} {
		if _, err := VerifyAuthToken(ctx, minter.mint(issuer), opts); !errors.Is(err, ErrValidation) {
			t.Errorf("a document without an issuer, token issuer %q: %v", issuer, err)
		}
	}

	// Neither an issuer nor a custom domain.
	if _, err := VerifyAuthToken(ctx, minter.mint(platformIssuer), VerifyOptions{Resource: resource}); !errors.Is(err, ErrConfig) {
		t.Errorf("expected a configuration error, got %v", err)
	}
	// On the platform host nothing changed: Issuer is the trusted issuer.
	if _, err := VerifyAuthToken(ctx, minter.mint(platformIssuer), VerifyOptions{Issuer: platformIssuer, Resource: resource, JWKS: minter.jwks}); err != nil {
		t.Errorf("platform verification: %v", err)
	}
}

// ── LumoAuth access tokens ────────────────────────────────────────────

func TestCustomDomainAccessTokenVerification(t *testing.T) {
	ctx := context.Background()
	signer := newTestTokenSigner(t)

	var paths []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/.well-known/openid-configuration":
			writeJSON(w, 200, map[string]any{"issuer": server.URL, "jwks_uri": server.URL + "/api/v1/.well-known/jwks.json"})
		case "/api/v1/.well-known/jwks.json":
			writeJSON(w, 200, signer.jwks)
		default:
			// A custom domain answers 404 for the prefixed paths.
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	platformIssuer := server.URL + "/orgs/acme-corp/api/v1"
	opts := AccessTokenVerifyOptions{CustomDomain: server.URL, Resource: testResource}

	claims, err := VerifyAccessToken(ctx, signer.mint(t, map[string]any{"iss": server.URL}, nil), opts)
	if err != nil {
		t.Fatalf("a token that names the custom domain: %v", err)
	}
	if claims.Issuer != server.URL {
		t.Errorf("iss = %q", claims.Issuer)
	}
	want := []string{"/api/v1/.well-known/openid-configuration", "/api/v1/.well-known/jwks.json"}
	if strings.Join(paths, " ") != strings.Join(want, " ") {
		t.Errorf("paths = %v, want %v", paths, want)
	}

	// The platform form of the issuer is refused, also when the caller
	// names it in Issuer: the custom domain wins.
	platformToken := signer.mint(t, map[string]any{"iss": platformIssuer}, nil)
	for _, o := range []AccessTokenVerifyOptions{opts, {CustomDomain: server.URL, Issuer: platformIssuer, Resource: testResource}} {
		_, err := VerifyAccessToken(ctx, platformToken, o)
		if RejectionReason(err) != TokenRejectedIssuer {
			t.Errorf("a token that names the platform issuer: %v (reason %q)", err, RejectionReason(err))
		}
	}
	// And a verifier for the platform issuer refuses the domain's token.
	_, err = VerifyAccessToken(ctx, signer.mint(t, map[string]any{"iss": server.URL}, nil),
		AccessTokenVerifyOptions{Issuer: platformIssuer, Resource: testResource, JWKS: signer.jwks})
	if RejectionReason(err) != TokenRejectedIssuer {
		t.Errorf("a platform verifier accepted the custom domain's token: %v", err)
	}

	t.Run("the middleware", func(t *testing.T) {
		protect := RequireAccessToken(AccessTokenVerifyOptions{CustomDomain: server.URL, Resource: testResource})
		send := func(token string) int {
			request := httptest.NewRequest("GET", "/mcp", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			recorder := httptest.NewRecorder()
			protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if claims, ok := AccessTokenFromContext(r.Context()); !ok || claims.Issuer != server.URL {
					t.Errorf("claims = %+v", claims)
				}
			})).ServeHTTP(recorder, request)
			return recorder.Code
		}
		if code := send(signer.mint(t, map[string]any{"iss": server.URL}, nil)); code != 200 {
			t.Errorf("status = %d for a token of the custom domain", code)
		}
		if code := send(platformToken); code != 401 {
			t.Errorf("status = %d for a token of the platform issuer", code)
		}
	})

	t.Run("the key cache for a custom domain", func(t *testing.T) {
		paths = nil
		cache, err := NewAccessTokenKeyCacheForCustomDomain("  "+server.URL+"/  ", time.Minute, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cache.Get(ctx); err != nil {
			t.Fatalf("cache.Get: %v", err)
		}
		if paths[0] != "/api/v1/.well-known/openid-configuration" {
			t.Errorf("discovery path = %s", paths[0])
		}
		if _, err := NewAccessTokenKeyCacheForCustomDomain("", 0, nil); !errors.Is(err, ErrConfig) {
			t.Errorf("an empty custom domain: %v", err)
		}
	})

	t.Run("neither an issuer nor a custom domain", func(t *testing.T) {
		if _, err := VerifyAccessToken(ctx, platformToken, AccessTokenVerifyOptions{Resource: testResource}); !errors.Is(err, ErrConfig) {
			t.Errorf("expected a configuration error, got %v", err)
		}
	})
}

// TestCustomDomainPathRule holds the rule itself, without the vector.
func TestCustomDomainPathRule(t *testing.T) {
	cases := map[string]string{
		"/orgs/{orgId}/api/v1/oauth/token":             "/api/v1/oauth/token",
		"/orgs/{orgId}/api/v1/jit/task/{taskId}/token": "/api/v1/jit/task/{taskId}/token",
		"/api/v1/authz/check":                          "/api/v1/authz/check",
		"/.well-known/aauth-issuer":                    "/.well-known/aauth-issuer",
		// Only the leading segment, and only a whole segment.
		"/orgs/{orgId}":                  "/orgs/{orgId}",
		"/orgs/{orgId}s/api/v1/x":        "/orgs/{orgId}s/api/v1/x",
		"/api/v1/orgs/{orgId}/api/v1/x":  "/api/v1/orgs/{orgId}/api/v1/x",
		"/orgs/{organization}/api/v1/x":  "/orgs/{organization}/api/v1/x",
		"/orgs/{orgId}/orgs/{orgId}/x/y": "/orgs/{orgId}/x/y",
	}
	for template, want := range cases {
		if got := pathOnCustomDomain(template); got != want {
			t.Errorf("pathOnCustomDomain(%q) = %q, want %q", template, got, want)
		}
	}

	// Every route of the registry either starts with the segment or has no
	// organization in its path at all.
	for name, route := range Routes {
		onDomain := pathOnCustomDomain(route.Path)
		if strings.Contains(onDomain, "{orgId}") || strings.Contains(onDomain, "/orgs/") {
			t.Errorf("the route %s still names an organization on a custom domain: %s", name, onDomain)
		}
	}

	// The option's rules, for the values that the vector does not list.
	valid := map[string]string{
		"AUTH.Acme.com:8443/":   "https://auth.acme.com:8443",
		"http://[::1]:8000":     "http://[::1]:8000",
		"http://LOCALHOST":      "http://localhost",
		"https://xn--bcher-kva": "https://xn--bcher-kva",
	}
	for input, want := range valid {
		if got, err := normalizeCustomDomain(input); err != nil || got != want {
			t.Errorf("normalizeCustomDomain(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{
		"http://localhost.evil.example", "http://127.0.0.2", "auth.acme.com/api/v1", "auth.acme.com//",
		"https://auth.acme.com/?", "https://:8443", "//auth.acme.com", "https://auth.acme.com:port",
		"mailto:admin@acme.com", "user@auth.acme.com", "https://auth.acme.com\\path", "wss://auth.acme.com",
	} {
		if got, err := normalizeCustomDomain(input); !errors.Is(err, ErrConfig) {
			t.Errorf("normalizeCustomDomain(%q) = %q, %v; want a configuration error", input, got, err)
		}
	}
}

// TestCustomDomainServerAnswer checks the test server's one answer: it must
// decode as a verified Personal Agent Protocol result, which is the
// strictest shape among the calls that the tests above make.
func TestCustomDomainServerAnswer(t *testing.T) {
	var calls []domainCall
	server := domainServer(t, &calls)
	resp, err := http.Get(server.URL + "/anything")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var verification PoppyVerification
	if err := json.NewDecoder(resp.Body).Decode(&verification); err != nil || !verification.Active {
		t.Errorf("the universal answer is not a verified result: %v", err)
	}
}
