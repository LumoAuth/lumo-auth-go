package lumoauth

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultBaseURL is the LumoAuth cloud instance, used when neither
// WithBaseURL nor LUMOAUTH_URL supplies one.
const DefaultBaseURL = "https://app.lumoauth.dev"

// Environment variables read when the corresponding option is not passed.
const (
	EnvBaseURL = "LUMOAUTH_URL"
	EnvOrgID   = "LUMOAUTH_ORG_ID"
	EnvAPIKey  = "LUMOAUTH_API_KEY"
)

// Client is the general-purpose LumoAuth API client.
//
// Curated resource namespaces cover the common surface — the ones an
// application actually reaches for. Everything else (admin CRUD, SCIM,
// audit logs) is available through the Do escape hatch or the generated
// OpenAPI client, which APIConfig configures for you.
//
//	client, err := lumoauth.New(
//	    lumoauth.WithAPIKey(os.Getenv("LUMOAUTH_API_KEY")),
//	    lumoauth.WithOrgID("acme-corp"),
//	)
//	if err != nil {
//	    return err
//	}
//
//	ok, err := client.Permissions.Check(ctx, "document.edit", nil)
//	decision, err := client.Abac.Check(ctx, lumoauth.AbacCheckParams{
//	    ResourceType: "document", Action: "read", ResourceID: "doc-123",
//	})
//
// A Client is safe for concurrent use.
type Client struct {
	// Auth covers the OAuth 2.1 flows: authorization URLs, code exchange,
	// refresh, client credentials, token exchange, revocation, UserInfo.
	Auth *AuthResource
	// Permissions covers RBAC checks for the authenticated principal.
	Permissions *PermissionsResource
	// Zanzibar covers relationship-based (ReBAC) checks.
	Zanzibar *ZanzibarResource
	// Abac covers attribute-based policy evaluation and attribute management.
	Abac *AbacResource
	// Agents covers agent identity: ask, self-inspection, registration.
	Agents *AgentsResource
	// Delegation covers RFC 8693 token exchange (Chain of Agency).
	Delegation *DelegationResource
	// Jit covers Just-in-Time permissions: ephemeral tasks and scoped tokens.
	Jit *JitResource
	// Approvals covers push-approval-for-agent-actions.
	Approvals *ApprovalsResource
	// Mcp covers audience-scoped tokens for secured MCP servers.
	Mcp *McpResource

	baseURL string
	orgID   string
	apiKey  string
	http    *httpClient
}

// Option configures a Client. Options are applied in order.
type Option func(*clientConfig)

type clientConfig struct {
	baseURL            string
	orgID              string
	apiKey             string
	tokenProvider      TokenProvider
	timeout            time.Duration
	httpClient         *http.Client
	skipCertValidation bool
	headers            map[string]string
	userAgent          string
}

// WithBaseURL sets the LumoAuth instance URL. Defaults to $LUMOAUTH_URL,
// then DefaultBaseURL.
func WithBaseURL(baseURL string) Option {
	return func(c *clientConfig) { c.baseURL = baseURL }
}

// WithOrgID sets the organization slug. Required for org-scoped endpoints
// (ABAC, agents, JIT, approvals, OAuth). Defaults to $LUMOAUTH_ORG_ID.
func WithOrgID(orgID string) Option {
	return func(c *clientConfig) { c.orgID = orgID }
}

// WithAPIKey authenticates with a tenant API key, sent as X-API-Key.
// Defaults to $LUMOAUTH_API_KEY.
func WithAPIKey(apiKey string) Option {
	return func(c *clientConfig) { c.apiKey = apiKey }
}

// WithAccessToken authenticates with a fixed bearer token. For tokens that
// expire, prefer WithTokenProvider so the SDK can pick up refreshes.
func WithAccessToken(token string) Option {
	return WithTokenProvider(func(context.Context) (string, error) { return token, nil })
}

// WithTokenProvider authenticates with a bearer token resolved per request,
// which lets the caller refresh transparently. A provider that returns a
// token takes precedence over an API key.
func WithTokenProvider(provider TokenProvider) Option {
	return func(c *clientConfig) { c.tokenProvider = provider }
}

// WithTimeout sets the per-request timeout. Default: 30s.
func WithTimeout(timeout time.Duration) Option {
	return func(c *clientConfig) { c.timeout = timeout }
}

// WithHTTPClient supplies the *http.Client used for every request — the
// hook for custom transports, proxies, and instrumentation.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *clientConfig) { c.httpClient = httpClient }
}

// WithSkipCertValidation disables TLS certificate verification. Local
// development against a self-signed instance only.
func WithSkipCertValidation() Option {
	return func(c *clientConfig) { c.skipCertValidation = true }
}

// WithHeader adds a header to every request.
func WithHeader(name, value string) Option {
	return func(c *clientConfig) {
		if c.headers == nil {
			c.headers = map[string]string{}
		}
		c.headers[name] = value
	}
}

// WithUserAgent overrides the User-Agent sent with every request.
func WithUserAgent(userAgent string) Option {
	return func(c *clientConfig) { c.userAgent = userAgent }
}

// New builds a Client. It returns a *ConfigError when no credential is
// configured — either an API key or a token provider is required.
func New(opts ...Option) (*Client, error) {
	cfg := &clientConfig{
		baseURL:   os.Getenv(EnvBaseURL),
		orgID:     os.Getenv(EnvOrgID),
		apiKey:    os.Getenv(EnvAPIKey),
		timeout:   defaultTimeout,
		userAgent: userAgent(),
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.baseURL == "" {
		cfg.baseURL = DefaultBaseURL
	}
	if cfg.apiKey == "" && cfg.tokenProvider == nil {
		return nil, NewConfigError(
			"a credential is required: pass WithAPIKey (or set LUMOAUTH_API_KEY), " +
				"WithAccessToken, or WithTokenProvider")
	}
	return newClient(cfg), nil
}

// newClient builds a Client from an already-validated config. Internal
// callers (Agent, JITContext, DelegationChain) use it to skip the
// credential check, since they authenticate through a token provider they
// install themselves.
func newClient(cfg *clientConfig) *Client {
	transport := newHTTPClient(cfg.baseURL)
	transport.orgID = cfg.orgID
	transport.apiKey = cfg.apiKey
	transport.tokenProvider = cfg.tokenProvider
	transport.headers = cfg.headers
	transport.userAgent = cfg.userAgent

	if cfg.httpClient != nil {
		transport.doer = cfg.httpClient
	}
	if cfg.timeout > 0 {
		transport.timeout = cfg.timeout
		if cfg.httpClient == nil {
			transport.doer.Timeout = cfg.timeout
		}
	}
	if cfg.skipCertValidation {
		transport.insecureTLS()
	}

	client := &Client{
		baseURL: strings.TrimRight(cfg.baseURL, "/"),
		orgID:   cfg.orgID,
		apiKey:  cfg.apiKey,
		http:    transport,
	}
	client.Auth = &AuthResource{http: transport}
	client.Permissions = &PermissionsResource{http: transport}
	client.Zanzibar = &ZanzibarResource{http: transport}
	client.Abac = &AbacResource{http: transport}
	client.Agents = &AgentsResource{http: transport}
	client.Delegation = &DelegationResource{http: transport, auth: client.Auth}
	client.Jit = &JitResource{http: transport}
	client.Approvals = &ApprovalsResource{http: transport}
	client.Mcp = &McpResource{http: transport, auth: client.Auth}
	return client
}

// BaseURL returns the configured LumoAuth instance URL, without a trailing
// slash.
func (c *Client) BaseURL() string { return c.baseURL }

// OrgID returns the configured organization slug ("" when unset).
func (c *Client) OrgID() string { return c.orgID }

// ── Escape hatches ────────────────────────────────────────────────────

// Do sends an authenticated request to any LumoAuth endpoint and decodes
// the JSON response into out (pass nil to discard it). The path is joined
// to the client's base URL; an absolute URL is used as-is. Non-2xx
// responses become the typed errors in errors.go.
//
// Reach for this when an endpoint has no curated namespace yet:
//
//	var page struct {
//	    Data []map[string]any `json:"data"`
//	}
//	err := client.Do(ctx, "GET", "/orgs/acme-corp/api/v1/admin/users", nil, &page)
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	return c.http.do(ctx, method, path, &request{JSON: body}, out)
}

// DoRaw is Do without response handling: the caller owns the
// *http.Response and must close its body. Transport failures are still
// wrapped as *NetworkError, but HTTP statuses are left untouched.
func (c *Client) DoRaw(ctx context.Context, method, path string, body any) (*http.Response, error) {
	return c.http.doRaw(ctx, method, path, &request{JSON: body})
}

// OrgPath prefixes a path with this client's org-scoped API base, so
// callers building requests by hand do not hardcode the layout:
//
//	path, err := client.OrgPath("/admin/users") // /orgs/acme-corp/api/v1/admin/users
func (c *Client) OrgPath(path string) (string, error) { return c.http.orgPath(path) }

// APIConfig carries everything needed to point the generated OpenAPI
// client (github.com/lumoauth/api-clients/go) at this instance.
type APIConfig struct {
	// BaseURL is the server URL, without a trailing slash.
	BaseURL string
	// DefaultHeader holds exactly one credential header — X-API-Key or
	// Authorization — never both.
	DefaultHeader map[string]string
	// HTTPClient is this client's underlying *http.Client.
	HTTPClient *http.Client
}

// APIConfig returns the settings for the generated OpenAPI client, which
// covers the full REST surface (admin endpoints, SCIM, audit logs).
//
// Unlike the JS and Python SDKs, Go cannot import the generated client
// lazily — a hard dependency would force it on every consumer — so this
// SDK hands you the configuration instead of the client:
//
//	import lumoauthclient "github.com/lumoauth/api-clients/go"
//
//	apiCfg, err := client.APIConfig(ctx)
//	if err != nil {
//	    return err
//	}
//	cfg := lumoauthclient.NewConfiguration()
//	cfg.Servers = lumoauthclient.ServerConfigurations{{URL: apiCfg.BaseURL}}
//	cfg.DefaultHeader = apiCfg.DefaultHeader
//	cfg.HTTPClient = apiCfg.HTTPClient
//	api := lumoauthclient.NewAPIClient(cfg)
//
// The context resolves the current bearer token, so call this once per
// token lifetime (or per request when using short-lived agent tokens).
func (c *Client) APIConfig(ctx context.Context) (*APIConfig, error) {
	headers := map[string]string{}
	token, err := c.http.bearerToken(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case token != "":
		headers["Authorization"] = "Bearer " + token
	case c.apiKey != "":
		headers["X-API-Key"] = c.apiKey
	default:
		return nil, NewConfigError(
			"no credential available for the generated API client — configure " +
				"WithAPIKey or WithTokenProvider")
	}
	return &APIConfig{
		BaseURL:       c.baseURL,
		DefaultHeader: headers,
		HTTPClient:    c.http.doer,
	}, nil
}
