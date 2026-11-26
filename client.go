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
//
// An API key reaches only the admin API, client registration and the
// permission checks. ABAC, agent and JIT calls need a user access token
// (WithAccessToken or WithTokenProvider) or an agent credential; ABAC
// needs the abac:read scope.
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
	// Poppy covers the Personal Agent Protocol for your own API: it
	// verifies requests from personal agents, and looks up and ends their
	// Sessions. It needs WithClientCredentials.
	Poppy *PoppyResource

	baseURL      string
	customDomain string
	orgID        string
	apiKey       string
	http         *httpClient
}

// Option configures a Client. Options are applied in order.
type Option func(*clientConfig)

type clientConfig struct {
	baseURL string
	// customDomain is the raw option value in New, and the normalized
	// origin once a constructor has resolved it (see customDomainFrom).
	customDomain string
	// configErr is a configuration error that the constructor could not
	// return. Every request and every address of the client returns it.
	configErr          error
	orgID              string
	apiKey             string
	tokenProvider      TokenProvider
	timeout            time.Duration
	httpClient         *http.Client
	skipCertValidation bool
	headers            map[string]string
	userAgent          string
	dpop               *DPoPSigner
	clientID           string
	clientSecret       string
}

// WithBaseURL sets the LumoAuth instance URL. Defaults to $LUMOAUTH_URL,
// then DefaultBaseURL.
func WithBaseURL(baseURL string) Option {
	return func(c *clientConfig) { c.baseURL = baseURL }
}

// WithOrgID sets the organization slug. Required for org-scoped endpoints
// (ABAC, agents, JIT, approvals, OAuth) on the platform host. Defaults to
// $LUMOAUTH_ORG_ID. A client with a custom domain does not need it.
func WithOrgID(orgID string) Option {
	return func(c *clientConfig) { c.orgID = orgID }
}

// WithCustomDomain addresses the organization on its own domain, for
// example "auth.acme.com" or "https://auth.acme.com". Defaults to
// $LUMOAUTH_CUSTOM_DOMAIN.
//
// With a custom domain the client sends every request to that domain, and
// no path carries the /orgs/{orgId} segment. The organization ID is not
// needed, and the issuer is the bare domain. A custom domain wins over
// WithBaseURL and $LUMOAUTH_URL: the base URL is then not used at all.
//
// The value is a host name or an https:// origin. http:// is accepted only
// for localhost, 127.0.0.1 and [::1]. New returns a *ConfigError for a
// value with a path, a query, a fragment or credentials. An empty value
// means "not set".
func WithCustomDomain(domain string) Option {
	return func(c *clientConfig) { c.customDomain = domain }
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

// WithClientCredentials sets the client ID and the client secret of a
// confidential application of the organization. Only client.Poppy uses
// them: its calls authenticate with HTTP Basic, and they never send the
// client's bearer token or API key. The application's allowed scopes must
// include poppy:verify.
//
// A client with these credentials and no other credential can call
// client.Poppy only.
func WithClientCredentials(clientID, clientSecret string) Option {
	return func(c *clientConfig) {
		c.clientID = clientID
		c.clientSecret = clientSecret
	}
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

// WithDPoP binds the client's token requests to a DPoP key (RFC 9449).
// Every token the client obtains through client.Auth — client credentials,
// token exchange, MCP tokens — is then sender-constrained (token_type
// "DPoP"), and the client presents bound tokens with the DPoP scheme and a
// fresh proof. See DPoPSigner.
func WithDPoP(signer *DPoPSigner) Option {
	return func(c *clientConfig) { c.dpop = signer }
}

// WithUserAgent overrides the User-Agent sent with every request.
func WithUserAgent(userAgent string) Option {
	return func(c *clientConfig) { c.userAgent = userAgent }
}

// New builds a Client. It returns a *ConfigError when no credential is
// configured: an API key, a token provider, or the client credentials of
// WithClientCredentials.
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
	customDomain, err := customDomainFrom(cfg.customDomain)
	if err != nil {
		return nil, err
	}
	cfg.customDomain = customDomain
	if (cfg.clientID == "") != (cfg.clientSecret == "") {
		return nil, NewConfigError(
			"WithClientCredentials needs both values: the client ID and the client secret")
	}
	if cfg.apiKey == "" && cfg.tokenProvider == nil && cfg.clientID == "" {
		return nil, NewConfigError(
			"a credential is required: pass WithAPIKey (or set LUMOAUTH_API_KEY), " +
				"WithAccessToken, WithTokenProvider, or WithClientCredentials")
	}
	return newClient(cfg), nil
}

// newClient builds a Client from an already-validated config. Internal
// callers (Agent, JITContext, DelegationChain) use it to skip the
// credential check, since they authenticate through a token provider they
// install themselves.
func newClient(cfg *clientConfig) *Client {
	baseURL := cfg.baseURL
	if cfg.customDomain != "" {
		// The custom domain wins: the base URL is not used for any request.
		baseURL = cfg.customDomain
	}
	transport := newHTTPClient(baseURL)
	transport.customDomain = cfg.customDomain
	transport.configErr = cfg.configErr
	transport.orgID = cfg.orgID
	transport.apiKey = cfg.apiKey
	transport.tokenProvider = cfg.tokenProvider
	transport.headers = cfg.headers
	transport.userAgent = cfg.userAgent
	transport.dpop = cfg.dpop

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
		baseURL:      strings.TrimRight(baseURL, "/"),
		customDomain: cfg.customDomain,
		orgID:        cfg.orgID,
		apiKey:       cfg.apiKey,
		http:         transport,
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
	client.Poppy = &PoppyResource{http: transport, clientID: cfg.clientID, clientSecret: cfg.clientSecret}
	return client
}

// BaseURL returns the address that the client sends its requests to,
// without a trailing slash: the custom domain when one is set, the
// LumoAuth instance URL otherwise.
func (c *Client) BaseURL() string { return c.baseURL }

// OrgID returns the configured organization slug ("" when unset).
func (c *Client) OrgID() string { return c.orgID }

// CustomDomain returns the organization's custom domain as an origin, for
// example "https://auth.acme.com", or "" when none is set.
func (c *Client) CustomDomain() string { return c.customDomain }

// Issuer returns the issuer identifier of the organization: the `iss` of
// its tokens and the audience of a client assertion. On a custom domain it
// is the bare domain. On the platform host it is
// {baseURL}/orgs/{orgID}/api/v1, and a client without an organization ID
// gets a *ConfigError.
func (c *Client) Issuer() (string, error) { return c.http.issuer() }

// DPoP returns the signer passed with WithDPoP, or nil.
func (c *Client) DPoP() *DPoPSigner { return c.http.dpop }

// ── Escape hatches ────────────────────────────────────────────────────

// Do sends an authenticated request to any LumoAuth endpoint and decodes
// the JSON response into out (pass nil to discard it). The path is joined
// to the client's base URL; an absolute URL is used as-is. Non-2xx
// responses become the typed errors in errors.go.
//
// On a custom domain, give the path without the /orgs/{orgId} segment, or
// build it with OrgPath. A path that starts with the segment of the
// client's own organization still works when the client has that
// organization ID: the segment is removed. A path of another organization
// is sent as it is.
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
//
// On a custom domain the result is /api/v1/admin/users, and no organization
// ID is needed.
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
//
// On a custom domain BaseURL is the domain. The generated client puts
// /orgs/{orgId} in every path, and a custom domain answers 404 for those.
// When the client has an organization ID (WithOrgID), HTTPClient is a copy
// whose transport removes the segment of that organization from requests
// to the custom domain, so pass the same ID to the generated client's
// calls. Without an organization ID the generated client cannot reach a
// custom domain.
func (c *Client) APIConfig(ctx context.Context) (*APIConfig, error) {
	headers := map[string]string{}
	token, err := c.http.bearerToken(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case token != "" && c.http.dpop != nil && DPoPBound(token):
		return nil, NewConfigError(
			"the current token is DPoP-bound, and the generated API client cannot sign " +
				"DPoP proofs — use Client.Do, or configure the generated client with a " +
				"transport that calls DPoPSigner.AuthorizeRequest on each request")
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
		HTTPClient:    c.http.generatedClientHTTP(),
	}, nil
}
