package lumoauth

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Environment variables read by NewAgent when the corresponding field is
// left empty.
const (
	EnvAgentClientID     = "AGENT_CLIENT_ID"
	EnvAgentClientSecret = "AGENT_CLIENT_SECRET"
)

// tokenRefreshBuffer is subtracted from expires_in so the agent refreshes
// before the token actually expires.
const tokenRefreshBuffer = 60 * time.Second

// AgentConfig configures an Agent. Every field falls back to an
// environment variable when left empty.
type AgentConfig struct {
	// BaseURL is the LumoAuth instance. Defaults to $LUMOAUTH_URL, then
	// DefaultBaseURL.
	BaseURL string
	// OrgID is the organization slug. Defaults to $LUMOAUTH_ORG_ID.
	OrgID string
	// ClientID is the agent's OAuth client. Defaults to $AGENT_CLIENT_ID.
	ClientID string
	// ClientSecret is the agent's OAuth secret. Defaults to
	// $AGENT_CLIENT_SECRET.
	ClientSecret string
	// Scopes are requested at authentication. Leave empty to receive the
	// agent's registered defaults.
	Scopes []string
	// RedirectURI is the OAuth callback for the delegation consent flow.
	RedirectURI string
	// Timeout is the per-request timeout. Default: 30s.
	Timeout time.Duration
	// HTTPClient overrides the *http.Client used for every request.
	HTTPClient *http.Client
	// SkipCertValidation disables TLS verification. Local development only.
	SkipCertValidation bool
	// PrivateKey is for an agent registered with the "Private key JWT"
	// identity type: the agent then signs a client assertion (RFC 7523) for
	// every token request and needs no ClientSecret. Defaults to the PEM key
	// in $AGENT_PRIVATE_KEY, with its kid from $AGENT_KEY_ID.
	PrivateKey *ClientAssertionSigner
	// Issuer is the organization's issuer identifier, the assertion's aud.
	// Defaults to IssuerFor(BaseURL, OrgID); set it on a custom domain.
	Issuer string
	// DPoP binds the agent's tokens to a key (RFC 9449). The client
	// credentials grant, MCP token exchanges and delegation exchanges then
	// send a DPoP proof, the tokens come back with token_type "DPoP", and
	// the agent presents them with the DPoP scheme. Needed for MCP servers
	// registered with "Require DPoP". See NewDPoPSigner.
	DPoP *DPoPSigner
}

// Agent is the client for an AI agent acting under its own identity.
//
// It owns an OAuth 2.0 client-credentials token and refreshes it
// transparently, so no call has to be preceded by an explicit login:
//
//	agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{}) // reads env vars
//	if err != nil {
//	    return err
//	}
//
//	allowed, err := agent.IsAllowed(ctx, "document.read", map[string]any{"id": "doc_99"})
//	if err != nil {
//	    return err
//	}
//
//	approval, err := agent.Approvals.Require(ctx, lumoauth.ApprovalParams{
//	    TaskID: "wire-001", Reason: "Wire $4,500 to INV-7741",
//	    Impact: lumoauth.ImpactHigh, OnBehalfOf: "ada@acme.com",
//	}, nil)
//
// For the AAuth protocol — cryptographic agent identity and RFC 9421
// message signing — use AAuthClient instead.
//
// An Agent is safe for concurrent use; concurrent callers share one
// in-flight token request.
type Agent struct {
	// Agents covers ask/isAllowed, self-inspection, and registration.
	Agents *AgentsResource
	// Jit covers Just-in-Time permissions.
	Jit *JitResource
	// Delegation covers RFC 8693 delegation primitives.
	Delegation *DelegationResource
	// Approvals covers push-approval-for-agent-actions.
	Approvals *ApprovalsResource
	// Mcp covers token exchange for secured MCP servers.
	Mcp *McpResource
	// Permissions covers RBAC checks for the agent's own principal.
	Permissions *PermissionsResource

	baseURL      string
	orgID        string
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	assertion    *ClientAssertionSigner
	issuer       string

	client *Client

	// mu guards the cached token and identity; refreshMu serialises the
	// authentication round trip so concurrent callers make one request.
	mu          sync.Mutex
	refreshMu   sync.Mutex
	accessToken string
	tokenType   string
	refreshAt   time.Time
	tokenScopes []string
	identity    *AgentIdentity
	info        *UserInfo
}

// NewAgent builds an Agent from config and environment. It returns a
// *ConfigError when the client credentials cannot be resolved; no network
// call is made until the first request.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	agent := &Agent{
		baseURL:      firstNonEmpty(cfg.BaseURL, os.Getenv(EnvBaseURL), DefaultBaseURL),
		orgID:        firstNonEmpty(cfg.OrgID, os.Getenv(EnvOrgID)),
		clientID:     firstNonEmpty(cfg.ClientID, os.Getenv(EnvAgentClientID)),
		clientSecret: cfg.ClientSecret,
		redirectURI:  cfg.RedirectURI,
		scopes:       cfg.Scopes,
		assertion:    cfg.PrivateKey,
		issuer:       cfg.Issuer,
	}
	agent.baseURL = strings.TrimRight(agent.baseURL, "/")

	if agent.assertion == nil && os.Getenv(EnvAgentPrivateKey) != "" {
		signer, err := LoadClientAssertionSigner(os.Getenv(EnvAgentPrivateKey), ClientAssertionOptions{KeyID: os.Getenv(EnvAgentKeyID)})
		if err != nil {
			return nil, err
		}
		agent.assertion = signer
	}
	// A private key JWT agent has no secret; an AGENT_CLIENT_SECRET left in
	// the environment must not become a second authentication method.
	if agent.clientSecret == "" && agent.assertion == nil {
		agent.clientSecret = os.Getenv(EnvAgentClientSecret)
	}

	if agent.clientID == "" || (agent.clientSecret == "" && agent.assertion == nil) {
		return nil, NewConfigError(
			"agent credentials are required: set AGENT_CLIENT_ID and AGENT_CLIENT_SECRET " +
				"(or AGENT_PRIVATE_KEY for a private key JWT agent), or pass ClientID with " +
				"ClientSecret or PrivateKey in AgentConfig")
	}
	if agent.clientSecret != "" && agent.assertion != nil {
		return nil, NewConfigError("pass ClientSecret or PrivateKey, not both: an agent authenticates with one method")
	}

	agent.client = newClient(&clientConfig{
		baseURL:            agent.baseURL,
		orgID:              agent.orgID,
		tokenProvider:      agent.AccessToken,
		timeout:            cfg.Timeout,
		httpClient:         cfg.HTTPClient,
		skipCertValidation: cfg.SkipCertValidation,
		userAgent:          userAgent(),
		dpop:               cfg.DPoP,
	})

	agent.Agents = agent.client.Agents
	agent.Jit = agent.client.Jit
	agent.Delegation = agent.client.Delegation
	agent.Approvals = agent.client.Approvals
	agent.Mcp = agent.client.Mcp
	agent.Permissions = agent.client.Permissions
	return agent, nil
}

// Client returns the underlying general-purpose client, for the namespaces
// the agent does not surface directly (Zanzibar, ABAC, Auth) and the Do
// escape hatch.
func (a *Agent) Client() *Client { return a.client }

// BaseURL returns the LumoAuth instance URL.
func (a *Agent) BaseURL() string { return a.baseURL }

// OrgID returns the organization slug.
func (a *Agent) OrgID() string { return a.orgID }

// ClientID returns the agent's OAuth client ID.
func (a *Agent) ClientID() string { return a.clientID }

// ClientSecret returns the agent's OAuth client secret. Needed by
// DelegationChain for the confidential-client consent exchange.
func (a *Agent) ClientSecret() string { return a.clientSecret }

// RedirectURI returns the configured OAuth callback URL.
func (a *Agent) RedirectURI() string { return a.redirectURI }

// DPoP returns the signer from AgentConfig.DPoP, or nil when the agent's
// tokens are plain bearer tokens.
func (a *Agent) DPoP() *DPoPSigner { return a.client.DPoP() }

// ── Authentication ────────────────────────────────────────────────────

// Authenticate performs the client-credentials grant and caches the token.
//
// Every API call does this on demand, so call it directly only to fail
// fast at startup or to request non-default scopes.
func (a *Agent) Authenticate(ctx context.Context, scopes ...string) (string, error) {
	requested := scopes
	if len(requested) == 0 {
		requested = a.scopes
	}

	var token *TokenResponse
	var err error
	if a.assertion != nil {
		assertion, aerr := a.ClientAssertion()
		if aerr != nil {
			return "", aerr
		}
		token, err = a.client.Auth.ClientCredentialsWithAssertion(ctx, a.clientID, assertion, requested...)
	} else {
		token, err = a.client.Auth.ClientCredentials(ctx, a.clientID, a.clientSecret, requested...)
	}
	if err != nil {
		return "", err
	}

	expiresIn := time.Duration(token.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.accessToken = token.AccessToken
	a.tokenType = tokenTypeOrBearer(token.TokenType)
	a.refreshAt = time.Now().Add(expiresIn - tokenRefreshBuffer)
	a.tokenScopes = token.Scopes()
	return a.accessToken, nil
}

// ClientAssertion signs a new private_key_jwt client assertion for this agent
// (single-use), addressed to AgentConfig.Issuer or IssuerFor(BaseURL, OrgID).
// It is a *ConfigError when the agent has no PrivateKey.
func (a *Agent) ClientAssertion() (string, error) {
	if a.assertion == nil {
		return "", NewConfigError("this agent signs no client assertions: set AgentConfig.PrivateKey")
	}
	audience := a.issuer
	if audience == "" {
		if a.orgID == "" {
			return "", NewConfigError("OrgID (LUMOAUTH_ORG_ID) or Issuer is needed to address a client assertion")
		}
		audience = IssuerFor(a.baseURL, a.orgID)
	}
	return a.assertion.Assertion(a.clientID, audience)
}

// AccessToken returns a valid access token, authenticating or refreshing
// when the cached one is missing or within a minute of expiry. It doubles
// as the TokenProvider for the underlying client.
//
// Concurrent callers collapse onto a single token request: the first one
// through refreshes while the rest wait, then all read the fresh token.
func (a *Agent) AccessToken(ctx context.Context) (string, error) {
	if token, ok := a.cachedToken(); ok {
		return token, nil
	}

	// Only one refresh runs at a time. The data lock (a.mu) is never held
	// across the network call, so cached reads stay fast meanwhile.
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()

	// Another goroutine may have refreshed while we waited.
	if token, ok := a.cachedToken(); ok {
		return token, nil
	}

	a.mu.Lock()
	scopes := append([]string(nil), a.tokenScopes...)
	a.mu.Unlock()

	return a.Authenticate(ctx, scopes...)
}

// cachedToken returns the cached token when it is still comfortably valid.
func (a *Agent) cachedToken() (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.accessToken != "" && time.Now().Before(a.refreshAt) {
		return a.accessToken, true
	}
	return "", false
}

// TokenType returns the token_type of the cached token: "Bearer", or
// "DPoP" when AgentConfig.DPoP bound it to a key. It is "" before the first
// authentication.
func (a *Agent) TokenType() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tokenType
}

// TokenScopes returns the scopes granted by the last authentication.
func (a *Agent) TokenScopes() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.tokenScopes...)
}

// ── Ask API and self-inspection ───────────────────────────────────────

// Ask asks whether the agent may perform an action — the preflight check
// before an LLM tool call.
func (a *Agent) Ask(ctx context.Context, action string, actionContext map[string]any) (*AgentAskResult, error) {
	return a.Agents.Ask(ctx, action, actionContext)
}

// IsAllowed is Ask reduced to a boolean.
func (a *Agent) IsAllowed(ctx context.Context, action string, actionContext map[string]any) (bool, error) {
	return a.Agents.IsAllowed(ctx, action, actionContext)
}

// Identity returns the agent's own identity, capabilities, and workspace,
// caching the result. Pass refresh to force a fetch.
func (a *Agent) Identity(ctx context.Context, refresh bool) (*AgentIdentity, error) {
	a.mu.Lock()
	cached := a.identity
	a.mu.Unlock()
	if cached != nil && !refresh {
		return cached, nil
	}

	identity, err := a.Agents.Me(ctx)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.identity = identity
	a.mu.Unlock()
	return identity, nil
}

// Info returns the agent's UserInfo claims (capabilities, budget policy),
// caching the result. Pass refresh to force a fetch.
func (a *Agent) Info(ctx context.Context, refresh bool) (*UserInfo, error) {
	a.mu.Lock()
	cached := a.info
	a.mu.Unlock()
	if cached != nil && !refresh {
		return cached, nil
	}

	info, err := a.Agents.Info(ctx)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.info = info
	a.mu.Unlock()
	return info, nil
}

// ReportUsage reports the model tokens and cost that the agent just used, for
// example the usage that the model provider returned. LumoAuth does not see
// model calls, so token and cost limits count only reported usage. The budget
// in the result also replaces the cached one, so CheckBudget reflects the
// report without another request.
//
//	resp, _ := llm.Chat(ctx, req)
//	if _, err := agent.ReportUsage(ctx, resp.Usage.TotalTokens, 0.0042); err != nil {
//	    return err
//	}
//	if err := agent.CheckBudget(ctx); err != nil {
//	    return err // ErrBudgetExceeded
//	}
func (a *Agent) ReportUsage(ctx context.Context, tokens int, costUSD float64) (*UsageReportResult, error) {
	result, err := a.Agents.ReportUsage(ctx, tokens, costUSD)
	if err != nil {
		return nil, err
	}
	if result.Budget != nil {
		a.mu.Lock()
		if a.info != nil {
			updated := *a.info
			updated.BudgetPolicy = result.Budget
			a.info = &updated
		}
		a.mu.Unlock()
	}
	return result, nil
}

// Capabilities returns the agent's capability slugs.
func (a *Agent) Capabilities(ctx context.Context) ([]string, error) {
	info, err := a.Info(ctx, false)
	if err != nil {
		return nil, err
	}
	return info.Capabilities, nil
}

// HasCapability reports whether the agent holds a capability. Names match as
// on the server: "tool:search_web" matches the stored "tool.search_web", and
// a held "tool.*" covers it (see CapabilityCovers). It checks only the agent's
// registered capabilities; the Ask API (Agent.Ask) also applies your policies
// and the token's scope.
func (a *Agent) HasCapability(ctx context.Context, capability string) (bool, error) {
	capabilities, err := a.Capabilities(ctx)
	if err != nil {
		return false, err
	}
	return AnyCapabilityCovers(capabilities, capability), nil
}

// RequireCapability is the guard for a capability-gated method: it returns
// nil when the agent holds the capability, and an error matching
// ErrPermissionDenied when it does not.
//
//	func (s *Service) SearchWeb(ctx context.Context, query string) error {
//	    if err := s.agent.RequireCapability(ctx, "tool:search_web"); err != nil {
//	        return err
//	    }
//	    …
//	}
func (a *Agent) RequireCapability(ctx context.Context, capability string) error {
	ok, err := a.HasCapability(ctx, capability)
	if err != nil {
		return err
	}
	if !ok {
		// Matches ErrPermissionDenied like a server-side 403 would, but is
		// deliberately not an *APIError: no request was made, so there is
		// no status code to report.
		return newError(ErrPermissionDenied, CodePermissionDenied,
			"agent lacks the required capability "+capability+
				" — update the agent registration to include it")
	}
	return nil
}

// Budget returns the agent's budget policy. It is never nil.
func (a *Agent) Budget(ctx context.Context) (*AgentBudget, error) {
	info, err := a.Info(ctx, false)
	if err != nil {
		return nil, err
	}
	if info.BudgetPolicy == nil {
		return &AgentBudget{}, nil
	}
	return info.BudgetPolicy, nil
}

// CheckBudget returns an error matching ErrBudgetExceeded when the agent's
// daily token budget is spent, and nil otherwise. Budget state is cached
// with the rest of the agent info — call Info(ctx, true) first for a live
// reading.
func (a *Agent) CheckBudget(ctx context.Context) error {
	budget, err := a.Budget(ctx)
	if err != nil {
		return err
	}
	if budget.Exhausted() {
		return newBudgetExceeded(budget)
	}
	return nil
}

// Register creates or updates this agent's record in the organization
// directory, using its own client ID.
func (a *Agent) Register(ctx context.Context, params RegisterParams) (*AgentRegistration, error) {
	if params.ClientID == "" {
		params.ClientID = a.clientID
	}
	return a.Agents.Register(ctx, params)
}

// MCPToken exchanges the agent's token for one bound to a secured MCP
// server. serverID is the Resource URI that the server is registered with,
// e.g. "https://mcp.example.com/mcp". The token works only at that server;
// see McpResource.Token.
func (a *Agent) MCPToken(ctx context.Context, serverID string) (string, error) {
	return a.Mcp.Token(ctx, serverID, "")
}

// AuthorizeMcpTool asks whether this agent may run one tool on an MCP
// server. serverID is the registered MCP server ID, not its URL. A deny
// returns Allowed false and a nil error; see AgentsResource.AuthorizeMcpTool.
func (a *Agent) AuthorizeMcpTool(ctx context.Context, serverID, tool string) (*AgentMcpToolDecision, error) {
	return a.Agents.AuthorizeMcpTool(ctx, serverID, tool)
}

// ── Generic requests ──────────────────────────────────────────────────

// Do sends an authenticated request to any endpoint and decodes the JSON
// response into out (nil to discard). See Client.Do.
func (a *Agent) Do(ctx context.Context, method, path string, body, out any) error {
	return a.client.Do(ctx, method, path, body, out)
}

// DoRaw is Do without response handling: the caller owns the
// *http.Response and must close its body.
func (a *Agent) DoRaw(ctx context.Context, method, path string, body any) (*http.Response, error) {
	return a.client.DoRaw(ctx, method, path, body)
}

// tokenTypeOrBearer normalises a token_type for comparison: "DPoP" for a
// bound token, "Bearer" otherwise (the field is optional on the wire).
func tokenTypeOrBearer(tokenType string) string {
	if strings.EqualFold(tokenType, DPoPTokenType) {
		return DPoPTokenType
	}
	return "Bearer"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
