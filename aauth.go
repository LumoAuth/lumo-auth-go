package lumoauth

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// AAuthConfig configures an AAuthClient.
type AAuthConfig struct {
	// AgentIdentifier is the HTTPS URL uniquely identifying the agent,
	// e.g. "https://my-agent.example.com". Required.
	AgentIdentifier string
	// PrivateKeyPEM is the agent's Ed25519 (PKCS#8) or RSA private key.
	// Required.
	PrivateKeyPEM string
	// BaseURL is the LumoAuth instance. Defaults to $LUMOAUTH_URL, then
	// DefaultBaseURL.
	BaseURL string
	// OrgID is the organization slug. Defaults to $LUMOAUTH_ORG_ID.
	OrgID string
	// Kid identifies the key in the JWKS registered with LumoAuth.
	// Defaults to DefaultKid.
	Kid string
	// Timeout is the per-request timeout. Default: 30s.
	Timeout time.Duration
	// HTTPClient overrides the *http.Client used for every request.
	HTTPClient *http.Client
	// SkipCertValidation disables TLS verification. Local development only.
	SkipCertValidation bool
}

// AAuthClient speaks the AAuth (Agent Auth) protocol, which extends OAuth
// 2.1 with cryptographic agent identity, proof-of-possession tokens, and
// RFC 9421 HTTP message signing.
//
//	client, err := lumoauth.NewAAuthClient(lumoauth.AAuthConfig{
//	    AgentIdentifier: "https://my-agent.example.com",
//	    PrivateKeyPEM:   os.Getenv("AGENT_PRIVATE_KEY"),
//	    OrgID:           "acme-corp",
//	})
//	if err != nil {
//	    return err
//	}
//
//	result, err := client.RequestAuthToken(ctx, lumoauth.AuthTokenParams{
//	    ResourceToken: resourceToken,
//	    Scope:         "read write",
//	    AgentToken:    agentToken,
//	})
//	if err != nil {
//	    return err
//	}
//	if result.AuthorizationRequired {
//	    // Redirect the user to result.AuthorizationURI, then ExchangeCode.
//	}
//
// For OAuth client-credentials agents (no signing key) use Agent instead.
type AAuthClient struct {
	agentIdentifier string
	baseURL         string
	orgID           string
	kid             string
	privateKeyPEM   string
	signer          crypto.Signer
	http            *httpClient
}

// NewAAuthClient builds an AAuth client and parses the agent's private key.
func NewAAuthClient(cfg AAuthConfig) (*AAuthClient, error) {
	if cfg.AgentIdentifier == "" {
		return nil, NewConfigError("AgentIdentifier is required")
	}
	if cfg.PrivateKeyPEM == "" {
		return nil, NewConfigError("PrivateKeyPEM is required")
	}

	signer, err := LoadPrivateKey(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	client := &AAuthClient{
		agentIdentifier: cfg.AgentIdentifier,
		baseURL:         strings.TrimRight(firstNonEmpty(cfg.BaseURL, os.Getenv(EnvBaseURL), DefaultBaseURL), "/"),
		orgID:           firstNonEmpty(cfg.OrgID, os.Getenv(EnvOrgID)),
		kid:             firstNonEmpty(cfg.Kid, DefaultKid),
		privateKeyPEM:   cfg.PrivateKeyPEM,
		signer:          signer,
	}

	client.http = newHTTPClient(client.baseURL)
	client.http.orgID = client.orgID
	client.http.userAgent = userAgent()
	if cfg.HTTPClient != nil {
		client.http.doer = cfg.HTTPClient
	}
	if cfg.Timeout > 0 {
		client.http.timeout = cfg.Timeout
		if cfg.HTTPClient == nil {
			client.http.doer.Timeout = cfg.Timeout
		}
	}
	if cfg.SkipCertValidation {
		client.http.insecureTLS()
	}
	return client, nil
}

// AgentIdentifier returns the agent's identity URL.
func (c *AAuthClient) AgentIdentifier() string { return c.agentIdentifier }

// BaseURL returns the LumoAuth instance URL.
func (c *AAuthClient) BaseURL() string { return c.baseURL }

// OrgID returns the organization slug.
func (c *AAuthClient) OrgID() string { return c.orgID }

// Issuer returns the organization's AAuth issuer URL —
// {baseURL}/orgs/{orgID}/api/v1 — which is the `iss` value in issued
// tokens and the base for JWKS discovery.
func (c *AAuthClient) Issuer() string {
	return c.baseURL + "/orgs/" + url.PathEscape(c.orgID) + "/api/v1"
}

// PublicJWK returns the agent's public key as a JWK, tagged with its kid.
func (c *AAuthClient) PublicJWK() (JWK, error) {
	jwk, err := jwkFromPublicKey(c.signer.Public())
	if err != nil {
		return JWK{}, err
	}
	jwk.Use = "sig"
	jwk.Kid = c.kid
	return jwk, nil
}

// PublicJWKThumbprint returns the RFC 7638 thumbprint of the agent's public
// key — the `jkt` value that binds tokens to this key.
func (c *AAuthClient) PublicJWKThumbprint() (string, error) {
	jwk, err := c.PublicJWK()
	if err != nil {
		return "", err
	}
	return jwk.Thumbprint()
}

// SignRequest builds RFC 9421 signature headers with this agent's key.
func (c *AAuthClient) SignRequest(method, targetURL string, opts SignOptions) (map[string]string, error) {
	return signRequestWithKey(c.signer, method, targetURL, opts)
}

// ── Token flows ───────────────────────────────────────────────────────

// AAuthTokenResponse is a successful response from the agent token
// endpoint. When the server requires user consent instead,
// AuthorizationRequired is set and the token fields are empty.
type AAuthTokenResponse struct {
	// RequestType echoes the flow: auth, code, exchange, or refresh.
	RequestType string
	// AuthToken is the `auth+jwt` to present to the resource.
	AuthToken string
	// ExpiresIn is the token's lifetime in seconds.
	ExpiresIn int
	// TokenType is normally "auth+jwt".
	TokenType string
	// RefreshToken is present when the grant includes one.
	RefreshToken string

	// AuthorizationRequired reports that a human must consent first.
	AuthorizationRequired bool
	// RequestToken identifies the pending request (600s TTL).
	RequestToken string
	// AuthorizationURI is the consent page to redirect the user to.
	AuthorizationURI string
}

// rawAAuthToken is the wire shape of the agent token endpoint's response.
type rawAAuthToken struct {
	RequestType      string `json:"request_type"`
	AuthToken        string `json:"auth_token"`
	ExpiresIn        int    `json:"expires_in"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	RequestToken     string `json:"request_token"`
	AuthorizationURI string `json:"authorization_uri"`
	AuthURL          string `json:"auth_url"`
}

// AuthTokenParams describes a direct authorization request
// (request_type=auth).
type AuthTokenParams struct {
	// ResourceToken is the `resource+jwt` obtained from the target
	// resource. Required.
	ResourceToken string
	// Scope is space-separated and informational; scopes bind through the
	// resource token.
	Scope string
	// AgentToken is the `agent+jwt` presented in Agent-Auth. Required —
	// the endpoint authenticates the agent through that header, not the
	// request body.
	AgentToken string
	// RedirectURI is where consent should return the user, for flows that
	// need it. Must be registered for the agent.
	RedirectURI string
}

// RequestAuthToken asks for an auth token (AAuth Flow 2, direct
// authorization).
//
// When the server requires user consent it returns a response with
// AuthorizationRequired set: redirect the user to AuthorizationURI, then
// call ExchangeCode with the code delivered to your redirect URI.
func (c *AAuthClient) RequestAuthToken(ctx context.Context, params AuthTokenParams) (*AAuthTokenResponse, error) {
	if params.ResourceToken == "" {
		return nil, NewValidationError("ResourceToken is required")
	}
	if err := c.requireAgentToken(params.AgentToken); err != nil {
		return nil, err
	}

	body := map[string]any{
		"request_type":   "auth",
		"resource_token": params.ResourceToken,
	}
	if params.Scope != "" {
		body["scope"] = params.Scope
	}
	if params.RedirectURI != "" {
		body["redirect_uri"] = params.RedirectURI
	}

	raw, err := c.tokenRequest(ctx, body, params.AgentToken)
	if err != nil {
		// A 401 carrying a consent URL is not a failure: it is the
		// server asking for the user's approval.
		if consent, ok := consentFromError(err); ok {
			return consent, nil
		}
		return nil, err
	}

	if raw.AuthToken == "" && (raw.RequestToken != "" || raw.AuthorizationURI != "" || raw.AuthURL != "") {
		return &AAuthTokenResponse{
			AuthorizationRequired: true,
			RequestToken:          raw.RequestToken,
			AuthorizationURI:      firstNonEmpty(raw.AuthorizationURI, raw.AuthURL),
			ExpiresIn:             raw.ExpiresIn,
		}, nil
	}
	return mapAAuthToken(raw)
}

// ConsentURL builds the user-consent URL for a pending request token.
// Prefer the AuthorizationURI returned by RequestAuthToken when present.
func (c *AAuthClient) ConsentURL(requestToken string) (string, error) {
	target, err := c.routeURL(RouteAAuthAgentAuth)
	if err != nil {
		return "", err
	}
	return target + "?request_token=" + url.QueryEscape(requestToken), nil
}

// ExchangeCode trades an authorization code for tokens after user consent
// (request_type=code).
//
// redirectURI must be the exact URI the code was delivered to; the server
// redeems codes atomically and rejects a mismatch.
func (c *AAuthClient) ExchangeCode(ctx context.Context, code, redirectURI, agentToken string) (*AAuthTokenResponse, error) {
	if code == "" {
		return nil, NewValidationError("an authorization code is required")
	}
	if redirectURI == "" {
		return nil, NewValidationError("a redirect URI is required and must match the one the code was delivered to")
	}
	if err := c.requireAgentToken(agentToken); err != nil {
		return nil, err
	}

	raw, err := c.tokenRequest(ctx, map[string]any{
		"request_type": "code",
		"code":         code,
		"redirect_uri": redirectURI,
	}, agentToken)
	if err != nil {
		return nil, err
	}
	return mapAAuthToken(raw)
}

// ExchangeToken performs a multi-hop exchange (request_type=exchange):
// trade an upstream auth token plus a downstream resource token for a new
// auth token carrying an `act` actor chain. The agent must be permitted to
// exchange tokens.
func (c *AAuthClient) ExchangeToken(ctx context.Context, authToken, resourceToken, agentToken string) (*AAuthTokenResponse, error) {
	if authToken == "" || resourceToken == "" {
		return nil, NewValidationError("both an auth token and a resource token are required")
	}
	if err := c.requireAgentToken(agentToken); err != nil {
		return nil, err
	}

	raw, err := c.tokenRequest(ctx, map[string]any{
		"request_type":   "exchange",
		"auth_token":     authToken,
		"resource_token": resourceToken,
	}, agentToken)
	if err != nil {
		return nil, err
	}
	return mapAAuthToken(raw)
}

// RefreshParams describes an auth-token refresh.
type RefreshParams struct {
	// RefreshToken is the token from a prior response. Required.
	RefreshToken string
	// ResourceToken must be a FRESH resource token for the target
	// resource — the server requires one on every refresh. Required.
	ResourceToken string
	// Scope optionally narrows the refreshed token; it must be a subset
	// of the original grant.
	Scope string
	// AgentToken is the `agent+jwt` presented in Agent-Auth. Required.
	AgentToken string
}

// Refresh renews an auth token (request_type=refresh). Refresh tokens are
// not rotated, so the same one stays valid for the grant's lifetime.
func (c *AAuthClient) Refresh(ctx context.Context, params RefreshParams) (*AAuthTokenResponse, error) {
	if params.RefreshToken == "" {
		return nil, NewValidationError("RefreshToken is required")
	}
	if params.ResourceToken == "" {
		return nil, NewValidationError(
			"ResourceToken is required — the server needs a fresh resource token on every refresh")
	}
	if err := c.requireAgentToken(params.AgentToken); err != nil {
		return nil, err
	}

	body := map[string]any{
		"request_type":   "refresh",
		"refresh_token":  params.RefreshToken,
		"resource_token": params.ResourceToken,
	}
	if params.Scope != "" {
		body["scope"] = params.Scope
	}

	raw, err := c.tokenRequest(ctx, body, params.AgentToken)
	if err != nil {
		return nil, err
	}
	return mapAAuthToken(raw)
}

// Token types accepted by Revoke.
const (
	AAuthTokenTypeAuth    = "auth_token"
	AAuthTokenTypeRefresh = "refresh_token"
)

// Revoke invalidates an auth token (by its `jti`) or a refresh token (by
// value). It succeeds whether or not the token existed — the server does
// not reveal that.
func (c *AAuthClient) Revoke(ctx context.Context, token, tokenType, agentToken string) error {
	if token == "" {
		return NewValidationError("a token is required")
	}
	if err := c.requireAgentToken(agentToken); err != nil {
		return err
	}
	if tokenType == "" {
		tokenType = AAuthTokenTypeAuth
	}

	target, err := c.routeURL(RouteAAuthTokenRevoke)
	if err != nil {
		return err
	}
	_, err = c.signedPost(ctx, target, map[string]any{
		"token":      token,
		"token_type": tokenType,
	}, agentToken)
	return err
}

// ── Signed requests to protected resources ────────────────────────────

// SignedRequest makes a signed, authenticated request to a protected
// resource.
//
// The request carries the auth token as a Bearer credential AND an RFC
// 9421 signature proving possession of the key bound in the token's
// cnf.jwk. The signature covers the authorization component, so the
// resource server verifies both together.
//
// The caller owns the returned response and must close its body.
func (c *AAuthClient) SignedRequest(ctx context.Context, method, targetURL, authToken string, body any) (*http.Response, error) {
	if authToken == "" {
		return nil, NewValidationError("an auth token is required")
	}

	var payload []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, NewValidationError("could not encode the request body: " + err.Error())
		}
		payload = encoded
	}

	authorization := "Bearer " + authToken
	headers, err := c.SignRequest(method, targetURL, SignOptions{
		Body:          payload,
		Authorization: authorization,
	})
	if err != nil {
		return nil, err
	}
	headers["Authorization"] = authorization

	return c.http.doRaw(ctx, method, targetURL, &request{
		// Raw, not JSON: the Content-Digest covers these exact bytes.
		Raw:     payload,
		Headers: headers,
		NoAuth:  true,
	})
}

// ── Discovery ─────────────────────────────────────────────────────────

// AAuthIssuerMetadata describes an AAuth authorization server.
type AAuthIssuerMetadata struct {
	Issuer                    string   `json:"issuer"`
	AAuthVersion              string   `json:"aauth_version,omitempty"`
	JWKSURI                   string   `json:"jwks_uri,omitempty"`
	AgentTokenEndpoint        string   `json:"agent_token_endpoint,omitempty"`
	AgentAuthEndpoint         string   `json:"agent_auth_endpoint,omitempty"`
	AgentSigningAlgsSupported []string `json:"agent_signing_algs_supported,omitempty"`
	TokenSigningAlgsSupported []string `json:"token_signing_algs_supported,omitempty"`
	RequestTypesSupported     []string `json:"request_types_supported,omitempty"`
	ScopesSupported           []string `json:"scopes_supported,omitempty"`
}

// AAuthAgentMetadata describes a registered agent.
type AAuthAgentMetadata struct {
	Agent        string   `json:"agent"`
	JWKSURI      string   `json:"jwks_uri,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	Name         string   `json:"name,omitempty"`
}

// AAuthResourceMetadata describes a protected resource server.
type AAuthResourceMetadata struct {
	Resource              string   `json:"resource"`
	JWKSURI               string   `json:"jwks_uri,omitempty"`
	ResourceTokenEndpoint string   `json:"resource_token_endpoint,omitempty"`
	SupportedScopes       []string `json:"supported_scopes,omitempty"`
}

// DiscoverIssuer fetches the organization's AAuth issuer metadata.
func (c *AAuthClient) DiscoverIssuer(ctx context.Context) (*AAuthIssuerMetadata, error) {
	var metadata AAuthIssuerMetadata
	if err := c.http.call(ctx, RouteAAuthIssuerMetadata, nil, &request{NoAuth: true}, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

// DiscoverAgents fetches metadata for the organization's active agents.
func (c *AAuthClient) DiscoverAgents(ctx context.Context) ([]AAuthAgentMetadata, error) {
	var raw json.RawMessage
	if err := c.http.call(ctx, RouteAAuthAgentMetadata, nil, &request{NoAuth: true}, &raw); err != nil {
		return nil, err
	}

	// The endpoint returns a single object for one agent, an array for many.
	var agents []AAuthAgentMetadata
	if err := json.Unmarshal(raw, &agents); err == nil {
		return agents, nil
	}
	var single AAuthAgentMetadata
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, NewValidationError("could not decode the agent metadata: " + err.Error())
	}
	return []AAuthAgentMetadata{single}, nil
}

// DiscoverResource fetches a resource server's AAuth metadata from
// {resourceURL}/.well-known/aauth-resource.
func (c *AAuthClient) DiscoverResource(ctx context.Context, resourceURL string) ([]AAuthResourceMetadata, error) {
	target := strings.TrimRight(resourceURL, "/") + "/.well-known/aauth-resource"

	var raw json.RawMessage
	if err := c.http.do(ctx, http.MethodGet, target, &request{NoAuth: true}, &raw); err != nil {
		return nil, err
	}

	var resources []AAuthResourceMetadata
	if err := json.Unmarshal(raw, &resources); err == nil {
		return resources, nil
	}
	var single AAuthResourceMetadata
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, NewValidationError("could not decode the resource metadata: " + err.Error())
	}
	return []AAuthResourceMetadata{single}, nil
}

// JWKS fetches the organization's AAuth signing keys — the keys that
// verify issued auth tokens.
func (c *AAuthClient) JWKS(ctx context.Context) (*JWKS, error) {
	var keys JWKS
	if err := c.http.call(ctx, RouteAAuthJWKS, nil, &request{NoAuth: true}, &keys); err != nil {
		return nil, err
	}
	return &keys, nil
}

// ── Internal ──────────────────────────────────────────────────────────

func (c *AAuthClient) requireAgentToken(agentToken string) error {
	if agentToken == "" {
		return NewValidationError(
			"an agent token is required — the /agent/token endpoint authenticates " +
				"the agent through the Agent-Auth header, not the request body")
	}
	return nil
}

// routeURL builds the absolute URL for an org-scoped route.
func (c *AAuthClient) routeURL(routeName string) (string, error) {
	if c.orgID == "" {
		return "", NewConfigError(
			"an org ID is required for AAuth operations — set OrgID or LUMOAUTH_ORG_ID")
	}
	path, err := RoutePath(routeName, map[string]string{"orgId": c.orgID})
	if err != nil {
		return "", err
	}
	return c.baseURL + path, nil
}

// tokenRequest posts a signed request to the agent token endpoint.
func (c *AAuthClient) tokenRequest(ctx context.Context, body map[string]any, agentToken string) (*rawAAuthToken, error) {
	target, err := c.routeURL(RouteAAuthAgentToken)
	if err != nil {
		return nil, err
	}
	raw, err := c.signedPost(ctx, target, body, agentToken)
	if err != nil {
		return nil, err
	}

	var token rawAAuthToken
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &token); err != nil {
			return nil, NewValidationError("could not decode the token response: " + err.Error())
		}
	}
	return &token, nil
}

// signedPost signs a JSON body per the AAuth profile and posts it. The
// signature covers the exact bytes sent, so the body is marshalled once
// and reused.
func (c *AAuthClient) signedPost(ctx context.Context, target string, body map[string]any, agentToken string) (json.RawMessage, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, NewValidationError("could not encode the request body: " + err.Error())
	}

	headers, err := c.SignRequest(http.MethodPost, target, SignOptions{
		Body:       payload,
		AgentToken: agentToken,
	})
	if err != nil {
		return nil, err
	}

	var raw json.RawMessage
	if err := c.http.do(ctx, http.MethodPost, target, &request{
		// Raw, not JSON: the signature covers these exact bytes.
		Raw:     payload,
		Headers: headers,
		NoAuth:  true,
	}, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// mapAAuthToken converts the wire response into the public shape.
func mapAAuthToken(raw *rawAAuthToken) (*AAuthTokenResponse, error) {
	if raw.AuthToken == "" {
		return nil, NewValidationError("the token response carried no auth_token")
	}
	response := &AAuthTokenResponse{
		RequestType:  firstNonEmpty(raw.RequestType, "auth"),
		AuthToken:    raw.AuthToken,
		ExpiresIn:    raw.ExpiresIn,
		TokenType:    firstNonEmpty(raw.TokenType, "auth+jwt"),
		RefreshToken: raw.RefreshToken,
	}
	return response, nil
}

// consentFromError recognises the 401 the server returns when a human must
// approve the request, and converts it into a consent instruction.
func consentFromError(err error) (*AAuthTokenResponse, bool) {
	apiErr, ok := AsAPIError(err)
	if !ok || apiErr.StatusCode != http.StatusUnauthorized {
		return nil, false
	}
	body, ok := apiErr.Body.(map[string]any)
	if !ok {
		return nil, false
	}

	authorizationURI, _ := body["authorization_uri"].(string)
	if authorizationURI == "" {
		authorizationURI, _ = body["auth_url"].(string)
	}
	requestToken, _ := body["request_token"].(string)
	if authorizationURI == "" && requestToken == "" {
		return nil, false
	}

	consent := &AAuthTokenResponse{
		AuthorizationRequired: true,
		RequestToken:          requestToken,
		AuthorizationURI:      authorizationURI,
	}
	if expiresIn, ok := body["expires_in"].(float64); ok {
		consent.ExpiresIn = int(expiresIn)
	}
	return consent, true
}
