package lumoauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConfidentialClient is what the deprecated NewDelegationChain needs from an
// agent: a token source plus OAuth client credentials. *Agent satisfies it.
//
// As for a TokenSource, an implementation that addresses its organization
// on a custom domain also has the method CustomDomain() string.
type ConfidentialClient interface {
	TokenSource
	ClientID() string
	ClientSecret() string
}

// DelegationApplication is the application of your organization through
// which a person lets an agent act for them. An agent never starts a
// sign-in: the person signs in to this application, the application redeems
// the code, and the agent exchanges the person's access token.
type DelegationApplication struct {
	// ClientID is the application's client ID, never the agent's agt_… ID.
	// Required.
	ClientID string
	// ClientSecret is the application's secret; leave it empty for a public
	// application (PKCE alone).
	ClientSecret string
	// RedirectURI is one of the application's registered redirect URIs,
	// where your callback receives the code. Required.
	RedirectURI string
	// OfflineAccess asks for a refresh token (scope offline_access). The
	// chain needs it to renew the person's token and to revoke the grant.
	OfflineAccess bool
}

// ErrDelegationNotRevoked matches the error of DelegationChain.Revoke when it
// could only forget the session's local state: the chain holds no refresh
// token for the session, or no application credentials to revoke it with.
// The person's grant at LumoAuth then still stands. The error also matches
// ErrConfig.
var ErrDelegationNotRevoked = errors.New("lumoauth: the delegation was forgotten locally, not revoked at LumoAuth")

// DelegationChain manages RFC 8693 token exchange for agents acting on
// behalf of users — the Chain of Agency.
//
// It tracks one delegation per session ID through the full lifecycle:
//
//  1. Consent — the person signs in to your application (ConsentURL), and
//     the application redeems the code (HandleConsentCallback). Or register
//     tokens that you already hold (SetUserTokens, SetUserToken).
//
//  2. Token exchange — combine the person's token (subject) with the
//     agent's (actor) into a delegated token carrying an `act` claim.
//
//  3. Delegated requests — call APIs as "agent acting for user", so every
//     action is attributable to both.
//
//  4. Nested delegation — pass authority to a sub-agent, adding a link to
//     the chain (up to MaxDelegationDepth).
//
//  5. Revocation — the application revokes the person's refresh token,
//     which ends every delegated token of that grant.
//
// For example:
//
//	chain, err := lumoauth.NewDelegationChainForApplication(agent, lumoauth.DelegationApplication{
//	    ClientID:      os.Getenv("APP_CLIENT_ID"),
//	    ClientSecret:  os.Getenv("APP_CLIENT_SECRET"),
//	    RedirectURI:   "https://app.example.com/agent/callback",
//	    OfflineAccess: true,
//	})
//	url, err := chain.ConsentURL("session-1", []string{"documents:read"}, "")
//	// … the person signs in, your callback receives `code` …
//	err = chain.HandleConsentCallback(ctx, "session-1", code)
//	resp, err := chain.DoRaw(ctx, "session-1", "GET", "https://api.example.com/documents", nil)
//
// A DelegationChain is safe for concurrent use.
type DelegationChain struct {
	agent TokenSource
	// app is the application of the consent flow (NewDelegationChainForApplication).
	app *DelegationApplication
	// legacy and redirectURI belong to the deprecated NewDelegationChain.
	legacy      ConfidentialClient
	redirectURI string
	client      *Client
	resource    *DelegationResource

	mu               sync.Mutex
	userTokens       map[string]*userTokens
	delegatedTokens  map[string]string
	consents         map[string]*pendingConsent
	defaultScopeList []string
}

// userTokens holds one user's consent tokens for a session.
type userTokens struct {
	accessToken  string
	refreshToken string
	expiresAt    time.Time
	scopes       []string
}

// pendingConsent is a consent URL that was handed out and not redeemed yet.
type pendingConsent struct {
	verifier string
	state    string
}

// NewDelegationChainForApplication builds a chain whose consent flow goes
// through one of your organization's applications. agent supplies the
// actor token of every exchange (an *Agent does); the application's
// credentials redeem the code, refresh the person's token and revoke it.
// It returns a *ConfigError for an application without a client ID, with
// an agent's ID, or without an absolute redirect URI.
func NewDelegationChainForApplication(agent TokenSource, app DelegationApplication) (*DelegationChain, error) {
	if app.ClientID == "" {
		return nil, NewConfigError("DelegationApplication.ClientID (the application's client ID) is required")
	}
	if isAgentID(app.ClientID) {
		return nil, NewConfigError("DelegationApplication.ClientID is an agent's ID: " + agentIDConsentRefusal)
	}
	redirect, err := url.Parse(app.RedirectURI)
	if err != nil || !redirect.IsAbs() || redirect.Host == "" || redirect.Fragment != "" {
		return nil, NewConfigError("DelegationApplication.RedirectURI must be an absolute URL that is registered on the application")
	}
	chain := newDelegationChain(agent)
	chain.app = &app
	return chain, nil
}

// NewDelegationChain builds a chain over an authenticated agent, with the
// agent's own client ID for the consent flow.
//
// Deprecated: LumoAuth starts a sign-in only for an application, so the
// consent flow of this chain cannot work for an agent's agt_… ID: ConsentURL
// and HandleConsentCallback then return a *ConfigError. Use
// NewDelegationChainForApplication. The exchange, delegated requests and
// SetUserToken keep working.
func NewDelegationChain(agent ConfidentialClient, redirectURI string) *DelegationChain {
	chain := newDelegationChain(agent)
	chain.legacy = agent
	chain.redirectURI = redirectURI
	return chain
}

func newDelegationChain(agent TokenSource) *DelegationChain {
	chain := &DelegationChain{
		agent:           agent,
		userTokens:      map[string]*userTokens{},
		delegatedTokens: map[string]string{},
		consents:        map[string]*pendingConsent{},
	}
	// The constructors return no error for the address, so an invalid
	// custom domain of the agent is kept and returned by the first call that
	// needs an address. *Agent never has one: NewAgent refuses it.
	customDomain, configErr := customDomainOf(agent)
	chain.client = newClient(&clientConfig{
		baseURL:      agent.BaseURL(),
		customDomain: customDomain,
		configErr:    configErr,
		orgID:        agent.OrgID(),
		userAgent:    userAgent(),
	})
	chain.resource = chain.client.Delegation
	return chain
}

// clientCredentials is the client that redeems codes, refreshes and
// revokes the person's tokens: the application, or the deprecated chain's
// agent. ok is false when the chain has none that can work.
func (c *DelegationChain) clientCredentials() (clientID, clientSecret string, ok bool) {
	if c.app != nil {
		return c.app.ClientID, c.app.ClientSecret, true
	}
	if c.legacy != nil && !isAgentID(c.legacy.ClientID()) {
		return c.legacy.ClientID(), c.legacy.ClientSecret(), true
	}
	return "", "", false
}

// ── Step 1: user consent ──────────────────────────────────────────────

// ConsentURL builds the URL where the person signs in to your application
// to let the agent act for them. Redirect the person there; the sign-in
// returns them to the application's redirect URI with a code.
//
// The URL names the application, asks for "openid", the scopes and, with
// DelegationApplication.OfflineAccess, offline_access, and carries a PKCE
// S256 challenge whose verifier the chain keeps for HandleConsentCallback.
// Scopes are required: the exchange grants the agent only scopes that the
// person consented to. state defaults to a random value; ConsentState
// returns it, so your callback can compare it with the one it receives.
//
// On a chain from the deprecated NewDelegationChain, this builds the old
// URL with the agent's client ID, and returns a *ConfigError for an agent's
// agt_… ID, which LumoAuth answers with "Unknown Application".
func (c *DelegationChain) ConsentURL(sessionID string, scopes []string, state string) (string, error) {
	if sessionID == "" {
		return "", NewValidationError("a session ID is required")
	}
	if c.app == nil {
		return c.legacyConsentURL(sessionID, scopes, state)
	}
	if len(scopes) == 0 {
		return "", NewValidationError("scopes are required: the exchange grants the agent only what the person consented to")
	}
	verifier, challenge, err := pkcePair()
	if err != nil {
		return "", err
	}
	if state == "" {
		if state, err = randomToken(16); err != nil {
			return "", err
		}
	}
	consentURL, err := c.resource.ApplicationConsentURL(ApplicationConsentParams{
		ClientID:      c.app.ClientID,
		RedirectURI:   c.app.RedirectURI,
		Scopes:        scopes,
		State:         state,
		CodeChallenge: challenge,
		OfflineAccess: c.app.OfflineAccess,
	})
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.consents[sessionID] = &pendingConsent{verifier: verifier, state: state}
	c.mu.Unlock()
	return consentURL, nil
}

// legacyConsentURL is ConsentURL of the deprecated NewDelegationChain.
func (c *DelegationChain) legacyConsentURL(sessionID string, scopes []string, state string) (string, error) {
	if isAgentID(c.legacy.ClientID()) {
		return "", NewConfigError(agentIDConsentRefusal)
	}
	if c.redirectURI == "" {
		return "", NewConfigError(
			"a redirect URI is required for the consent flow — pass it to NewDelegationChain")
	}
	if state == "" {
		state = "session:" + sessionID
	}
	return c.resource.ConsentURL(ConsentURLParams{
		ClientID:    c.legacy.ClientID(),
		RedirectURI: c.redirectURI,
		Scopes:      scopes,
		State:       state,
	})
}

// ConsentState returns the state of the session's consent URL that has not
// been redeemed yet, or "".
func (c *DelegationChain) ConsentState(sessionID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if consent := c.consents[sessionID]; consent != nil {
		return consent.state
	}
	return ""
}

// HandleConsentCallback redeems the code of the consent callback as the
// application (its client ID, its secret when it is confidential, and the
// PKCE verifier of this session's ConsentURL) and stores the person's tokens
// under sessionID. The agent's credentials play no part. The session's
// consent is used up whether or not the redemption succeeds: a code is
// single-use, so a failure needs a new ConsentURL.
//
// It returns a *ConfigError when this chain handed out no consent URL for
// the session, and, on a chain from the deprecated NewDelegationChain, for
// an agent's agt_… ID.
func (c *DelegationChain) HandleConsentCallback(ctx context.Context, sessionID, authorizationCode string) error {
	if sessionID == "" {
		return NewValidationError("a session ID is required")
	}
	if authorizationCode == "" {
		return NewValidationError("an authorization code is required")
	}

	params := ExchangeCodeParams{Code: authorizationCode}
	if c.app != nil {
		c.mu.Lock()
		consent := c.consents[sessionID]
		delete(c.consents, sessionID)
		c.mu.Unlock()
		if consent == nil {
			return configErrorf("no consent of this chain is waiting for session %q: call ConsentURL first", sessionID)
		}
		params.RedirectURI = c.app.RedirectURI
		params.ClientID = c.app.ClientID
		params.ClientSecret = c.app.ClientSecret
		params.CodeVerifier = consent.verifier
	} else {
		if isAgentID(c.legacy.ClientID()) {
			return NewConfigError(agentIDConsentRefusal)
		}
		params.RedirectURI = c.redirectURI
		params.ClientID = c.legacy.ClientID()
		params.ClientSecret = c.legacy.ClientSecret()
	}

	token, err := c.resource.ExchangeCode(ctx, params)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.userTokens[sessionID] = newUserTokens(token)
	delete(c.delegatedTokens, sessionID)
	return nil
}

// SetUserTokens registers the person's tokens that your application got
// itself, for example from its own sign-in: the access token, and the
// refresh token when there is one. With the refresh token, and the
// application's credentials (NewDelegationChainForApplication), the chain
// renews the person's token and Revoke ends the grant.
func (c *DelegationChain) SetUserTokens(sessionID string, tokens *TokenResponse) error {
	if sessionID == "" {
		return NewValidationError("a session ID is required")
	}
	if tokens == nil || tokens.AccessToken == "" {
		return NewValidationError("an access token is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userTokens[sessionID] = newUserTokens(tokens)
	delete(c.delegatedTokens, sessionID)
	return nil
}

// SetUserToken registers a user access token you already hold, skipping the
// consent redirect. Without a refresh token the SDK cannot renew it, so the
// delegation lasts only as long as the token does, and Revoke can only
// forget it (ErrDelegationNotRevoked). SetUserTokens also takes the refresh
// token.
func (c *DelegationChain) SetUserToken(sessionID, accessToken string) error {
	if sessionID == "" {
		return NewValidationError("a session ID is required")
	}
	if accessToken == "" {
		return NewValidationError("an access token is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userTokens[sessionID] = &userTokens{accessToken: accessToken}
	delete(c.delegatedTokens, sessionID)
	return nil
}

// ── Step 2: token exchange ────────────────────────────────────────────

// Exchange produces a delegated token for a session, combining the user's
// token (subject) with the agent's (actor). The result is cached; scopes
// may only narrow what the user consented to. The token is bound to this
// agent; use ExchangeForResource to bind it to the API it will be sent to.
func (c *DelegationChain) Exchange(ctx context.Context, sessionID string, scopes ...string) (string, error) {
	return c.ExchangeForResource(ctx, sessionID, "", scopes...)
}

// ExchangeForResource is Exchange with an RFC 8707 resource indicator: the
// https URL in resource becomes the delegated token's `aud`. The result
// replaces the session's cached delegated token.
func (c *DelegationChain) ExchangeForResource(ctx context.Context, sessionID, resource string, scopes ...string) (string, error) {
	user, err := c.ensureUserToken(ctx, sessionID)
	if err != nil {
		return "", err
	}
	agentToken, err := c.agent.AccessToken(ctx)
	if err != nil {
		return "", err
	}

	response, err := c.resource.ExchangeForResource(ctx, user.accessToken, agentToken, resource, scopes...)
	if err != nil {
		return "", annotateDelegationError(err, "token exchange failed")
	}

	c.mu.Lock()
	c.delegatedTokens[sessionID] = response.AccessToken
	c.mu.Unlock()
	return response.AccessToken, nil
}

// DelegatedToken returns the cached delegated token for a session,
// performing the exchange if there isn't one yet.
func (c *DelegationChain) DelegatedToken(ctx context.Context, sessionID string) (string, error) {
	c.mu.Lock()
	token := c.delegatedTokens[sessionID]
	c.mu.Unlock()
	if token != "" {
		return token, nil
	}
	return c.Exchange(ctx, sessionID)
}

// ── Step 3: delegated requests ────────────────────────────────────────

// Do makes a request with a session's delegated token, exchanging for one
// first if needed, and decodes the JSON response into out (nil to discard).
func (c *DelegationChain) Do(ctx context.Context, sessionID, method, path string, body, out any) error {
	token, err := c.DelegatedToken(ctx, sessionID)
	if err != nil {
		return err
	}
	return c.client.http.do(ctx, method, path, &request{
		JSON:    body,
		Headers: map[string]string{"Authorization": "Bearer " + token},
	}, out)
}

// DoRaw is Do without response handling: the caller owns the
// *http.Response and must close its body.
func (c *DelegationChain) DoRaw(ctx context.Context, sessionID, method, path string, body any) (*http.Response, error) {
	token, err := c.DelegatedToken(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	return c.client.http.doRaw(ctx, method, path, &request{
		JSON:    body,
		Headers: map[string]string{"Authorization": "Bearer " + token},
	})
}

// ── Step 4: nested delegation ─────────────────────────────────────────

// DelegateToSubAgent mints a token for the chain user → this agent →
// sub-agent. Each hop may only narrow scopes, and LumoAuth caps the chain
// at MaxDelegationDepth.
//
// subAgentToken is the sub-agent's own client-credentials token.
func (c *DelegationChain) DelegateToSubAgent(ctx context.Context, sessionID, subAgentToken string, scopes ...string) (string, error) {
	return c.DelegateToSubAgentForResource(ctx, sessionID, subAgentToken, "", scopes...)
}

// DelegateToSubAgentForResource is DelegateToSubAgent with an RFC 8707
// resource indicator for the sub-agent's token (its `aud`).
func (c *DelegationChain) DelegateToSubAgentForResource(ctx context.Context, sessionID, subAgentToken, resource string, scopes ...string) (string, error) {
	if subAgentToken == "" {
		return "", NewValidationError("the sub-agent's own access token is required")
	}
	ourToken, err := c.DelegatedToken(ctx, sessionID)
	if err != nil {
		return "", err
	}

	response, err := c.resource.ExchangeForResource(ctx, ourToken, subAgentToken, resource, scopes...)
	if err != nil {
		return "", annotateDelegationError(err, "nested delegation failed")
	}
	return response.AccessToken, nil
}

// ── Introspection ─────────────────────────────────────────────────────

// ActorChain returns the actors recorded in a delegated JWT, outermost
// first. Decoded without signature verification — display and audit only.
func (c *DelegationChain) ActorChain(token string) ([]string, error) {
	return ParseActorChain(token)
}

// ActiveSessions returns the session IDs holding user tokens.
func (c *DelegationChain) ActiveSessions() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	sessions := make([]string, 0, len(c.userTokens))
	for sessionID := range c.userTokens {
		sessions = append(sessions, sessionID)
	}
	return sessions
}

// HasDelegation reports whether a delegated token is cached for a session.
func (c *DelegationChain) HasDelegation(sessionID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.delegatedTokens[sessionID] != ""
}

// ── Step 5: revocation ────────────────────────────────────────────────

// Revoke ends a delegation: the application revokes the person's refresh
// token at LumoAuth (POST /oauth/revoke with the application's client ID,
// and its secret when it is confidential), which ends every delegated token
// of that grant, and the chain drops the session's local state. Local state
// is cleared even if the server call fails, so a revoked session never keeps
// serving requests from cache.
//
// When the chain cannot end the grant at LumoAuth, it only forgets the
// local state and says so: the error matches ErrDelegationNotRevoked (and
// ErrConfig). That is the case for a session without a refresh token (for
// example one registered with SetUserToken), and on a chain without the
// application's credentials (the deprecated NewDelegationChain with an
// agent: LumoAuth refuses a revocation by another client than the one the
// token was issued to). Revoke the person's refresh token where it is held,
// with Auth.Revoke and the application's credentials, or call Forget when
// forgetting is all you want. An unknown session returns nil.
func (c *DelegationChain) Revoke(ctx context.Context, sessionID string) error {
	c.mu.Lock()
	user := c.userTokens[sessionID]
	delete(c.userTokens, sessionID)
	delete(c.delegatedTokens, sessionID)
	delete(c.consents, sessionID)
	c.mu.Unlock()

	if user == nil {
		return nil
	}
	clientID, clientSecret, ok := c.clientCredentials()
	switch {
	case user.refreshToken == "":
		return notRevoked(sessionID, "the chain holds no refresh token for it")
	case !ok:
		return notRevoked(sessionID, "the chain has no application credentials to revoke it with (use NewDelegationChainForApplication)")
	}
	return c.resource.Revoke(ctx, RevokeParams{
		Token:         user.refreshToken,
		TokenTypeHint: "refresh_token",
		ClientID:      clientID,
		ClientSecret:  clientSecret,
	})
}

// notRevoked is the error of a Revoke that could only forget local state.
func notRevoked(sessionID, why string) error {
	err := configErrorf("session %q was forgotten here, but its grant at LumoAuth still stands: %s; "+
		"revoke the person's refresh token as the application (Auth.Revoke)", sessionID, why)
	err.cause = ErrDelegationNotRevoked
	return err
}

// Forget drops a session's local state (tokens and pending consent) without
// any request. The person's grant at LumoAuth is not touched.
func (c *DelegationChain) Forget(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.userTokens, sessionID)
	delete(c.delegatedTokens, sessionID)
	delete(c.consents, sessionID)
}

// RevokeAll revokes every active session, returning the first error while
// still attempting the rest.
func (c *DelegationChain) RevokeAll(ctx context.Context) error {
	var firstErr error
	for _, sessionID := range c.ActiveSessions() {
		if err := c.Revoke(ctx, sessionID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ── Internal ──────────────────────────────────────────────────────────

// ensureUserToken returns a session's user tokens, refreshing first when
// they have expired and a refresh token is available.
func (c *DelegationChain) ensureUserToken(ctx context.Context, sessionID string) (*userTokens, error) {
	c.mu.Lock()
	user := c.userTokens[sessionID]
	c.mu.Unlock()

	if user == nil {
		return nil, configErrorf(
			"no user token for session %q — complete the consent flow "+
				"(ConsentURL → HandleConsentCallback) or register one with SetUserTokens",
			sessionID)
	}
	if user.expiresAt.IsZero() || time.Now().Before(user.expiresAt) {
		return user, nil
	}
	if user.refreshToken == "" {
		// Expired with nothing to refresh from: let the server reject it
		// rather than guessing that it is unusable.
		return user, nil
	}

	clientID, clientSecret, ok := c.clientCredentials()
	if !ok {
		// The refresh token belongs to an application whose credentials
		// this chain does not hold: let the server judge the old token.
		return user, nil
	}
	token, err := c.resource.RefreshUserToken(ctx, RefreshTokenParams{
		RefreshToken: user.refreshToken,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		return nil, err
	}

	refreshed := newUserTokens(token)
	if refreshed.refreshToken == "" {
		refreshed.refreshToken = user.refreshToken // not rotated
	}

	c.mu.Lock()
	c.userTokens[sessionID] = refreshed
	// The underlying user token changed, so the derived one is stale.
	delete(c.delegatedTokens, sessionID)
	c.mu.Unlock()
	return refreshed, nil
}

func newUserTokens(token *TokenResponse) *userTokens {
	expiresIn := time.Duration(token.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}
	return &userTokens{
		accessToken:  token.AccessToken,
		refreshToken: token.RefreshToken,
		expiresAt:    time.Now().Add(expiresIn),
		scopes:       token.Scopes(),
	}
}

// depthRefusalPattern matches the server's refusal of a chain that would be
// too deep: 400 invalid_request "Delegation chain too deep: act nesting depth
// 6 exceeds the maximum of 5".
var depthRefusalPattern = regexp.MustCompile(`(?i)^delegation chain too deep\b.*?(?:maximum of (\d+))?$`)

// delegationDepthRefusal reports whether an exchange failure is the depth
// limit, and the maximum depth that the server named (MaxDelegationDepth when
// it named none). It also recognises the 403 delegation_depth_exceeded
// answer with max_depth that earlier servers documented.
func delegationDepthRefusal(apiErr *APIError) (int, bool) {
	body, _ := apiErr.Body.(map[string]any)
	if code, _ := body["error"].(string); code == "delegation_depth_exceeded" {
		if reported, ok := body["max_depth"].(float64); ok && reported > 0 {
			return int(reported), true
		}
		return MaxDelegationDepth, true
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		return 0, false
	}
	description, _ := body["error_description"].(string)
	match := depthRefusalPattern.FindStringSubmatch(strings.TrimSpace(description))
	if match == nil {
		return 0, false
	}
	if reported, err := strconv.Atoi(match[1]); err == nil && reported > 0 {
		return reported, true
	}
	return MaxDelegationDepth, true
}

// annotateDelegationError adds delegation context to an exchange failure,
// naming the depth limit when that is what the server rejected.
func annotateDelegationError(err error, prefix string) error {
	apiErr, ok := AsAPIError(err)
	if !ok {
		return err
	}
	if maxDepth, ok := delegationDepthRefusal(apiErr); ok {
		tooDeep := validationErrorf("delegation chain too deep (maximum depth: %d)", maxDepth)
		tooDeep.cause = err // the server's answer stays reachable with errors.As
		return tooDeep
	}
	annotated := newAPIError(apiErr.StatusCode, apiErr.Code, prefix+": "+apiErr.Message, apiErr.Body)
	annotated.RetryAfter = apiErr.RetryAfter
	annotated.RequiredScopes = apiErr.RequiredScopes
	annotated.cause = err
	return annotated
}
