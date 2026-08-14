package lumoauth

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// ConfidentialClient is what DelegationChain needs from an agent: a token
// source plus the OAuth client credentials the consent-code exchange and
// revocation require. *Agent satisfies it.
type ConfidentialClient interface {
	TokenSource
	ClientID() string
	ClientSecret() string
}

// DelegationChain manages RFC 8693 token exchange for agents acting on
// behalf of users — the Chain of Agency.
//
// It tracks one delegation per session ID through the full lifecycle:
//
//  1. User consent — build an authorization URL, then exchange the
//     callback code for the user's tokens.
//
//  2. Token exchange — combine the user's token (subject) with the agent's
//     (actor) into a delegated token carrying an `act` claim.
//
//  3. Delegated requests — call APIs as "agent acting for user", so every
//     action is attributable to both.
//
//  4. Nested delegation — pass authority to a sub-agent, adding a link to
//     the chain (up to MaxDelegationDepth).
//
//  5. Revocation — invalidate a session's tokens.
//
//     chain := lumoauth.NewDelegationChain(agent, "https://agent.example.com/callback")
//
//     url, err := chain.ConsentURL("session-1", []string{"read:documents"}, "")
//     // … user completes consent, your callback receives `code` …
//     if err := chain.HandleConsentCallback(ctx, "session-1", code); err != nil {
//     return err
//     }
//     resp, err := chain.Do(ctx, "session-1", "GET", "/orgs/acme/api/v1/documents", nil)
//
// A DelegationChain is safe for concurrent use.
type DelegationChain struct {
	agent       ConfidentialClient
	redirectURI string
	client      *Client
	resource    *DelegationResource

	mu               sync.Mutex
	userTokens       map[string]*userTokens
	delegatedTokens  map[string]string
	defaultScopeList []string
}

// userTokens holds one user's consent tokens for a session.
type userTokens struct {
	accessToken  string
	refreshToken string
	expiresAt    time.Time
	scopes       []string
}

// NewDelegationChain builds a chain over an authenticated agent.
// redirectURI is the OAuth callback the consent flow returns to; it may be
// empty when tokens are registered directly with SetUserToken.
func NewDelegationChain(agent ConfidentialClient, redirectURI string) *DelegationChain {
	chain := &DelegationChain{
		agent:           agent,
		redirectURI:     redirectURI,
		userTokens:      map[string]*userTokens{},
		delegatedTokens: map[string]string{},
	}
	chain.client = newClient(&clientConfig{
		baseURL:   agent.BaseURL(),
		orgID:     agent.OrgID(),
		userAgent: userAgent(),
	})
	chain.resource = chain.client.Delegation
	return chain
}

// ── Step 1: user consent ──────────────────────────────────────────────

// ConsentURL builds the URL where the user grants the agent permission to
// act on their behalf. Redirect the user there; consent returns them to
// the chain's redirect URI with an authorization code.
//
// sessionID correlates the consent with the later exchange. state defaults
// to "session:<sessionID>".
func (c *DelegationChain) ConsentURL(sessionID string, scopes []string, state string) (string, error) {
	if sessionID == "" {
		return "", NewValidationError("a session ID is required")
	}
	if c.redirectURI == "" {
		return "", NewConfigError(
			"a redirect URI is required for the consent flow — pass it to NewDelegationChain")
	}
	if state == "" {
		state = "session:" + sessionID
	}
	return c.resource.ConsentURL(ConsentURLParams{
		ClientID:    c.agent.ClientID(),
		RedirectURI: c.redirectURI,
		Scopes:      scopes,
		State:       state,
	})
}

// HandleConsentCallback exchanges the authorization code from the consent
// callback for the user's tokens and stores them under sessionID.
func (c *DelegationChain) HandleConsentCallback(ctx context.Context, sessionID, authorizationCode string) error {
	if sessionID == "" {
		return NewValidationError("a session ID is required")
	}
	if authorizationCode == "" {
		return NewValidationError("an authorization code is required")
	}

	token, err := c.resource.ExchangeCode(ctx, ExchangeCodeParams{
		Code:         authorizationCode,
		RedirectURI:  c.redirectURI,
		ClientID:     c.agent.ClientID(),
		ClientSecret: c.agent.ClientSecret(),
	})
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.userTokens[sessionID] = newUserTokens(token)
	delete(c.delegatedTokens, sessionID)
	return nil
}

// SetUserToken registers a user access token you already hold, skipping the
// consent redirect. Without a refresh token the SDK cannot renew it, so the
// delegation lasts only as long as the token does.
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
// may only narrow what the user consented to.
func (c *DelegationChain) Exchange(ctx context.Context, sessionID string, scopes ...string) (string, error) {
	user, err := c.ensureUserToken(ctx, sessionID)
	if err != nil {
		return "", err
	}
	agentToken, err := c.agent.AccessToken(ctx)
	if err != nil {
		return "", err
	}

	response, err := c.resource.Exchange(ctx, user.accessToken, agentToken, scopes...)
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
	if subAgentToken == "" {
		return "", NewValidationError("the sub-agent's own access token is required")
	}
	ourToken, err := c.DelegatedToken(ctx, sessionID)
	if err != nil {
		return "", err
	}

	response, err := c.resource.Exchange(ctx, ourToken, subAgentToken, scopes...)
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

// Revoke ends a delegation: it revokes the user's refresh token at the
// server, which invalidates every derived token, and drops the local
// state. Local state is cleared even if the server call fails, so a
// revoked session never keeps serving requests from cache.
func (c *DelegationChain) Revoke(ctx context.Context, sessionID string) error {
	c.mu.Lock()
	user := c.userTokens[sessionID]
	delete(c.userTokens, sessionID)
	delete(c.delegatedTokens, sessionID)
	c.mu.Unlock()

	if user == nil || user.refreshToken == "" {
		return nil
	}
	return c.resource.Revoke(ctx, RevokeParams{
		Token:         user.refreshToken,
		TokenTypeHint: "refresh_token",
		ClientID:      c.agent.ClientID(),
		ClientSecret:  c.agent.ClientSecret(),
	})
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
				"(ConsentURL → HandleConsentCallback) or register one with SetUserToken",
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

	token, err := c.resource.RefreshUserToken(ctx, RefreshTokenParams{
		RefreshToken: user.refreshToken,
		ClientID:     c.agent.ClientID(),
		ClientSecret: c.agent.ClientSecret(),
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

// annotateDelegationError adds delegation context to an exchange failure,
// naming the depth limit when that is what the server rejected.
func annotateDelegationError(err error, prefix string) error {
	apiErr, ok := AsAPIError(err)
	if !ok {
		return err
	}
	body, _ := apiErr.Body.(map[string]any)
	if code, _ := body["error"].(string); code == "delegation_depth_exceeded" {
		maxDepth := MaxDelegationDepth
		if reported, ok := body["max_depth"].(float64); ok {
			maxDepth = int(reported)
		}
		return validationErrorf("delegation chain too deep (maximum depth: %d)", maxDepth)
	}
	annotated := newAPIError(apiErr.StatusCode, apiErr.Code, prefix+": "+apiErr.Message, apiErr.Body)
	annotated.RetryAfter = apiErr.RetryAfter
	annotated.cause = err
	return annotated
}
