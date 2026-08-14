package lumoauth

import "context"

// MaxDelegationDepth is the deepest delegation chain LumoAuth will issue
// tokens for (user → agent → sub-agent).
const MaxDelegationDepth = 3

// DelegationResource covers the RFC 8693 delegation primitives — the raw
// operations behind the Chain of Agency.
//
// For session-tracked delegation with consent handling and refresh, use
// DelegationChain, which wraps this resource.
type DelegationResource struct {
	http *httpClient
	auth *AuthResource
}

// ConsentURLParams describes the consent redirect a user follows to let an
// agent act on their behalf.
type ConsentURLParams struct {
	// ClientID is the agent's OAuth client. Required.
	ClientID string
	// RedirectURI is where consent returns the user. Required.
	RedirectURI string
	// Scopes are the permissions being requested. Defaults to
	// ["read:documents"].
	Scopes []string
	// State is the CSRF token echoed back to the redirect URI.
	State string
}

// ConsentURL builds the URL where a user grants an agent delegated access.
// It requests offline access so the agent receives a refresh token.
func (r *DelegationResource) ConsentURL(params ConsentURLParams) (string, error) {
	scopes := params.Scopes
	if len(scopes) == 0 {
		scopes = []string{"read:documents"}
	}
	return r.auth.AuthorizationURL(AuthorizationURLParams{
		ClientID:    params.ClientID,
		RedirectURI: params.RedirectURI,
		Scope:       joinScopes(scopes),
		State:       params.State,
		Prompt:      "consent",
		AccessType:  "offline",
	})
}

// ExchangeCode trades a consent callback code for the user's tokens.
func (r *DelegationResource) ExchangeCode(ctx context.Context, params ExchangeCodeParams) (*TokenResponse, error) {
	return r.auth.ExchangeCode(ctx, params)
}

// RefreshUserToken refreshes a user's delegated access token.
func (r *DelegationResource) RefreshUserToken(ctx context.Context, params RefreshTokenParams) (*TokenResponse, error) {
	return r.auth.RefreshToken(ctx, params)
}

// Exchange combines a subject token (the user) with an actor token (the
// agent) into a delegated token. The resulting JWT carries an `act` claim
// recording the chain, so every downstream action is attributable to both.
func (r *DelegationResource) Exchange(ctx context.Context, subjectToken, actorToken string, scopes ...string) (*TokenResponse, error) {
	if subjectToken == "" {
		return nil, NewValidationError("a subject token is required")
	}
	if actorToken == "" {
		return nil, NewValidationError("an actor token is required")
	}
	return r.auth.TokenExchange(ctx, TokenExchangeParams{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
		Scopes:       scopes,
	})
}

// Revoke invalidates a delegation's refresh token, which also invalidates
// every token derived from it.
func (r *DelegationResource) Revoke(ctx context.Context, params RevokeParams) error {
	if params.TokenTypeHint == "" {
		params.TokenTypeHint = "refresh_token"
	}
	return r.auth.Revoke(ctx, params)
}

// ParseActorChain returns the `sub` of each nested `act` claim in a
// delegated JWT, outermost first — the direct actor, then progressively
// deeper sub-agents.
//
// The token is decoded WITHOUT signature verification: this is for display
// and audit, never for an authorization decision.
func ParseActorChain(token string) ([]string, error) {
	claims, err := decodeJWTPayload(token)
	if err != nil {
		return nil, err
	}
	var actors []string
	act, _ := claims["act"].(map[string]any)
	for act != nil {
		if sub, ok := act["sub"].(string); ok && sub != "" {
			actors = append(actors, sub)
		}
		act, _ = act["act"].(map[string]any)
	}
	return actors, nil
}

// TokenSubject returns a JWT's `sub` (principal) claim.
//
// The token is decoded WITHOUT signature verification — display and audit
// only.
func TokenSubject(token string) (string, error) {
	claims, err := decodeJWTPayload(token)
	if err != nil {
		return "", err
	}
	sub, _ := claims["sub"].(string)
	return sub, nil
}

// ParseActorChain is the method form of the package-level function, for
// callers who already hold the namespace.
func (r *DelegationResource) ParseActorChain(token string) ([]string, error) {
	return ParseActorChain(token)
}

// Subject is the method form of TokenSubject.
func (r *DelegationResource) Subject(token string) (string, error) {
	return TokenSubject(token)
}
