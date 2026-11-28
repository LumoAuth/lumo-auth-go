package lumoauth

import (
	"context"
	"strings"
)

// MaxDelegationDepth is the number of actors that a delegation chain may
// hold: the depth of the nested `act` claims of a token (user → agent →
// sub-agent → … , the user not counted). LumoAuth refuses the exchange that
// would add a sixth actor with 400 invalid_request ("Delegation chain too
// deep: …"); DelegationChain reports it as a ValidationError.
const MaxDelegationDepth = 5

// DelegationResource covers the RFC 8693 delegation primitives — the raw
// operations behind the Chain of Agency.
//
// For session-tracked delegation with consent handling and refresh, use
// DelegationChain, which wraps this resource.
type DelegationResource struct {
	http *httpClient
	auth *AuthResource
}

// ApplicationConsentParams describes the sign-in through which a person lets
// an agent act for them. An agent never starts a sign-in: the person signs
// in to an APPLICATION of your organization, the application redeems the
// code, and the agent exchanges the person's access token (Exchange).
type ApplicationConsentParams struct {
	// ClientID is the application's client ID, never the agent's agt_… ID.
	// Required.
	ClientID string
	// RedirectURI is one of the application's registered redirect URIs.
	// Required.
	RedirectURI string
	// Scopes are what the agent may do for the person: scopes that the
	// application is allowed and that the agent holds as capabilities.
	// "openid" is added. Required.
	Scopes []string
	// State is the CSRF value echoed back to the redirect URI. Required.
	State string
	// CodeChallenge is the PKCE S256 challenge of a verifier that you keep
	// for the code redemption. Required.
	CodeChallenge string
	// OfflineAccess asks for a refresh token (scope offline_access): the
	// application needs it to renew the person's token and to revoke the
	// grant.
	OfflineAccess bool
}

// ApplicationConsentURL builds the authorization URL where a person signs
// in to your application to let an agent act for them. The application
// then redeems the code with ExchangeCode (its client ID, its secret when it
// is confidential, and the PKCE verifier), and the agent calls Exchange with
// the person's access token. Revoke the person's refresh token as the
// application to end the delegation.
func (r *DelegationResource) ApplicationConsentURL(params ApplicationConsentParams) (string, error) {
	if params.ClientID == "" {
		return "", NewValidationError("ClientID (the application's client ID) is required")
	}
	if isAgentID(params.ClientID) {
		return "", NewValidationError(agentIDConsentRefusal)
	}
	if params.RedirectURI == "" {
		return "", NewValidationError("RedirectURI (a registered redirect URI of the application) is required")
	}
	if len(params.Scopes) == 0 {
		return "", NewValidationError("Scopes are required: without them the exchange grants the agent nothing")
	}
	if params.State == "" {
		return "", NewValidationError("State is required")
	}
	if params.CodeChallenge == "" {
		return "", NewValidationError("CodeChallenge (PKCE S256) is required")
	}
	return r.auth.AuthorizationURL(AuthorizationURLParams{
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		Scope:               consentScope(params.Scopes, params.OfflineAccess),
		State:               params.State,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: "S256",
	})
}

// consentScope is "openid", the scopes, and offline_access when asked for,
// each once.
func consentScope(scopes []string, offlineAccess bool) string {
	all := []string{"openid"}
	seen := map[string]bool{"openid": true}
	for _, scope := range scopes {
		if !seen[scope] {
			seen[scope] = true
			all = append(all, scope)
		}
	}
	if offlineAccess && !seen["offline_access"] {
		all = append(all, "offline_access")
	}
	return joinScopes(all)
}

// isAgentID reports whether a client ID is an agent's ID (agt_…), which
// cannot start a sign-in.
func isAgentID(clientID string) bool { return strings.HasPrefix(clientID, "agt_") }

const agentIDConsentRefusal = "an agent's ID (agt_…) cannot start a sign-in, LumoAuth answers \"Unknown Application\": " +
	"build the consent URL with the client ID of an application (ApplicationConsentURL, or NewDelegationChainForApplication), " +
	"then exchange the person's access token for the agent"

// ConsentURLParams describes the consent redirect a user follows to let an
// agent act on their behalf.
//
// Deprecated: use ApplicationConsentParams. LumoAuth starts a sign-in only
// for an application, never for an agent's ID, and the agent's credentials
// cannot redeem the code.
type ConsentURLParams struct {
	// ClientID is the OAuth client of the sign-in. Required. An agent's ID
	// is refused.
	ClientID string
	// RedirectURI is where consent returns the user. Required.
	RedirectURI string
	// Scopes are the scopes being requested. Defaults to
	// ["documents:read"].
	Scopes []string
	// State is the CSRF token echoed back to the redirect URI.
	State string
}

// ConsentURL builds an authorization URL that requests offline access.
//
// Deprecated: use ApplicationConsentURL, which names an application, uses
// PKCE and asks for offline_access. With an agent's ID this returns a
// ValidationError: LumoAuth answers "Unknown Application" for it.
func (r *DelegationResource) ConsentURL(params ConsentURLParams) (string, error) {
	if isAgentID(params.ClientID) {
		return "", NewValidationError(agentIDConsentRefusal)
	}
	scopes := params.Scopes
	if len(scopes) == 0 {
		scopes = []string{"documents:read"}
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

// ExchangeCode trades a consent callback code for the person's tokens. Pass
// the APPLICATION's client ID (and its secret when it is confidential) and
// the PKCE verifier; the agent's credentials are refused for the code.
func (r *DelegationResource) ExchangeCode(ctx context.Context, params ExchangeCodeParams) (*TokenResponse, error) {
	return r.auth.ExchangeCode(ctx, params)
}

// RefreshUserToken refreshes the person's access token, as the application
// that holds the refresh token (its client ID, and its secret when it is
// confidential).
func (r *DelegationResource) RefreshUserToken(ctx context.Context, params RefreshTokenParams) (*TokenResponse, error) {
	return r.auth.RefreshToken(ctx, params)
}

// Exchange combines a subject token (the user) with an actor token (the
// agent) into a delegated token. The resulting JWT carries an `act` claim
// recording the chain, so every downstream action is attributable to both.
// The token is bound to the acting agent; use ExchangeForResource to bind it
// to the API it will be sent to.
func (r *DelegationResource) Exchange(ctx context.Context, subjectToken, actorToken string, scopes ...string) (*TokenResponse, error) {
	return r.ExchangeForResource(ctx, subjectToken, actorToken, "", scopes...)
}

// ExchangeForResource is Exchange with an RFC 8707 resource indicator: the
// https URL in resource becomes the delegated token's `aud`.
func (r *DelegationResource) ExchangeForResource(ctx context.Context, subjectToken, actorToken, resource string, scopes ...string) (*TokenResponse, error) {
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
		Resource:     resource,
	})
}

// Revoke invalidates the person's refresh token, which also ends every
// token derived from it, the agent's delegated tokens included. Pass the
// client ID (and secret) of the APPLICATION that the token was issued to:
// LumoAuth refuses a revocation by another client, such as the agent
// (RFC 7009 §2.1).
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
