package lumoauth

import (
	"context"
	"net/url"
)

// RFC 8693 token-exchange constants.
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)

// AuthResource covers the org-scoped OAuth 2.1 endpoints: authorize, token,
// userinfo, and revoke.
type AuthResource struct {
	http *httpClient
}

// AuthorizationURLParams describes an authorization-code redirect.
type AuthorizationURLParams struct {
	// ClientID is the OAuth client initiating the flow. Required.
	ClientID string
	// RedirectURI must match one registered on the client. Required.
	RedirectURI string
	// Scope defaults to "openid profile email".
	Scope string
	// State is the CSRF token echoed back to the redirect URI.
	State string
	// ResponseType defaults to "code".
	ResponseType string
	// CodeChallenge enables PKCE. When set and CodeChallengeMethod is
	// empty, "S256" is used.
	CodeChallenge       string
	CodeChallengeMethod string
	// Prompt is the OIDC prompt parameter ("consent", "login", "none").
	Prompt string
	// AccessType set to "offline" requests a refresh token.
	AccessType string
	// Extra adds arbitrary query parameters.
	Extra map[string]string
}

// AuthorizationURL builds the URL to redirect a user to in order to start
// the authorization-code flow.
func (r *AuthResource) AuthorizationURL(params AuthorizationURLParams) (string, error) {
	if params.ClientID == "" {
		return "", NewValidationError("ClientID is required to build an authorization URL")
	}
	if params.RedirectURI == "" {
		return "", NewValidationError("RedirectURI is required to build an authorization URL")
	}

	_, path, err := r.http.resolve(RouteOAuthAuthorize, nil)
	if err != nil {
		return "", err
	}

	scope := params.Scope
	if scope == "" {
		scope = "openid profile email"
	}
	responseType := params.ResponseType
	if responseType == "" {
		responseType = "code"
	}

	query := url.Values{}
	query.Set("response_type", responseType)
	query.Set("client_id", params.ClientID)
	query.Set("redirect_uri", params.RedirectURI)
	query.Set("scope", scope)
	if params.State != "" {
		query.Set("state", params.State)
	}
	if params.CodeChallenge != "" {
		method := params.CodeChallengeMethod
		if method == "" {
			method = "S256"
		}
		query.Set("code_challenge", params.CodeChallenge)
		query.Set("code_challenge_method", method)
	}
	if params.Prompt != "" {
		query.Set("prompt", params.Prompt)
	}
	if params.AccessType != "" {
		query.Set("access_type", params.AccessType)
	}
	for key, value := range params.Extra {
		query.Set(key, value)
	}

	return r.http.baseURL + path + "?" + query.Encode(), nil
}

// ExchangeCodeParams describes an authorization-code exchange.
type ExchangeCodeParams struct {
	// Code is the authorization code from the callback. Required.
	Code string
	// RedirectURI must match the one used to obtain the code. Required.
	RedirectURI string
	// ClientID is the OAuth client. Required.
	ClientID string
	// ClientSecret is required for confidential clients.
	ClientSecret string
	// CodeVerifier is the PKCE verifier matching the challenge sent to
	// the authorization endpoint.
	CodeVerifier string
}

// ExchangeCode trades an authorization code for tokens.
func (r *AuthResource) ExchangeCode(ctx context.Context, params ExchangeCodeParams) (*TokenResponse, error) {
	if params.Code == "" {
		return nil, NewValidationError("Code is required to exchange an authorization code")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", params.Code)
	form.Set("redirect_uri", params.RedirectURI)
	form.Set("client_id", params.ClientID)
	if params.ClientSecret != "" {
		form.Set("client_secret", params.ClientSecret)
	}
	if params.CodeVerifier != "" {
		form.Set("code_verifier", params.CodeVerifier)
	}
	return r.tokenRequest(ctx, form)
}

// RefreshTokenParams describes a refresh-token grant.
type RefreshTokenParams struct {
	// RefreshToken is the token to redeem. Required.
	RefreshToken string
	// ClientID is the OAuth client. Required.
	ClientID string
	// ClientSecret is required for confidential clients.
	ClientSecret string
	// Scopes optionally narrows the refreshed token; must be a subset of
	// the original grant.
	Scopes []string
}

// RefreshToken exchanges a refresh token for a new access token.
func (r *AuthResource) RefreshToken(ctx context.Context, params RefreshTokenParams) (*TokenResponse, error) {
	if params.RefreshToken == "" {
		return nil, NewValidationError("RefreshToken is required")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", params.RefreshToken)
	form.Set("client_id", params.ClientID)
	if params.ClientSecret != "" {
		form.Set("client_secret", params.ClientSecret)
	}
	if len(params.Scopes) > 0 {
		form.Set("scope", joinScopes(params.Scopes))
	}
	return r.tokenRequest(ctx, form)
}

// ClientCredentials performs the machine-to-machine client-credentials
// grant. Passing no scopes lets the server grant the client's defaults.
func (r *AuthResource) ClientCredentials(ctx context.Context, clientID, clientSecret string, scopes ...string) (*TokenResponse, error) {
	if clientID == "" || clientSecret == "" {
		return nil, NewValidationError("clientID and clientSecret are both required for the client-credentials grant")
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	if len(scopes) > 0 {
		form.Set("scope", joinScopes(scopes))
	}
	return r.tokenRequest(ctx, form)
}

// TokenExchangeParams describes an RFC 8693 token exchange.
type TokenExchangeParams struct {
	// SubjectToken is the token representing the principal being acted
	// for. Required.
	SubjectToken string
	// ActorToken is the token of the party doing the acting (the agent);
	// set it to build a delegation chain with an `act` claim.
	ActorToken string
	// Audience scopes the issued token to one resource (an MCP server id,
	// for instance).
	Audience string
	// Scopes optionally narrows the issued token.
	Scopes []string
}

// TokenExchange performs an RFC 8693 exchange — the primitive behind
// delegation and MCP audience scoping.
func (r *AuthResource) TokenExchange(ctx context.Context, params TokenExchangeParams) (*TokenResponse, error) {
	if params.SubjectToken == "" {
		return nil, NewValidationError("SubjectToken is required for a token exchange")
	}
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", params.SubjectToken)
	form.Set("subject_token_type", TokenTypeAccessToken)
	if params.ActorToken != "" {
		form.Set("actor_token", params.ActorToken)
		form.Set("actor_token_type", TokenTypeAccessToken)
	}
	if params.Audience != "" {
		form.Set("audience", params.Audience)
	}
	if len(params.Scopes) > 0 {
		form.Set("scope", joinScopes(params.Scopes))
	}
	return r.tokenRequest(ctx, form)
}

// RevokeParams describes a token revocation.
type RevokeParams struct {
	// Token is the access or refresh token to revoke. Required.
	Token string
	// TokenTypeHint is "access_token" or "refresh_token".
	TokenTypeHint string
	// ClientID and ClientSecret authenticate the revocation.
	ClientID     string
	ClientSecret string
}

// Revoke invalidates an access or refresh token. Revoking a refresh token
// also invalidates the tokens derived from it.
func (r *AuthResource) Revoke(ctx context.Context, params RevokeParams) error {
	if params.Token == "" {
		return NewValidationError("Token is required to revoke")
	}
	form := url.Values{}
	form.Set("token", params.Token)
	if params.TokenTypeHint != "" {
		form.Set("token_type_hint", params.TokenTypeHint)
	}
	if params.ClientID != "" {
		form.Set("client_id", params.ClientID)
	}
	if params.ClientSecret != "" {
		form.Set("client_secret", params.ClientSecret)
	}
	// The revocation endpoint authenticates through the form body.
	return r.http.call(ctx, RouteOAuthRevoke, nil, &request{Form: form, NoAuth: true}, nil)
}

// UserInfo fetches the OIDC UserInfo claims. Pass an empty accessToken to
// use the client's own credentials.
func (r *AuthResource) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req := &request{}
	if accessToken != "" {
		req.Headers = map[string]string{"Authorization": "Bearer " + accessToken}
	}
	var info UserInfo
	if err := r.http.call(ctx, RouteOAuthUserInfo, nil, req, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// tokenRequest posts to the token endpoint. Token endpoints authenticate
// through the form body, so the client's own credentials are never
// injected — sending both would be ambiguous.
func (r *AuthResource) tokenRequest(ctx context.Context, form url.Values) (*TokenResponse, error) {
	var token TokenResponse
	if err := r.http.call(ctx, RouteOAuthToken, nil, &request{Form: form, NoAuth: true}, &token); err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, NewValidationError("the token endpoint returned no access_token")
	}
	return &token, nil
}
