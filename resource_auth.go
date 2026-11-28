package lumoauth

import (
	"context"
	"net/http"
	"net/url"
)

// RFC 8693 token-exchange constants.
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	// TokenTypeAccessToken is an opaque or at+jwt access token issued by the
	// organization — the default subject/actor type.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	// TokenTypeJWT is an at+jwt access token, or an external workload identity
	// token (Kubernetes, AWS, GCP, Azure, GitHub, SPIFFE) presented by a
	// registered agent.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"
	// TokenTypeIDToken is an OpenID Connect ID token issued by the organization
	// to the exchanging client.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
	// TokenTypeRefreshToken is a refresh token issued to the exchanging client.
	// It is refused as the subject when an agent acts on a user's behalf
	// (ActorToken is an agent access token): 400 invalid_request.
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
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

	authorizeURL, err := r.http.routeURL(RouteOAuthAuthorize, nil)
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

	return authorizeURL + "?" + query.Encode(), nil
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
// grant. Passing no scopes lets the server grant the client's defaults. To
// send a resource indicator, use ClientCredentialsWithParams.
func (r *AuthResource) ClientCredentials(ctx context.Context, clientID, clientSecret string, scopes ...string) (*TokenResponse, error) {
	if clientID == "" || clientSecret == "" {
		return nil, NewValidationError("clientID and clientSecret are both required for the client-credentials grant")
	}
	return r.ClientCredentialsWithParams(ctx, ClientCredentialsParams{
		ClientID: clientID, ClientSecret: clientSecret, Scopes: scopes,
	})
}

// ClientCredentialsWithAssertion performs the client-credentials grant with a
// private_key_jwt client assertion (RFC 7523) instead of a secret: the
// authentication of an agent registered with the "Private key JWT" identity
// type. Build clientAssertion with ClientAssertionSigner.Assertion; it is
// single-use.
func (r *AuthResource) ClientCredentialsWithAssertion(ctx context.Context, clientID, clientAssertion string, scopes ...string) (*TokenResponse, error) {
	if clientID == "" || clientAssertion == "" {
		return nil, NewValidationError("clientID and clientAssertion are both required for the client-credentials grant")
	}
	return r.ClientCredentialsWithParams(ctx, ClientCredentialsParams{
		ClientID: clientID, ClientAssertion: clientAssertion, Scopes: scopes,
	})
}

// ClientCredentialsParams describes a client-credentials grant.
type ClientCredentialsParams struct {
	// ClientID is the OAuth client or the agent. Required.
	ClientID string
	// ClientSecret authenticates a client with a secret. Set it or
	// ClientAssertion, not both.
	ClientSecret string
	// ClientAuthMethod is how ClientSecret is sent: ClientSecretPost (the
	// default, as ClientCredentials does) or ClientSecretBasic.
	ClientAuthMethod string
	// ClientAssertion is a private_key_jwt client assertion (RFC 7523),
	// built with ClientAssertionSigner.Assertion; it is single-use.
	ClientAssertion string
	// Scopes optionally narrows the token; empty means the client's
	// defaults.
	Scopes []string
	// Resource is the RFC 8707 resource indicator: the absolute URL of the
	// API that the token is for. It becomes the token's aud; without it,
	// aud is the client ID. The client's allowed audiences, when set, must
	// cover it, and a registered MCP server applies its own policy.
	Resource string
}

// ClientCredentialsWithParams performs the client-credentials grant with a
// secret or an assertion, and optionally a resource indicator:
//
//	token, err := client.Auth.ClientCredentialsWithParams(ctx, lumoauth.ClientCredentialsParams{
//	    ClientID:     clientID,
//	    ClientSecret: clientSecret,
//	    Scopes:       []string{"reports:read"},
//	    Resource:     "https://api.example.com/",
//	})
func (r *AuthResource) ClientCredentialsWithParams(ctx context.Context, params ClientCredentialsParams) (*TokenResponse, error) {
	if params.ClientID == "" {
		return nil, NewValidationError("ClientID is required for the client-credentials grant")
	}
	if err := validateResource(params.Resource); err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	basic, err := applyClientAuth(form, clientAuth{
		clientID: params.ClientID, secret: params.ClientSecret, assertion: params.ClientAssertion,
		method: params.ClientAuthMethod, defaultMethod: ClientSecretPost,
	})
	if err != nil {
		return nil, err
	}
	if len(params.Scopes) > 0 {
		form.Set("scope", joinScopes(params.Scopes))
	}
	if params.Resource != "" {
		form.Set("resource", params.Resource)
	}
	return r.tokenRequestWith(ctx, form, basic)
}

// validateResource accepts "" or an absolute URL without a fragment
// (RFC 8707 §2).
func validateResource(resource string) error {
	if resource == "" {
		return nil
	}
	parsed, err := url.Parse(resource)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Fragment != "" {
		return NewValidationError("Resource must be an absolute URL without a fragment (RFC 8707)")
	}
	return nil
}

// TokenExchangeParams describes an RFC 8693 token exchange.
type TokenExchangeParams struct {
	// SubjectToken is the token representing the principal being acted
	// for. Required. The subject must still be active: a deactivated or
	// blocked user, or a suspended agent, gets invalid_grant. A JIT task
	// token is never accepted as the subject.
	SubjectToken string
	// ActorToken is the token of the party doing the acting (the agent);
	// set it to build a delegation chain with an `act` claim.
	ActorToken string
	// Audience is sent as the RFC 8693 `audience` parameter. LumoAuth binds
	// the issued token's `aud` from Resource, not from Audience.
	Audience string
	// Resource is the RFC 8707 resource indicator — the absolute https URL
	// of the API the issued token is for. It becomes its `aud`; without it
	// an agent on-behalf-of token is bound to the acting agent's id.
	Resource string
	// Scopes optionally narrows the issued token.
	Scopes []string
	// SubjectTokenType declares what SubjectToken is (TokenTypeAccessToken,
	// TokenTypeJWT, TokenTypeIDToken or TokenTypeRefreshToken). Empty means
	// TokenTypeAccessToken. The server refuses a token that does not match
	// its declared type (sdk-contract/token-types.json).
	SubjectTokenType string
	// ActorTokenType declares what ActorToken is; empty means
	// TokenTypeAccessToken.
	ActorTokenType string

	// ClientID, with ClientSecret or ClientAssertion, authenticates your
	// application at the token endpoint: the exchange of a confidential
	// application (token exchange switched on for it). Leave all three empty
	// for the agent on-behalf-of exchange, where the actor token
	// authenticates the agent.
	ClientID string
	// ClientSecret is the application's secret.
	ClientSecret string
	// ClientAuthMethod is how ClientSecret is sent: ClientSecretBasic (the
	// default, an Authorization header) or ClientSecretPost (form fields).
	ClientAuthMethod string
	// ClientAssertion is a private_key_jwt client assertion (RFC 7523),
	// built with ClientAssertionSigner.Assertion, instead of a secret.
	ClientAssertion string
}

// TokenExchange performs an RFC 8693 exchange — the primitive behind
// delegation and MCP audience scoping. A confidential application
// authenticates with ClientID and ClientSecret (Basic by default) or
// ClientAssertion; an agent's on-behalf-of exchange needs none.
func (r *AuthResource) TokenExchange(ctx context.Context, params TokenExchangeParams) (*TokenResponse, error) {
	if params.SubjectToken == "" {
		return nil, NewValidationError("SubjectToken is required for a token exchange")
	}
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", params.SubjectToken)
	form.Set("subject_token_type", tokenTypeOrDefault(params.SubjectTokenType))
	if params.ActorToken != "" {
		form.Set("actor_token", params.ActorToken)
		form.Set("actor_token_type", tokenTypeOrDefault(params.ActorTokenType))
	}
	if params.Audience != "" {
		form.Set("audience", params.Audience)
	}
	if params.Resource != "" {
		form.Set("resource", params.Resource)
	}
	if len(params.Scopes) > 0 {
		form.Set("scope", joinScopes(params.Scopes))
	}
	basic, err := applyClientAuth(form, clientAuth{
		clientID: params.ClientID, secret: params.ClientSecret, assertion: params.ClientAssertion,
		method: params.ClientAuthMethod, defaultMethod: ClientSecretBasic, optional: true,
	})
	if err != nil {
		return nil, err
	}
	return r.tokenRequestWith(ctx, form, basic)
}

// Methods of sending a client secret to the token endpoint (RFC 6749
// §2.3.1). A client assertion (private_key_jwt) is chosen by setting
// ClientAssertion instead.
const (
	// ClientSecretBasic sends the client ID and secret in an HTTP Basic
	// Authorization header.
	ClientSecretBasic = "client_secret_basic"
	// ClientSecretPost sends them as the client_id and client_secret form
	// fields.
	ClientSecretPost = "client_secret_post"
)

// clientAuth is the client authentication of one token request.
type clientAuth struct {
	clientID, secret, assertion string
	method, defaultMethod       string
	// optional allows a request without client authentication.
	optional bool
}

// applyClientAuth validates the client authentication and adds it to the
// form, or returns the Basic credentials to send in the header.
func applyClientAuth(form url.Values, auth clientAuth) (*basicCredentials, error) {
	if auth.secret == "" && auth.assertion == "" {
		if auth.method != "" {
			return nil, NewValidationError("ClientAuthMethod is set, but there is no ClientSecret")
		}
		if auth.optional {
			if auth.clientID != "" {
				form.Set("client_id", auth.clientID)
			}
			return nil, nil
		}
		return nil, NewValidationError("ClientSecret or ClientAssertion is required")
	}
	if auth.clientID == "" {
		return nil, NewValidationError("ClientID is required with ClientSecret or ClientAssertion")
	}
	if auth.secret != "" && auth.assertion != "" {
		return nil, NewValidationError("set ClientSecret or ClientAssertion, not both: a client authenticates with one method")
	}
	if auth.assertion != "" {
		if auth.method != "" {
			return nil, NewValidationError("ClientAuthMethod applies to a ClientSecret, not to a ClientAssertion")
		}
		form.Set("client_id", auth.clientID)
		form.Set("client_assertion_type", ClientAssertionType)
		form.Set("client_assertion", auth.assertion)
		return nil, nil
	}
	method := auth.method
	if method == "" {
		method = auth.defaultMethod
	}
	switch method {
	case ClientSecretBasic:
		return &basicCredentials{id: auth.clientID, secret: auth.secret}, nil
	case ClientSecretPost:
		form.Set("client_id", auth.clientID)
		form.Set("client_secret", auth.secret)
		return nil, nil
	default:
		return nil, validationErrorf("ClientAuthMethod %q is not supported: use ClientSecretBasic or ClientSecretPost", method)
	}
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

// EndSessionURLParams describes an RP-initiated logout (OpenID Connect
// RP-Initiated Logout 1.0) at the organization's end-session endpoint.
type EndSessionURLParams struct {
	// IDTokenHint is the last ID token that LumoAuth issued to your client
	// for this user; an expired one is accepted. With it, LumoAuth ends the
	// session at once and honours PostLogoutRedirectURI. Without it, the
	// user confirms the sign-out on a LumoAuth page and stays there.
	IDTokenHint string
	// PostLogoutRedirectURI is where LumoAuth sends the browser afterwards.
	// It must be an absolute URL registered on the client as a post-logout
	// redirect URI.
	PostLogoutRedirectURI string
	// State is passed back to PostLogoutRedirectURI unchanged.
	State string
}

// EndSessionURL builds the address to send a browser to so that it signs
// out of LumoAuth as well (the discovery document's end_session_endpoint).
// Clear your own session first. WebAuth's logout route does this for you.
//
//	logout, err := client.Auth.EndSessionURL(lumoauth.EndSessionURLParams{
//	    IDTokenHint:           tokens.IDToken,
//	    PostLogoutRedirectURI: "https://app.example.com/",
//	})
//	if err != nil {
//	    return err
//	}
//	http.Redirect(w, req, logout, http.StatusFound)
func (r *AuthResource) EndSessionURL(params EndSessionURLParams) (string, error) {
	if params.PostLogoutRedirectURI != "" {
		parsed, err := url.Parse(params.PostLogoutRedirectURI)
		if err != nil || !parsed.IsAbs() || parsed.Host == "" {
			return "", NewValidationError("PostLogoutRedirectURI must be an absolute URL, as registered on the client")
		}
	}
	logoutURL, err := r.http.routeURL(RouteOAuthLogout, nil)
	if err != nil {
		return "", err
	}
	query := url.Values{}
	if params.IDTokenHint != "" {
		query.Set("id_token_hint", params.IDTokenHint)
	}
	if params.PostLogoutRedirectURI != "" {
		query.Set("post_logout_redirect_uri", params.PostLogoutRedirectURI)
	}
	if params.State != "" {
		query.Set("state", params.State)
	}
	if len(query) == 0 {
		return logoutURL, nil
	}
	return logoutURL + "?" + query.Encode(), nil
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
//
// With a DPoP signer configured, the request carries a proof over the token
// endpoint (RFC 9449 §5). A 400 use_dpop_nonce answer is retried once with
// the DPoP-Nonce the server supplied; the nonce from any answer is kept for
// the following proofs.
func (r *AuthResource) tokenRequest(ctx context.Context, form url.Values) (*TokenResponse, error) {
	return r.tokenRequestWith(ctx, form, nil)
}

// tokenRequestWith is tokenRequest with the client authenticated by HTTP
// Basic (client_secret_basic) when basic is set. The header is the only
// credential of the request, and a DPoP proof still goes with it.
func (r *AuthResource) tokenRequestWith(ctx context.Context, form url.Values, basic *basicCredentials) (*TokenResponse, error) {
	headers := map[string]string{}
	if basic != nil {
		headers["Authorization"] = basic.header()
	}
	var token TokenResponse
	if r.http.dpop == nil {
		if err := r.http.call(ctx, RouteOAuthToken, nil, &request{Form: form, NoAuth: true, Headers: headers}, &token); err != nil {
			return nil, err
		}
		return checkTokenResponse(&token)
	}

	tokenURL, err := r.http.dpopTokenURL()
	if err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		proof, err := r.http.dpop.Proof(http.MethodPost, tokenURL)
		if err != nil {
			return nil, err
		}
		reqHeaders := map[string]string{DPoPHeader: proof}
		for k, v := range headers {
			reqHeaders[k] = v
		}
		req := &request{Form: form, NoAuth: true, Headers: reqHeaders}
		respHeaders, err := r.http.doHeaders(ctx, http.MethodPost, tokenURL, req, &token)
		if err == nil {
			return checkTokenResponse(&token)
		}
		// doRaw already remembered the DPoP-Nonce for this origin; retry
		// once when that is all the server asked for.
		if attempt == 0 && isUseDPoPNonce(err) && respHeaders.Get(DPoPNonceHeader) != "" {
			continue
		}
		return nil, err
	}
}

// checkTokenResponse rejects a 2xx token response without an access_token.
func checkTokenResponse(token *TokenResponse) (*TokenResponse, error) {
	if token.AccessToken == "" {
		return nil, NewValidationError("the token endpoint returned no access_token")
	}
	return token, nil
}

// isUseDPoPNonce reports whether err is the token endpoint's 400
// use_dpop_nonce answer (RFC 9449 §8).
func isUseDPoPNonce(err error) bool {
	apiErr, ok := AsAPIError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest && apiErr.Code == "use_dpop_nonce"
}

// tokenTypeOrDefault returns the declared RFC 8693 token type, or the
// access-token type when none was chosen.
func tokenTypeOrDefault(tokenType string) string {
	if tokenType == "" {
		return TokenTypeAccessToken
	}
	return tokenType
}
