package lumoauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

// Web sign-in: the OAuth 2.1 Authorization Code + PKCE flow, wired into
// any net/http-compatible router and backed by a signed session cookie.

// WebConfig configures NewWebAuth.
type WebConfig struct {
	// BaseURL is the LumoAuth deployment, e.g. "https://app.lumoauth.dev".
	// Defaults to $LUMOAUTH_URL, then DefaultBaseURL.
	BaseURL string
	// Organization is the tenant slug that owns the OAuth client.
	// Defaults to $LUMOAUTH_ORG_ID.
	Organization string
	// ClientID is the OAuth client registered for this app. Required.
	ClientID string
	// ClientSecret is required for confidential clients; omit for public
	// ones, which rely on PKCE alone.
	ClientSecret string
	// SessionSecret keys the cookie store. Use at least 32 random bytes,
	// and keep it stable across restarts or every session is invalidated.
	// Required.
	SessionSecret string
	// CallbackPath is the absolute path LumoAuth redirects back to. It
	// must match a redirect URI registered on the OAuth client.
	// Defaults to "/auth/callback".
	CallbackPath string
	// Scope is the space-separated scope list.
	// Defaults to "openid profile email".
	Scope string
	// PostLoginRedirect is where users land after signing in.
	// Defaults to "/".
	PostLoginRedirect string
	// PostLogoutRedirect is where users land after signing out.
	// Defaults to "/".
	PostLogoutRedirect string
	// HTTPClient overrides the client used for token exchange and
	// UserInfo. Defaults to a 10s-timeout client.
	HTTPClient *http.Client
	// CookieName is the session cookie's name. Defaults to "lumo_session".
	CookieName string
	// CookieSecure controls the Secure flag. Nil means true — the cookie
	// is only sent over HTTPS. Set Bool(false) for local development over
	// plain HTTP, and leave it alone in production.
	CookieSecure *bool
	// SessionMaxAge bounds the session cookie's lifetime.
	// Defaults to 30 days.
	SessionMaxAge time.Duration
	// SkipCertValidation disables TLS verification. Local development only.
	SkipCertValidation bool
}

// Bool returns a pointer to b — for optional *bool fields such as
// WebConfig.CookieSecure.
func Bool(b bool) *bool { return &b }

// User is the signed-in principal, as returned by the UserInfo endpoint.
type User struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
}

// SessionTokens are the OAuth tokens held for a signed-in user.
type SessionTokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Scope        string    `json:"scope,omitempty"`
}

// Expired reports whether the access token has passed its expiry. Tokens
// with no known expiry never report expired.
func (t *SessionTokens) Expired() bool {
	return !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)
}

// WebAuth drives the browser sign-in flow.
type WebAuth struct {
	cfg    WebConfig
	store  sessions.Store
	client *Client
}

// NewWebAuth validates configuration and returns a usable WebAuth.
func NewWebAuth(cfg WebConfig) (*WebAuth, error) {
	cfg.BaseURL = strings.TrimRight(
		firstNonEmpty(cfg.BaseURL, os.Getenv(EnvBaseURL), DefaultBaseURL), "/")
	cfg.Organization = firstNonEmpty(cfg.Organization, os.Getenv(EnvOrgID))

	if cfg.Organization == "" {
		return nil, NewConfigError("Organization is required (or set LUMOAUTH_ORG_ID)")
	}
	if cfg.ClientID == "" {
		return nil, NewConfigError("ClientID is required")
	}
	if cfg.SessionSecret == "" {
		return nil, NewConfigError("SessionSecret is required (use at least 32 random bytes)")
	}
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = "/auth/callback"
	}
	if cfg.Scope == "" {
		cfg.Scope = "openid profile email"
	}
	if cfg.PostLoginRedirect == "" {
		cfg.PostLoginRedirect = "/"
	}
	if cfg.PostLogoutRedirect == "" {
		cfg.PostLogoutRedirect = "/"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "lumo_session"
	}
	if cfg.SessionMaxAge <= 0 {
		cfg.SessionMaxAge = 30 * 24 * time.Hour
	}

	// Secure cookies by default; callers serving plain HTTP locally opt
	// out with CookieSecure: lumoauth.Bool(false).
	cookieSecure := true
	if cfg.CookieSecure != nil {
		cookieSecure = *cfg.CookieSecure
	}

	store := sessions.NewCookieStore([]byte(cfg.SessionSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(cfg.SessionMaxAge / time.Second),
	}

	client := newClient(&clientConfig{
		baseURL:            cfg.BaseURL,
		orgID:              cfg.Organization,
		httpClient:         cfg.HTTPClient,
		skipCertValidation: cfg.SkipCertValidation,
		userAgent:          userAgent(),
	})

	return &WebAuth{cfg: cfg, store: store, client: client}, nil
}

// Client returns a LumoAuth client bound to this deployment and org, for
// calls made outside the sign-in flow. It carries no user credentials —
// use ClientForRequest for those.
func (w *WebAuth) Client() *Client { return w.client }

// ClientForRequest returns a client authenticated as the signed-in user of
// this request, so authorization checks run under their identity:
//
//	client, err := auth.ClientForRequest(req)
//	if err != nil {
//	    return err
//	}
//	ok, err := client.Permissions.Check(req.Context(), "document.edit", nil)
func (w *WebAuth) ClientForRequest(req *http.Request) (*Client, error) {
	tokens := TokensFromContext(req.Context())
	if tokens == nil {
		var err error
		if tokens, err = w.Tokens(req); err != nil {
			return nil, err
		}
	}
	if tokens == nil || tokens.AccessToken == "" {
		return nil, NewConfigError("no signed-in user on this request")
	}

	accessToken := tokens.AccessToken
	return newClient(&clientConfig{
		baseURL:            w.cfg.BaseURL,
		orgID:              w.cfg.Organization,
		tokenProvider:      func(context.Context) (string, error) { return accessToken, nil },
		httpClient:         w.cfg.HTTPClient,
		skipCertValidation: w.cfg.SkipCertValidation,
		userAgent:          userAgent(),
	}), nil
}

// Router serves the sign-in endpoints: login, callback, and logout.
//
// The paths come from CallbackPath, so the default "/auth/callback" gives
// /auth/login, /auth/callback, and /auth/logout. Mount it at that prefix:
//
//	mux := http.NewServeMux()
//	mux.Handle("/auth/", auth.Router())
//
// It returns a plain http.Handler, so it mounts into chi, gorilla/mux, or
// net/http alike. The bare /login, /callback, and /logout paths are also
// registered, so mounting behind http.StripPrefix works too.
func (w *WebAuth) Router() http.Handler {
	mux := http.NewServeMux()

	handlers := map[string]http.HandlerFunc{
		"/login":    w.handleLogin,
		"/callback": w.handleCallback,
		"/logout":   w.handleLogout,
	}

	// Register under the callback's own prefix and bare, so the router
	// behaves the same mounted directly or behind StripPrefix.
	prefix := path.Dir(w.cfg.CallbackPath)
	if prefix == "/" || prefix == "." {
		prefix = ""
	}

	registered := map[string]bool{}
	register := func(pattern string, handler http.HandlerFunc) {
		if pattern == "" || registered[pattern] {
			return
		}
		registered[pattern] = true
		mux.HandleFunc(pattern, handler)
	}

	for suffix, handler := range handlers {
		register(prefix+suffix, handler)
		register(suffix, handler)
	}
	// A callback path that does not end in /callback still resolves.
	register(w.cfg.CallbackPath, w.handleCallback)

	return mux
}

// LoginHandler starts the sign-in flow. Mount it directly when you would
// rather wire routes yourself than mount Router.
func (w *WebAuth) LoginHandler() http.HandlerFunc { return w.handleLogin }

// CallbackHandler completes the sign-in flow.
func (w *WebAuth) CallbackHandler() http.HandlerFunc { return w.handleCallback }

// LogoutHandler clears the session.
func (w *WebAuth) LogoutHandler() http.HandlerFunc { return w.handleLogout }

// ── Route handlers ────────────────────────────────────────────────────

func (w *WebAuth) handleLogin(rw http.ResponseWriter, req *http.Request) {
	verifier, challenge, err := pkcePair()
	if err != nil {
		http.Error(rw, "could not start login: "+err.Error(), http.StatusInternalServerError)
		return
	}
	state, err := randomToken(32)
	if err != nil {
		http.Error(rw, "could not start login: "+err.Error(), http.StatusInternalServerError)
		return
	}

	returnTo := sanitizeReturnTo(req.URL.Query().Get("return_to"), w.cfg.PostLoginRedirect)
	redirectURI := absoluteURL(req, w.cfg.CallbackPath)

	session := w.session(req)
	session.Values[sessionKeyFlow] = mustEncode(flowState{
		Verifier:    verifier,
		State:       state,
		RedirectURI: redirectURI,
		ReturnTo:    returnTo,
	})
	if err := session.Save(req, rw); err != nil {
		http.Error(rw, "could not save the session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	authorizeURL, err := w.client.Auth.AuthorizationURL(AuthorizationURLParams{
		ClientID:            w.cfg.ClientID,
		RedirectURI:         redirectURI,
		Scope:               w.cfg.Scope,
		State:               state,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		http.Error(rw, "could not build the authorization URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, req, authorizeURL, http.StatusFound)
}

func (w *WebAuth) handleCallback(rw http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	if errCode := query.Get("error"); errCode != "" {
		http.Error(rw, errCode+": "+query.Get("error_description"), http.StatusBadRequest)
		return
	}
	code := query.Get("code")
	state := query.Get("state")
	if code == "" || state == "" {
		http.Error(rw, "missing code or state", http.StatusBadRequest)
		return
	}

	session := w.session(req)
	rawFlow, _ := session.Values[sessionKeyFlow].(string)
	if rawFlow == "" {
		http.Error(rw, "no login in progress", http.StatusBadRequest)
		return
	}
	var flow flowState
	if err := json.Unmarshal([]byte(rawFlow), &flow); err != nil {
		http.Error(rw, "corrupt session", http.StatusBadRequest)
		return
	}
	// Constant-time-ish comparison is unnecessary here: the state is a
	// random value the attacker would have to guess in one shot, and a
	// mismatch reveals nothing about it.
	if state != flow.State {
		http.Error(rw, "CSRF state mismatch", http.StatusBadRequest)
		return
	}

	token, err := w.client.Auth.ExchangeCode(req.Context(), ExchangeCodeParams{
		Code:         code,
		RedirectURI:  flow.RedirectURI,
		ClientID:     w.cfg.ClientID,
		ClientSecret: w.cfg.ClientSecret,
		CodeVerifier: flow.Verifier,
	})
	if err != nil {
		http.Error(rw, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	info, err := w.client.Auth.UserInfo(req.Context(), token.AccessToken)
	if err != nil {
		http.Error(rw, "userinfo failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	delete(session.Values, sessionKeyFlow)
	session.Values[sessionKeyUser] = mustEncode(userFromInfo(info))
	session.Values[sessionKeyTokens] = mustEncode(tokensFromResponse(token))
	if err := session.Save(req, rw); err != nil {
		http.Error(rw, "could not save the session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(rw, req, flow.ReturnTo, http.StatusFound)
}

func (w *WebAuth) handleLogout(rw http.ResponseWriter, req *http.Request) {
	session := w.session(req)

	// Best-effort server-side revocation before dropping local state: a
	// failure here must not strand the user in a session they asked to end.
	if raw, ok := session.Values[sessionKeyTokens].(string); ok && raw != "" {
		var tokens SessionTokens
		if json.Unmarshal([]byte(raw), &tokens) == nil && tokens.RefreshToken != "" {
			_ = w.client.Auth.Revoke(req.Context(), RevokeParams{
				Token:         tokens.RefreshToken,
				TokenTypeHint: "refresh_token",
				ClientID:      w.cfg.ClientID,
				ClientSecret:  w.cfg.ClientSecret,
			})
		}
	}

	delete(session.Values, sessionKeyUser)
	delete(session.Values, sessionKeyTokens)
	delete(session.Values, sessionKeyFlow)
	session.Options.MaxAge = -1 // expire the cookie
	_ = session.Save(req, rw)

	http.Redirect(rw, req, w.cfg.PostLogoutRedirect, http.StatusFound)
}

// ── Middleware ────────────────────────────────────────────────────────

type userContextKey struct{}
type tokensContextKey struct{}

// Middleware reads the signed-in user from the session and attaches the
// user and their tokens to the request context. It does NOT enforce
// authentication — compose it with RequireAuth to gate a route.
func (w *WebAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session := w.session(req)
		ctx := req.Context()

		if raw, ok := session.Values[sessionKeyUser].(string); ok && raw != "" {
			var user User
			if json.Unmarshal([]byte(raw), &user) == nil {
				ctx = context.WithValue(ctx, userContextKey{}, &user)
			}
		}
		if raw, ok := session.Values[sessionKeyTokens].(string); ok && raw != "" {
			var tokens SessionTokens
			if json.Unmarshal([]byte(raw), &tokens) == nil {
				ctx = context.WithValue(ctx, tokensContextKey{}, &tokens)
			}
		}

		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

// RequireAuth gates a handler on a signed-in user, answering 401 when
// there is none. It must run inside Middleware, which is what puts the
// user on the context.
func (w *WebAuth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if UserFromContext(req.Context()) == nil {
			http.Error(rw, "unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(rw, req)
	})
}

// RequireAuthRedirect gates a handler on a signed-in user, sending anyone
// else to loginPath with a return_to pointing back here — the right
// behaviour for HTML pages, where RequireAuth's bare 401 is not.
func (w *WebAuth) RequireAuthRedirect(loginPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if UserFromContext(req.Context()) == nil {
				target := loginPath + "?return_to=" + url.QueryEscape(req.URL.RequestURI())
				http.Redirect(rw, req, target, http.StatusFound)
				return
			}
			next.ServeHTTP(rw, req)
		})
	}
}

// UserFromContext returns the signed-in user for a request, or nil when
// the request is unauthenticated.
func UserFromContext(ctx context.Context) *User {
	user, _ := ctx.Value(userContextKey{}).(*User)
	return user
}

// TokensFromContext returns the signed-in user's OAuth tokens, or nil.
func TokensFromContext(ctx context.Context) *SessionTokens {
	tokens, _ := ctx.Value(tokensContextKey{}).(*SessionTokens)
	return tokens
}

// ── Session access ────────────────────────────────────────────────────

// User reads the signed-in user straight from the request's session,
// without requiring Middleware. It returns nil when nobody is signed in.
func (w *WebAuth) User(req *http.Request) (*User, error) {
	session := w.session(req)
	raw, _ := session.Values[sessionKeyUser].(string)
	if raw == "" {
		return nil, nil
	}
	var user User
	if err := json.Unmarshal([]byte(raw), &user); err != nil {
		return nil, NewValidationError("could not decode the session user: " + err.Error())
	}
	return &user, nil
}

// Tokens reads the signed-in user's OAuth tokens from the session.
func (w *WebAuth) Tokens(req *http.Request) (*SessionTokens, error) {
	session := w.session(req)
	raw, _ := session.Values[sessionKeyTokens].(string)
	if raw == "" {
		return nil, nil
	}
	var tokens SessionTokens
	if err := json.Unmarshal([]byte(raw), &tokens); err != nil {
		return nil, NewValidationError("could not decode the session tokens: " + err.Error())
	}
	return &tokens, nil
}

// RefreshSession renews an expired access token using the stored refresh
// token and writes the result back to the session. It reports whether a
// refresh actually happened.
func (w *WebAuth) RefreshSession(rw http.ResponseWriter, req *http.Request) (bool, error) {
	tokens, err := w.Tokens(req)
	if err != nil {
		return false, err
	}
	if tokens == nil || tokens.RefreshToken == "" || !tokens.Expired() {
		return false, nil
	}

	refreshed, err := w.client.Auth.RefreshToken(req.Context(), RefreshTokenParams{
		RefreshToken: tokens.RefreshToken,
		ClientID:     w.cfg.ClientID,
		ClientSecret: w.cfg.ClientSecret,
	})
	if err != nil {
		return false, err
	}

	updated := tokensFromResponse(refreshed)
	if updated.RefreshToken == "" {
		updated.RefreshToken = tokens.RefreshToken // not rotated
	}

	session := w.session(req)
	session.Values[sessionKeyTokens] = mustEncode(updated)
	if err := session.Save(req, rw); err != nil {
		return false, NewValidationError("could not save the refreshed session: " + err.Error())
	}
	return true, nil
}

// ── Internal ──────────────────────────────────────────────────────────

// Session keys. They are namespaced so an app sharing the cookie store for
// its own values cannot collide with the SDK's.
const (
	sessionKeyFlow   = "lumo_flow"
	sessionKeyUser   = "lumo_user"
	sessionKeyTokens = "lumo_tokens"
)

func (w *WebAuth) session(req *http.Request) *sessions.Session {
	// A decode failure (rotated secret, tampered cookie) still yields a
	// usable new session, so the user can simply sign in again.
	session, _ := w.store.Get(req, w.cfg.CookieName)
	return session
}

// flowState is the per-login state carried across the redirect.
type flowState struct {
	Verifier    string `json:"v"`
	State       string `json:"s"`
	RedirectURI string `json:"r"`
	ReturnTo    string `json:"t"`
}

func userFromInfo(info *UserInfo) User {
	return User{
		Sub:           info.Sub,
		Email:         info.Email,
		EmailVerified: info.EmailVerified,
		Name:          info.Name,
		GivenName:     info.GivenName,
		FamilyName:    info.FamilyName,
		Picture:       info.Picture,
	}
}

func tokensFromResponse(token *TokenResponse) SessionTokens {
	tokens := SessionTokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      token.IDToken,
		TokenType:    token.TokenType,
		Scope:        token.Scope,
	}
	if token.ExpiresIn > 0 {
		tokens.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	return tokens
}

// pkcePair generates an RFC 7636 verifier and its S256 challenge.
func pkcePair() (verifier, challenge string, err error) {
	raw, err := randomBytes(48)
	if err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func randomToken(byteLen int) (string, error) {
	raw, err := randomBytes(byteLen)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, newError(ErrLumoAuth, CodeError,
			"could not read random bytes: "+err.Error())
	}
	return buf, nil
}

// absoluteURL rebuilds this request's origin plus a path, honouring the
// forwarding headers a proxy or load balancer sets.
func absoluteURL(req *http.Request, path string) string {
	scheme := "https"
	if forwarded := req.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	} else if req.TLS == nil {
		scheme = "http"
	}
	host := req.Host
	if forwarded := req.Header.Get("X-Forwarded-Host"); forwarded != "" {
		host = forwarded
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

// sanitizeReturnTo blocks open redirects through the return_to parameter:
// only same-origin absolute paths are allowed.
func sanitizeReturnTo(value, fallback string) string {
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return fallback
	}
	// "/\evil.com" is treated as protocol-relative by some browsers.
	if strings.HasPrefix(value, `/\`) {
		return fallback
	}
	return value
}

func mustEncode(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}
