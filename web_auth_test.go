package lumoauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testSessionSecret = "test-session-secret-at-least-32-bytes-long"

// webAuthServer stands in for LumoAuth during the sign-in flow.
type webAuthServer struct {
	t *testing.T

	codeForms    []url.Values
	refreshForms []url.Values
	revokeForms  []url.Values

	accessTokenExpiresIn int
	userInfoStatus       int
}

func (s *webAuthServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			_ = r.ParseForm()
			expiresIn := s.accessTokenExpiresIn
			if expiresIn == 0 {
				expiresIn = 3600
			}
			switch r.Form.Get("grant_type") {
			case "authorization_code":
				s.codeForms = append(s.codeForms, r.Form)
				writeJSON(w, 200, map[string]any{
					"access_token":  "access-token",
					"refresh_token": "refresh-token",
					"id_token":      "id-token",
					"token_type":    "Bearer",
					"expires_in":    expiresIn,
					"scope":         "openid profile email",
				})
			case "refresh_token":
				s.refreshForms = append(s.refreshForms, r.Form)
				writeJSON(w, 200, map[string]any{
					"access_token": "access-token-2", "expires_in": expiresIn,
				})
			default:
				s.t.Errorf("unexpected grant_type %q", r.Form.Get("grant_type"))
			}

		case strings.HasSuffix(r.URL.Path, "/oauth/revoke"):
			_ = r.ParseForm()
			s.revokeForms = append(s.revokeForms, r.Form)
			w.WriteHeader(http.StatusNoContent)

		case strings.HasSuffix(r.URL.Path, "/oauth/userinfo"):
			if s.userInfoStatus != 0 {
				writeJSON(w, s.userInfoStatus, map[string]any{"error": "invalid_token"})
				return
			}
			writeJSON(w, 200, map[string]any{
				"sub": "user_1", "email": "ada@acme.com", "email_verified": true,
				"name": "Ada Lovelace",
			})

		default:
			s.t.Errorf("unexpected path %q", r.URL.Path)
		}
	}
}

func newTestWebAuth(t *testing.T, state *webAuthServer) (*WebAuth, *httptest.Server) {
	t.Helper()
	state.t = t

	server := httptest.NewServer(state.handler())
	t.Cleanup(server.Close)

	auth, err := NewWebAuth(WebConfig{
		BaseURL:       server.URL,
		Organization:  "acme-corp",
		ClientID:      "web-client",
		ClientSecret:  "web-secret",
		SessionSecret: testSessionSecret,
		CookieSecure:  Bool(false),
	})
	if err != nil {
		t.Fatalf("NewWebAuth: %v", err)
	}
	return auth, server
}

func TestNewWebAuthValidation(t *testing.T) {
	t.Setenv(EnvOrgID, "")

	cases := []struct {
		name string
		cfg  WebConfig
	}{
		{"no organization", WebConfig{ClientID: "c", SessionSecret: testSessionSecret}},
		{"no client ID", WebConfig{Organization: "acme", SessionSecret: testSessionSecret}},
		{"no session secret", WebConfig{Organization: "acme", ClientID: "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewWebAuth(tc.cfg); !errors.Is(err, ErrConfig) {
				t.Errorf("expected a config error, got %v", err)
			}
		})
	}
}

func TestNewWebAuthDefaults(t *testing.T) {
	auth, err := NewWebAuth(WebConfig{
		Organization: "acme", ClientID: "c", SessionSecret: testSessionSecret,
	})
	if err != nil {
		t.Fatalf("NewWebAuth: %v", err)
	}
	if auth.cfg.CallbackPath != "/auth/callback" {
		t.Errorf("CallbackPath = %q", auth.cfg.CallbackPath)
	}
	if auth.cfg.Scope != "openid profile email" {
		t.Errorf("Scope = %q", auth.cfg.Scope)
	}
	if auth.cfg.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q", auth.cfg.BaseURL)
	}
	if auth.cfg.CookieName != "lumo_session" {
		t.Errorf("CookieName = %q", auth.cfg.CookieName)
	}
}

func TestWebAuthLoginRedirect(t *testing.T) {
	auth, server := newTestWebAuth(t, &webAuthServer{})

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/login", nil)
	rec := httptest.NewRecorder()
	auth.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}

	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), server.URL) {
		t.Errorf("the redirect should point at LumoAuth: %q", rec.Header().Get("Location"))
	}
	if location.Path != "/orgs/acme-corp/api/v1/oauth/authorize" {
		t.Errorf("path = %q", location.Path)
	}

	query := location.Query()
	if query.Get("client_id") != "web-client" {
		t.Errorf("client_id = %q", query.Get("client_id"))
	}
	if query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		t.Errorf("the login flow must use PKCE: %v", query)
	}
	if query.Get("state") == "" {
		t.Error("the login flow must set a state parameter")
	}
	// The callback URI is derived from the incoming request's origin.
	if query.Get("redirect_uri") != "http://app.example.com/auth/callback" {
		t.Errorf("redirect_uri = %q", query.Get("redirect_uri"))
	}

	// The flow state rides in the session cookie.
	if len(rec.Result().Cookies()) == 0 {
		t.Error("the login handler should set a session cookie")
	}
}

func TestWebAuthLoginHonoursForwardingHeaders(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})

	req := httptest.NewRequest(http.MethodGet, "http://internal:8080/auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")

	rec := httptest.NewRecorder()
	auth.Router().ServeHTTP(rec, req)

	location, _ := url.Parse(rec.Header().Get("Location"))
	if got := location.Query().Get("redirect_uri"); got != "https://app.example.com/auth/callback" {
		t.Errorf("redirect_uri = %q — the proxy's headers should win", got)
	}
}

// completeLogin drives login + callback and returns the resulting session
// cookies.
func completeLogin(t *testing.T, auth *WebAuth) []*http.Cookie {
	t.Helper()

	loginReq := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/login", nil)
	loginRec := httptest.NewRecorder()
	auth.Router().ServeHTTP(loginRec, loginReq)

	location, _ := url.Parse(loginRec.Header().Get("Location"))
	state := location.Query().Get("state")

	callbackReq := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/auth/callback?code=auth-code&state="+url.QueryEscape(state), nil)
	for _, cookie := range loginRec.Result().Cookies() {
		callbackReq.AddCookie(cookie)
	}
	callbackRec := httptest.NewRecorder()
	auth.Router().ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback status = %d (%s)", callbackRec.Code, callbackRec.Body.String())
	}
	return callbackRec.Result().Cookies()
}

func TestWebAuthCallbackEstablishesASession(t *testing.T) {
	state := &webAuthServer{}
	auth, _ := newTestWebAuth(t, state)

	cookies := completeLogin(t, auth)

	if len(state.codeForms) != 1 {
		t.Fatalf("the authorization code was not exchanged")
	}
	form := state.codeForms[0]
	if form.Get("code") != "auth-code" {
		t.Errorf("code = %q", form.Get("code"))
	}
	if form.Get("code_verifier") == "" {
		t.Error("the PKCE verifier must be sent with the exchange")
	}
	if form.Get("client_secret") != "web-secret" {
		t.Error("a confidential client must authenticate with its secret")
	}

	// The session now carries the user and their tokens.
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	user, err := auth.User(req)
	if err != nil {
		t.Fatalf("User: %v", err)
	}
	if user == nil || user.Email != "ada@acme.com" || user.Sub != "user_1" {
		t.Errorf("user = %+v", user)
	}

	tokens, err := auth.Tokens(req)
	if err != nil {
		t.Fatalf("Tokens: %v", err)
	}
	if tokens == nil || tokens.AccessToken != "access-token" || tokens.RefreshToken != "refresh-token" {
		t.Errorf("tokens = %+v", tokens)
	}
	if tokens.Expired() {
		t.Error("a fresh token should not report expired")
	}
}

func TestWebAuthCallbackRejectsCSRF(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})

	loginReq := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/login", nil)
	loginRec := httptest.NewRecorder()
	auth.Router().ServeHTTP(loginRec, loginReq)

	// An attacker-supplied state must not be accepted.
	callbackReq := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/auth/callback?code=auth-code&state=attacker-state", nil)
	for _, cookie := range loginRec.Result().Cookies() {
		callbackReq.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	auth.Router().ServeHTTP(rec, callbackReq)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a state mismatch", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "CSRF") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestWebAuthCallbackRequiresALoginInProgress(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})

	// No session cookie at all.
	req := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/auth/callback?code=c&state=s", nil)
	rec := httptest.NewRecorder()
	auth.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestWebAuthCallbackSurfacesProviderErrors(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})

	req := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/auth/callback?error=access_denied&error_description=user+said+no", nil)
	rec := httptest.NewRecorder()
	auth.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "access_denied") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestWebAuthMiddlewareAndGuards(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})
	cookies := completeLogin(t, auth)

	var seenUser *User
	var seenTokens *SessionTokens
	protected := auth.Middleware(auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			seenUser = UserFromContext(r.Context())
			seenTokens = TokensFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})))

	t.Run("signed in", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if seenUser == nil || seenUser.Email != "ada@acme.com" {
			t.Errorf("the user should be on the context: %+v", seenUser)
		}
		if seenTokens == nil || seenTokens.AccessToken != "access-token" {
			t.Errorf("the tokens should be on the context: %+v", seenTokens)
		}
	})

	t.Run("anonymous", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("redirect guard sends anonymous users to login", func(t *testing.T) {
		handler := auth.Middleware(auth.RequireAuthRedirect("/auth/login")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))

		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard?tab=1", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		location := rec.Header().Get("Location")
		if !strings.HasPrefix(location, "/auth/login?return_to=") {
			t.Errorf("Location = %q", location)
		}
		if !strings.Contains(location, url.QueryEscape("/dashboard?tab=1")) {
			t.Errorf("the guard should preserve where the user was going: %q", location)
		}
	})
}

func TestWebAuthLogout(t *testing.T) {
	state := &webAuthServer{}
	auth, _ := newTestWebAuth(t, state)
	cookies := completeLogin(t, auth)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/logout", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	auth.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}

	// The refresh token is revoked server-side, not just dropped locally.
	if len(state.revokeForms) != 1 {
		t.Fatalf("revocations = %d, want 1", len(state.revokeForms))
	}
	if state.revokeForms[0].Get("token") != "refresh-token" {
		t.Errorf("revoked token = %q", state.revokeForms[0].Get("token"))
	}

	// The session is gone.
	after := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	for _, cookie := range rec.Result().Cookies() {
		after.AddCookie(cookie)
	}
	user, err := auth.User(after)
	if err != nil {
		t.Fatalf("User: %v", err)
	}
	if user != nil {
		t.Errorf("the session should be cleared, got %+v", user)
	}
}

func TestWebAuthRefreshSession(t *testing.T) {
	state := &webAuthServer{}
	auth, _ := newTestWebAuth(t, state)
	cookies := completeLogin(t, auth)

	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		return req
	}

	// A live token is left alone.
	rec := httptest.NewRecorder()
	refreshed, err := auth.RefreshSession(rec, newRequest())
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if refreshed {
		t.Error("a valid token should not be refreshed")
	}
	if len(state.refreshForms) != 0 {
		t.Errorf("refreshes = %d, want 0", len(state.refreshForms))
	}

	// An expired one is renewed. Sign a session whose token has already
	// lapsed, which is otherwise unreachable inside one test run.
	expiredReq := newRequest()
	session := auth.session(expiredReq)
	session.Values[sessionKeyTokens] = mustEncode(SessionTokens{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(-time.Minute),
	})
	expiredRec := httptest.NewRecorder()
	if err := session.Save(expiredReq, expiredRec); err != nil {
		t.Fatalf("saving the session: %v", err)
	}

	staleReq := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	for _, cookie := range expiredRec.Result().Cookies() {
		staleReq.AddCookie(cookie)
	}

	rec = httptest.NewRecorder()
	refreshed, err = auth.RefreshSession(rec, staleReq)
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if !refreshed {
		t.Fatal("an expired token should be refreshed")
	}
	if len(state.refreshForms) != 1 {
		t.Fatalf("refreshes = %d, want 1", len(state.refreshForms))
	}

	// The refreshed token is written back, and the non-rotated refresh
	// token is retained.
	updatedReq := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	for _, cookie := range rec.Result().Cookies() {
		updatedReq.AddCookie(cookie)
	}
	tokens, err := auth.Tokens(updatedReq)
	if err != nil {
		t.Fatalf("Tokens: %v", err)
	}
	if tokens.AccessToken != "access-token-2" {
		t.Errorf("AccessToken = %q, want the refreshed one", tokens.AccessToken)
	}
	if tokens.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken = %q — a non-rotated refresh token must be kept", tokens.RefreshToken)
	}
}

func TestWebAuthClientForRequest(t *testing.T) {
	state := &webAuthServer{}
	auth, _ := newTestWebAuth(t, state)
	cookies := completeLogin(t, auth)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	client, err := auth.ClientForRequest(req)
	if err != nil {
		t.Fatalf("ClientForRequest: %v", err)
	}

	// The client authenticates as the signed-in user.
	var seen string
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		writeJSON(w, 200, map[string]any{"allowed": true})
	}))
	defer probe.Close()

	client.http.baseURL = probe.URL
	if _, err := client.Permissions.Check(context.Background(), "document.edit", nil); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if seen != "Bearer access-token" {
		t.Errorf("Authorization = %q, want the session's access token", seen)
	}

	// Anonymous requests get a clear error instead of an unauthenticated
	// client that would 401 later.
	if _, err := auth.ClientForRequest(httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)); !errors.Is(err, ErrConfig) {
		t.Errorf("expected a config error for an anonymous request, got %v", err)
	}
}

func TestSanitizeReturnTo(t *testing.T) {
	const fallback = "/"

	cases := []struct {
		value string
		want  string
	}{
		{"/dashboard", "/dashboard"},
		{"/dashboard?tab=1", "/dashboard?tab=1"},
		{"", fallback},
		{"https://evil.com", fallback},     // absolute URL
		{"//evil.com", fallback},           // protocol-relative
		{`/\evil.com`, fallback},           // backslash trick
		{"http://evil.com/path", fallback}, // absolute with scheme
		{"javascript:alert(1)", fallback},  // scheme injection
	}

	for _, tc := range cases {
		if got := sanitizeReturnTo(tc.value, fallback); got != tc.want {
			t.Errorf("sanitizeReturnTo(%q) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

func TestWebAuthLoginRespectsReturnTo(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})

	// A same-origin path is preserved through the flow.
	loginReq := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/auth/login?return_to=/dashboard", nil)
	loginRec := httptest.NewRecorder()
	auth.Router().ServeHTTP(loginRec, loginReq)

	location, _ := url.Parse(loginRec.Header().Get("Location"))
	state := location.Query().Get("state")

	callbackReq := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/auth/callback?code=c&state="+url.QueryEscape(state), nil)
	for _, cookie := range loginRec.Result().Cookies() {
		callbackReq.AddCookie(cookie)
	}
	callbackRec := httptest.NewRecorder()
	auth.Router().ServeHTTP(callbackRec, callbackReq)

	if got := callbackRec.Header().Get("Location"); got != "/dashboard" {
		t.Errorf("post-login redirect = %q, want /dashboard", got)
	}
}

func TestWebAuthOpenRedirectIsBlockedEndToEnd(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})

	loginReq := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/auth/login?return_to=https://evil.com/steal", nil)
	loginRec := httptest.NewRecorder()
	auth.Router().ServeHTTP(loginRec, loginReq)

	location, _ := url.Parse(loginRec.Header().Get("Location"))
	state := location.Query().Get("state")

	callbackReq := httptest.NewRequest(http.MethodGet,
		"http://app.example.com/auth/callback?code=c&state="+url.QueryEscape(state), nil)
	for _, cookie := range loginRec.Result().Cookies() {
		callbackReq.AddCookie(cookie)
	}
	callbackRec := httptest.NewRecorder()
	auth.Router().ServeHTTP(callbackRec, callbackReq)

	if got := callbackRec.Header().Get("Location"); got != "/" {
		t.Errorf("post-login redirect = %q — an off-site return_to must be dropped", got)
	}
}

func TestWebAuthCookieFlags(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/login", nil)
	rec := httptest.NewRecorder()
	auth.Router().ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie was set")
	}
	cookie := cookies[0]

	if !cookie.HttpOnly {
		t.Error("the session cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
	// This instance opted out of Secure for local HTTP.
	if cookie.Secure {
		t.Error("CookieSecure(false) should have been honoured")
	}
}

func TestWebAuthSecureCookiesByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	auth, err := NewWebAuth(WebConfig{
		BaseURL: server.URL, Organization: "acme-corp",
		ClientID: "c", SessionSecret: testSessionSecret,
	})
	if err != nil {
		t.Fatalf("NewWebAuth: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/auth/login", nil)
	rec := httptest.NewRecorder()
	auth.Router().ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie was set")
	}
	if !cookies[0].Secure {
		t.Error("session cookies must be Secure unless the caller opts out")
	}
}
