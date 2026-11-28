package lumoauth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// fakeJWT returns a random token of the given length with the look of a JWT.
// Random content does not compress, as the base64 parts of a real JWT.
func fakeJWT(t *testing.T, length int) string {
	t.Helper()
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)[:length]
	return token[:length/3] + "." + token[length/3+1:2*length/3] + "." + token[2*length/3+1:]
}

// requestWith returns a GET request that carries the cookies.
func requestWith(cookies []*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	return req
}

// liveCookies drops the cookies that a response deletes.
func liveCookies(cookies []*http.Cookie) []*http.Cookie {
	var live []*http.Cookie
	for _, cookie := range cookies {
		if cookie.MaxAge >= 0 && cookie.Value != "" {
			live = append(live, cookie)
		}
	}
	return live
}

func TestWebAuthSessionFitsWithTokensOfARealSize(t *testing.T) {
	// The dev server's tokens for the default scopes "openid profile email"
	// are 999 (access) and 923 (ID) characters; an organization with custom
	// claims has larger ones. One signed cookie holds at most 4096 bytes.
	state := &webAuthServer{accessToken: fakeJWT(t, 1800), idToken: fakeJWT(t, 1500)}
	auth, _ := newTestWebAuth(t, state)

	cookies := completeLogin(t, auth)

	if len(cookies) < 2 {
		t.Fatalf("expected the session to be split over several cookies, got %d", len(cookies))
	}
	for _, cookie := range cookies {
		if size := len(cookie.Name) + 1 + len(cookie.Value); size > 4096 {
			t.Errorf("cookie %s is %d bytes, more than a browser keeps", cookie.Name, size)
		}
		if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie %s lost its flags: %+v", cookie.Name, cookie)
		}
	}

	tokens, err := auth.Tokens(requestWith(cookies))
	if err != nil {
		t.Fatalf("Tokens: %v", err)
	}
	if tokens == nil || tokens.AccessToken != state.accessToken || tokens.IDToken != state.idToken {
		t.Fatalf("the tokens did not survive the round trip: %+v", tokens)
	}
	user, err := auth.User(requestWith(cookies))
	if err != nil || user == nil || user.Email != "ada@acme.com" {
		t.Fatalf("User = %+v, %v", user, err)
	}
}

func TestWebAuthSessionCookieIsEncrypted(t *testing.T) {
	state := &webAuthServer{accessToken: fakeJWT(t, 900), idToken: fakeJWT(t, 900)}
	auth, _ := newTestWebAuth(t, state)

	cookies := completeLogin(t, auth)

	var joined strings.Builder
	for _, cookie := range cookies {
		joined.WriteString(cookie.Value)
	}
	// securecookie writes base64(date|base64(payload)|mac). Undo both layers
	// and look for what the session holds.
	outer, err := base64.URLEncoding.DecodeString(joined.String())
	if err != nil {
		t.Fatalf("decoding the cookie: %v", err)
	}
	parts := strings.SplitN(string(outer), "|", 3)
	if len(parts) != 3 {
		t.Fatalf("unexpected cookie layout")
	}
	payload, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding the payload: %v", err)
	}
	for _, secret := range []string{state.accessToken[:40], state.idToken[:40], "refresh-token", "ada@acme.com"} {
		if strings.Contains(string(payload), secret) || strings.Contains(joined.String(), secret) {
			t.Errorf("the cookie carries %q in readable form", secret)
		}
	}
}

func TestWebAuthReadsASessionOfTheEarlierSignedOnlyCookie(t *testing.T) {
	// Sessions written before the cookie was encrypted (a gorilla
	// CookieStore keyed with the SessionSecret) stay valid until they expire,
	// so an upgrade signs nobody out.
	auth, _ := newTestWebAuth(t, &webAuthServer{})

	legacy := sessions.NewCookieStore([]byte(testSessionSecret))
	legacy.Options = &sessions.Options{Path: "/", HttpOnly: true, MaxAge: 3600}
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	session, _ := legacy.New(req, "lumo_session")
	session.Values[sessionKeyUser] = mustEncode(User{Sub: "user_1", Email: "ada@acme.com"})
	session.Values[sessionKeyTokens] = mustEncode(SessionTokens{AccessToken: "old-access", RefreshToken: "old-refresh"})
	rec := httptest.NewRecorder()
	if err := legacy.Save(req, rec, session); err != nil {
		t.Fatalf("saving the earlier cookie: %v", err)
	}

	user, err := auth.User(requestWith(rec.Result().Cookies()))
	if err != nil || user == nil || user.Sub != "user_1" {
		t.Fatalf("User = %+v, %v", user, err)
	}

	// The next save writes the encrypted form.
	resave := requestWith(rec.Result().Cookies())
	saved := httptest.NewRecorder()
	current := auth.session(resave)
	if err := auth.store.Save(resave, saved, current); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if strings.Contains(saved.Result().Cookies()[0].Value, rec.Result().Cookies()[0].Value) {
		t.Error("the session should be written again in the new form")
	}
}

func TestWebAuthRefusesAForgedSession(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})

	// A cookie made with another secret, signed or encrypted, is no session.
	for _, store := range []*sessions.CookieStore{
		sessions.NewCookieStore([]byte("another-secret-of-at-least-32-bytes!!")),
		sessions.NewCookieStore(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32)),
	} {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		session, _ := store.New(req, "lumo_session")
		session.Values[sessionKeyUser] = mustEncode(User{Sub: "attacker"})
		rec := httptest.NewRecorder()
		if err := store.Save(req, rec, session); err != nil {
			t.Fatal(err)
		}
		if user, _ := auth.User(requestWith(rec.Result().Cookies())); user != nil {
			t.Errorf("a forged cookie was accepted: %+v", user)
		}
	}
}

func TestWebAuthSessionShrinksAndLogoutRemovesEveryChunk(t *testing.T) {
	state := &webAuthServer{accessToken: fakeJWT(t, 3000), idToken: fakeJWT(t, 3000)}
	auth, _ := newTestWebAuth(t, state)
	cookies := completeLogin(t, auth)
	if len(cookies) < 3 {
		t.Fatalf("expected at least three chunks, got %d", len(cookies))
	}

	// A smaller session expires the chunks that it no longer needs.
	req := requestWith(cookies)
	session := auth.session(req)
	session.Values[sessionKeyTokens] = mustEncode(SessionTokens{AccessToken: "short"})
	rec := httptest.NewRecorder()
	if err := auth.store.Save(req, rec, session); err != nil {
		t.Fatalf("Save: %v", err)
	}
	expired := map[string]bool{}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.MaxAge < 0 {
			expired[cookie.Name] = true
		}
	}
	for _, cookie := range cookies[1:] {
		if !expired[cookie.Name] {
			t.Errorf("the stale chunk %s was not expired", cookie.Name)
		}
	}
	tokens, err := auth.Tokens(requestWith(liveCookies(rec.Result().Cookies())))
	if err != nil || tokens == nil || tokens.AccessToken != "short" {
		t.Fatalf("Tokens after the shrink = %+v, %v", tokens, err)
	}

	// Logout expires the session cookie and every chunk.
	logout := httptest.NewRequest(http.MethodGet, "http://app.example.com/auth/logout", nil)
	for _, cookie := range cookies {
		logout.AddCookie(cookie)
	}
	logoutRec := httptest.NewRecorder()
	auth.Router().ServeHTTP(logoutRec, logout)
	expired = map[string]bool{}
	for _, cookie := range logoutRec.Result().Cookies() {
		if cookie.MaxAge < 0 {
			expired[cookie.Name] = true
		}
	}
	for _, cookie := range cookies {
		if !expired[cookie.Name] {
			t.Errorf("logout left the cookie %s", cookie.Name)
		}
	}
}

func TestWebAuthRefusesASessionTooLargeForCookies(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	session := auth.session(req)
	session.Values["app_data"] = fakeJWT(t, 40000)
	err := auth.store.Save(req, httptest.NewRecorder(), session)
	if err == nil || !strings.Contains(err.Error(), "WebConfig.Store") {
		t.Fatalf("expected an error that names WebConfig.Store, got %v", err)
	}
}

func TestWebAuthUsesTheStoreOfTheConfig(t *testing.T) {
	server := httptest.NewServer((&webAuthServer{t: t, accessToken: fakeJWT(t, 2000), idToken: fakeJWT(t, 2000)}).handler())
	t.Cleanup(server.Close)

	// A server-side store, as in the README: the cookie carries only an ID.
	files := sessions.NewFilesystemStore(t.TempDir(), securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32))
	files.MaxLength(0)
	store := &countingStore{Store: files}
	auth, err := NewWebAuth(WebConfig{
		BaseURL:      server.URL,
		Organization: "acme-corp",
		ClientID:     "web-client",
		ClientSecret: "web-secret",
		Store:        store, // no SessionSecret needed
	})
	if err != nil {
		t.Fatalf("NewWebAuth: %v", err)
	}

	cookies := completeLogin(t, auth)
	if store.saves == 0 {
		t.Fatal("the configured store was not used")
	}
	if len(cookies) != 1 || len(cookies[0].Value) > 300 {
		t.Errorf("a server-side store should set one short cookie, got %d (%d bytes)", len(cookies), len(cookies[0].Value))
	}
	user, err := auth.User(requestWith(cookies))
	if err != nil || user == nil || user.Email != "ada@acme.com" {
		t.Fatalf("User = %+v, %v", user, err)
	}
}

type countingStore struct {
	sessions.Store
	saves int
}

func (s *countingStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

func (s *countingStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	s.saves++
	return s.Store.Save(r, w, session)
}

func TestNewWebAuthNeedsASecretWithoutAStore(t *testing.T) {
	if _, err := NewWebAuth(WebConfig{Organization: "acme", ClientID: "c"}); err == nil {
		t.Fatal("expected a config error without SessionSecret and Store")
	}
	if _, err := NewWebAuth(WebConfig{Organization: "acme", ClientID: "c",
		Store: sessions.NewCookieStore(securecookie.GenerateRandomKey(32))}); err != nil {
		t.Fatalf("a Store should replace SessionSecret: %v", err)
	}
}

// A login started before a large sign-in must not leave its flow behind.
func TestWebAuthCallbackDropsTheFlowState(t *testing.T) {
	auth, _ := newTestWebAuth(t, &webAuthServer{})
	cookies := completeLogin(t, auth)
	session := auth.session(requestWith(cookies))
	if _, ok := session.Values[sessionKeyFlow]; ok {
		t.Error("the flow state should be removed after the callback")
	}
}
