package lumoauth

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// The net/http middleware of the Personal Agent Protocol. Two test servers
// take part: one in the place of LumoAuth (poppyLumoAuth in poppy_test.go)
// and the application that personal agents call, behind the middleware.

const poppyPublicOriginForTests = "https://shop.example.com"

// poppyApp is an application behind the middleware.
type poppyApp struct {
	server *httptest.Server
	lumo   *[]poppyCall // the calls that reached LumoAuth

	mu       sync.Mutex
	handled  int                // how often the handler ran
	verified *PoppyVerification // what the handler found in the context
	found    bool
	body     string // the request body that the handler read
}

// newPoppyApp starts LumoAuth with one answer and an application whose
// routes are built by mount. mount gets the middleware and the handler.
func newPoppyApp(t *testing.T, answer poppyAnswer, opts PoppyMiddlewareOptions,
	mount func(protect func(http.Handler) http.Handler, handler http.Handler) http.Handler) *poppyApp {
	t.Helper()
	var calls []poppyCall
	client := newPoppyClient(t, poppyLumoAuth(&calls, answer))

	if opts.PublicOrigin == "" {
		opts.PublicOrigin = poppyPublicOriginForTests
	}
	protect, err := client.Poppy.Middleware(opts)
	if err != nil {
		t.Fatalf("Middleware: %v", err)
	}

	app := &poppyApp{lumo: &calls}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		app.mu.Lock()
		app.handled++
		app.verified, app.found = PoppyFromContext(r.Context())
		app.body = string(raw)
		app.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"orders":[]}`))
	})
	if mount == nil {
		mount = func(protect func(http.Handler) http.Handler, handler http.Handler) http.Handler {
			return protect(handler)
		}
	}
	app.server = httptest.NewServer(mount(protect, handler))
	t.Cleanup(app.server.Close)
	return app
}

func (a *poppyApp) handlerRuns() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.handled
}

// get sends a request with the protocol headers and returns the response
// and its body.
func (a *poppyApp) do(t *testing.T, method, path string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, a.server.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Poppy-Session", "session.jwt")
	req.Header.Set("Poppy-Version", "1.0")
	req.Header.Set("Cookie", "sid=abc")
	resp, err := a.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

// sentURL is the URL of the only verification call.
func (a *poppyApp) sentURL(t *testing.T) string {
	t.Helper()
	if len(*a.lumo) != 1 {
		t.Fatalf("%d verification calls, want 1", len(*a.lumo))
	}
	assertPoppyCall(t, (*a.lumo)[0], poppyVerifyPath)
	sent, _ := (*a.lumo)[0].Body["url"].(string)
	return sent
}

// poppyAnswerCaseNamed finds one case of the vector.
func poppyAnswerCaseNamed(t *testing.T, vector *poppyVector, name string) poppyAnswerCase {
	t.Helper()
	for _, c := range vector.AnswerCases {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("the vector has no answer case %q", name)
	return poppyAnswerCase{}
}

// ── Verified ──────────────────────────────────────────────────────────

func TestPoppyMiddlewareVerifiedRequestReachesTheHandler(t *testing.T) {
	vector := loadPoppyVector(t)
	for _, name := range []string{"verified_signed_out", "verified_signed_in"} {
		c := poppyAnswerCaseNamed(t, vector, name)
		t.Run(name, func(t *testing.T) {
			app := newPoppyApp(t, c.Answer, PoppyMiddlewareOptions{
				RequiredScope: []string{"orders:read", "orders:write"},
				Resource:      "https://shop.example.com",
				AllowReplay:   true,
			}, nil)

			resp, body := app.do(t, "POST", "/api/orders?page=2", strings.NewReader(`{"sku":"trail-socks-3"}`))
			if resp.StatusCode != 200 || body != `{"orders":[]}` {
				t.Fatalf("response = %d %q, want the handler's own answer", resp.StatusCode, body)
			}
			if app.handlerRuns() != 1 || !app.found {
				t.Fatalf("the handler ran %d times, result found: %v", app.handlerRuns(), app.found)
			}
			assertPoppyVerified(t, app.verified, c)

			// The middleware does not read the request body.
			if app.body != `{"sku":"trail-socks-3"}` {
				t.Errorf("the handler read the body %q", app.body)
			}

			want := map[string]any{
				"method":         "POST",
				"url":            "https://shop.example.com/api/orders",
				"headers":        map[string]any{"poppy-session": "session.jwt", "poppy-version": "1.0"},
				"required_scope": "orders:read orders:write",
				"resource":       "https://shop.example.com",
				"allow_replay":   true,
			}
			if app.sentURL(t); !equalJSON((*app.lumo)[0].Body, want) {
				t.Errorf("verification body = %s", (*app.lumo)[0].Raw)
			}
		})
	}
}

func TestPoppyFromContextWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if verification, ok := PoppyFromContext(req.Context()); ok || verification != nil {
		t.Errorf("PoppyFromContext = %+v, %v on a plain request", verification, ok)
	}
	stored := &PoppyVerification{Active: true, ClientID: "https://agent.example/agent.json"}
	if got, ok := PoppyFromContext(ContextWithPoppy(req.Context(), stored)); !ok || got != stored {
		t.Errorf("PoppyFromContext = %+v, %v", got, ok)
	}
	if got, ok := PoppyFromContext(ContextWithPoppy(req.Context(), nil)); ok || got != nil {
		t.Errorf("a nil result must not be found: %+v, %v", got, ok)
	}
}

// ── Refused ───────────────────────────────────────────────────────────

// assertPoppyRelay checks a response against expect.relay: the status,
// every header, the content type and the body, and nothing else.
func assertPoppyRelay(t *testing.T, resp *http.Response, body string, c poppyAnswerCase) {
	t.Helper()
	relay := c.Expect.Relay
	if resp.StatusCode != relay.Status {
		t.Errorf("status = %d, want %d", resp.StatusCode, relay.Status)
	}
	allowed := map[string]bool{"Date": true, "Content-Length": true}
	for name, want := range relay.Headers {
		allowed[http.CanonicalHeaderKey(name)] = true
		if got := resp.Header.Values(name); len(got) != 1 || got[0] != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
	if relay.ContentType != nil {
		allowed["Content-Type"] = true
		if got := resp.Header.Get("Content-Type"); got != *relay.ContentType {
			t.Errorf("Content-Type = %q, want %q", got, *relay.ContentType)
		}
	} else if got, present := resp.Header["Content-Type"]; present {
		t.Errorf("Content-Type = %q, want none", got)
	}
	for name := range resp.Header {
		if !allowed[name] {
			t.Errorf("the response has the header %s, which LumoAuth did not send", name)
		}
	}
	if relay.Body == nil {
		if body != "" {
			t.Errorf("body = %q, want none", body)
		}
		return
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil || !equalJSON(got, relay.Body) {
		t.Errorf("body = %q, want %s", body, poppyJSON(t, relay.Body))
	}
}

func TestPoppyMiddlewareRelaysEveryRefusal(t *testing.T) {
	vector := loadPoppyVector(t)
	refusals := 0
	for _, c := range vector.AnswerCases {
		if c.Expect.Outcome != "refused" {
			continue
		}
		refusals++
		t.Run(c.Name, func(t *testing.T) {
			hookCalls := 0
			app := newPoppyApp(t, c.Answer, PoppyMiddlewareOptions{
				OnError: func(http.ResponseWriter, *http.Request, error) { hookCalls++ },
			}, nil)
			resp, body := app.do(t, "GET", "/api/orders", nil)

			assertPoppyRelay(t, resp, body, c)
			if app.handlerRuns() != 0 {
				t.Error("the handler ran for a refused request")
			}
			if hookCalls != 0 {
				t.Error("a refusal is not an error: OnError must not be called")
			}
		})

		// The same step for an application that calls VerifyRequest itself.
		t.Run(c.Name+"/WritePoppyRefusal", func(t *testing.T) {
			var verification PoppyVerification
			if err := json.Unmarshal(c.Answer.Body, &verification); err != nil {
				t.Fatalf("decode: %v", err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := WritePoppyRefusal(w, &verification); err != nil {
					t.Errorf("WritePoppyRefusal: %v", err)
				}
			}))
			defer server.Close()
			resp, err := server.Client().Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			assertPoppyRelay(t, resp, string(raw), c)
		})
	}
	if refusals == 0 {
		t.Fatal("the vector has no refused answer case")
	}
}

func TestWritePoppyRefusalNeedsARefusal(t *testing.T) {
	notRefusals := map[string]*PoppyVerification{
		"nil":                nil,
		"verified":           {Active: true, ClientID: "https://agent.example/agent.json", Session: &PoppySession{ID: 1, SID: "s"}},
		"no response":        {Active: false, Error: "invalid_session"},
		"a success status":   {Active: false, Error: "invalid_session", Response: &PoppyRelayResponse{Status: 200}},
		"a status of zero":   {Active: false, Error: "invalid_session", Response: &PoppyRelayResponse{}},
		"an unencodable map": {Active: false, Error: "invalid_session", Response: &PoppyRelayResponse{Status: 400, Body: map[string]any{"x": func() {}}}},
	}
	for name, verification := range notRefusals {
		recorder := httptest.NewRecorder()
		err := WritePoppyRefusal(recorder, verification)
		if !errors.Is(err, ErrValidation) {
			t.Errorf("%s: expected a validation error, got %v", name, err)
		}
		if recorder.Body.Len() != 0 || len(recorder.Header()) != 0 || recorder.Flushed {
			t.Errorf("%s: something was written: %v %q", name, recorder.Header(), recorder.Body.String())
		}
	}

	// A hand-built refusal works, with and without a body.
	recorder := httptest.NewRecorder()
	err := WritePoppyRefusal(recorder, &PoppyVerification{Error: "invalid_session", Response: &PoppyRelayResponse{
		Status: 400, Headers: map[string]string{"Cache-Control": "no-store"}, Body: map[string]any{"error": "<invalid_session>"},
	}})
	if err != nil || recorder.Code != 400 || recorder.Body.String() != `{"error":"<invalid_session>"}` ||
		recorder.Header().Get("Content-Type") != "application/json" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("err = %v, response = %d %v %q", err, recorder.Code, recorder.Header(), recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	err = WritePoppyRefusal(recorder, &PoppyVerification{Error: "invalid_token", Response: &PoppyRelayResponse{
		Status: 401, Headers: map[string]string{"WWW-Authenticate": `Bearer error="invalid_token"`},
	}})
	if err != nil || recorder.Code != 401 || recorder.Body.Len() != 0 || recorder.Header().Get("Content-Type") != "" ||
		recorder.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Errorf("err = %v, response = %d %v %q", err, recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

// ── The call failed ───────────────────────────────────────────────────

const poppyFailureBody = `{"error":"server_error"}`

// assertPoppyFailure checks the answer for a failed verification call:
// 500, the fixed body, and nothing of LumoAuth's answer.
func assertPoppyFailure(t *testing.T, resp *http.Response, body string, leaks ...string) {
	t.Helper()
	if resp.StatusCode != http.StatusInternalServerError || body != poppyFailureBody {
		t.Errorf("response = %d %q, want 500 %s", resp.StatusCode, body, poppyFailureBody)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	for _, name := range []string{"WWW-Authenticate", "Retry-After"} {
		if got := resp.Header.Get(name); got != "" {
			t.Errorf("the response relays %s: %q", name, got)
		}
	}
	for _, leak := range leaks {
		if leak != "" && strings.Contains(body, leak) {
			t.Errorf("the response leaks %q", leak)
		}
	}
}

func TestPoppyMiddlewareNeverRelaysAnError(t *testing.T) {
	vector := loadPoppyVector(t)
	errorCases := 0
	for _, c := range vector.AnswerCases {
		if c.Expect.Outcome != "error" {
			continue
		}
		errorCases++
		var answerBody map[string]any
		_ = json.Unmarshal(c.Answer.Body, &answerBody)
		description, _ := answerBody["error_description"].(string)
		code, _ := answerBody["error"].(string)

		t.Run(c.Name, func(t *testing.T) {
			app := newPoppyApp(t, c.Answer, PoppyMiddlewareOptions{}, nil)
			resp, body := app.do(t, "GET", "/api/orders", nil)

			assertPoppyFailure(t, resp, body, description, code, "poppy:verify", app.server.URL)
			if app.handlerRuns() != 0 {
				t.Error("the handler ran although the verification call failed")
			}
			if len(*app.lumo) != 1 {
				t.Errorf("%d verification calls, want 1", len(*app.lumo))
			}
		})

		t.Run(c.Name+"/OnError", func(t *testing.T) {
			var hookErr error
			hookCalls := 0
			app := newPoppyApp(t, c.Answer, PoppyMiddlewareOptions{
				OnError: func(w http.ResponseWriter, r *http.Request, err error) {
					hookCalls++
					hookErr = err
					http.Error(w, "try again later", http.StatusServiceUnavailable)
				},
			}, nil)
			resp, body := app.do(t, "GET", "/api/orders", nil)

			if resp.StatusCode != http.StatusServiceUnavailable || strings.TrimSpace(body) != "try again later" {
				t.Errorf("response = %d %q, want the hook's own answer", resp.StatusCode, body)
			}
			if hookCalls != 1 || app.handlerRuns() != 0 {
				t.Errorf("hook calls = %d, handler runs = %d", hookCalls, app.handlerRuns())
			}
			poppyVectorError(t, hookErr, c.Expect.ErrorClass, c.Expect.RetryAfter)
		})
	}
	if errorCases == 0 {
		t.Fatal("the vector has no error answer case")
	}
}

func TestPoppyMiddlewareWhenLumoAuthIsNotReachable(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	client, err := New(WithBaseURL(dead.URL), WithOrgID("acme-corp"),
		WithClientCredentials(poppyTestClientID, poppyTestClientSecret))
	if err != nil {
		t.Fatal(err)
	}

	for _, withHook := range []bool{false, true} {
		var hookErr error
		opts := PoppyMiddlewareOptions{PublicOrigin: poppyPublicOriginForTests}
		if withHook {
			opts.OnError = func(w http.ResponseWriter, r *http.Request, err error) {
				hookErr = err
				w.WriteHeader(http.StatusBadGateway)
			}
		}
		protect, err := client.Poppy.Middleware(opts)
		if err != nil {
			t.Fatal(err)
		}
		handled := false
		app := httptest.NewServer(protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handled = true })))
		resp, err := app.Client().Get(app.URL + "/api/orders")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		app.Close()

		if handled {
			t.Error("the handler ran although LumoAuth was not reachable")
		}
		if withHook {
			if resp.StatusCode != http.StatusBadGateway || !errors.Is(hookErr, ErrNetwork) {
				t.Errorf("status = %d, hook error = %v", resp.StatusCode, hookErr)
			}
			continue
		}
		// The network error names LumoAuth's address. It must stay inside.
		assertPoppyFailure(t, resp, string(raw), dead.URL, strings.TrimPrefix(dead.URL, "http://"), "connection", "refused")
	}
}

// ── The URL ───────────────────────────────────────────────────────────

func TestPoppyMiddlewareBuildsTheURLFromThePublicOrigin(t *testing.T) {
	app := newPoppyApp(t, poppyVerifiedAnswer(t), PoppyMiddlewareOptions{PublicOrigin: "https://example.com/shop/"}, nil)

	req, err := http.NewRequest("GET", app.server.URL+"/api/cart?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "evil.example"
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Prefix", "/evil")
	req.Header.Set("Forwarded", "host=evil.example;proto=http")
	req.Header.Set("X-Original-URL", "/admin")
	req.Header.Set("Poppy-Session", "session.jwt")
	resp, err := app.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := app.sentURL(t); got != "https://example.com/shop/api/cart" {
		t.Errorf("url = %q, want the public origin with the request path", got)
	}
	if raw := string((*app.lumo)[0].Raw); strings.Contains(raw, "evil") || strings.Contains(raw, "/admin") {
		t.Errorf("the verification body carries a value of a hostile header: %s", raw)
	}
	if app.handlerRuns() != 1 {
		t.Errorf("the handler ran %d times", app.handlerRuns())
	}
}

func TestPoppyMiddlewareSendsTheFullPathOfAMountedRoute(t *testing.T) {
	mounts := map[string]func(protect func(http.Handler) http.Handler, handler http.Handler) http.Handler{
		"http.StripPrefix in front of the middleware": func(protect func(http.Handler) http.Handler, handler http.Handler) http.Handler {
			mux := http.NewServeMux()
			mux.Handle("/shop/api/", http.StripPrefix("/shop/api", protect(handler)))
			return mux
		},
		"the middleware in front of http.StripPrefix": func(protect func(http.Handler) http.Handler, handler http.Handler) http.Handler {
			mux := http.NewServeMux()
			mux.Handle("/shop/api/", protect(http.StripPrefix("/shop/api", handler)))
			return mux
		},
		"two nested prefixes": func(protect func(http.Handler) http.Handler, handler http.Handler) http.Handler {
			inner := http.NewServeMux()
			inner.Handle("/api/", http.StripPrefix("/api", protect(handler)))
			outer := http.NewServeMux()
			outer.Handle("/shop/", http.StripPrefix("/shop", inner))
			return outer
		},
		"a method pattern with a wildcard": func(protect func(http.Handler) http.Handler, handler http.Handler) http.Handler {
			mux := http.NewServeMux()
			mux.Handle("GET /shop/api/orders/{id}/items", protect(handler))
			return mux
		},
		"a handler that rewrote the URL": func(protect func(http.Handler) http.Handler, handler http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rewritten := r.Clone(r.Context())
				rewritten.URL.Path, rewritten.URL.RawPath = "/internal", ""
				protect(handler).ServeHTTP(w, rewritten)
			})
		},
	}
	for name, mount := range mounts {
		t.Run(name, func(t *testing.T) {
			app := newPoppyApp(t, poppyVerifiedAnswer(t), PoppyMiddlewareOptions{}, mount)
			resp, _ := app.do(t, "GET", "/shop/api/orders/ord_1042/items?page=2", nil)
			if resp.StatusCode != 200 || app.handlerRuns() != 1 {
				t.Fatalf("status = %d, handler runs = %d", resp.StatusCode, app.handlerRuns())
			}
			if got := app.sentURL(t); got != "https://shop.example.com/shop/api/orders/ord_1042/items" {
				t.Errorf("url = %q, want the full path that the client sent", got)
			}
		})
	}
}

func TestPoppyRequestTargetOfARequestWithoutARequestLine(t *testing.T) {
	// http.NewRequest builds a client request: it has no RequestURI. The
	// path then comes from the URL, in its encoded form.
	req, err := http.NewRequest("GET", "https://internal.invalid/api/files/a%20b/..%2Fc?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := poppyRequestTarget(req); got != "/api/files/a%20b/..%2Fc" {
		t.Errorf("target = %q", got)
	}
	if got := poppyRequestTarget(&http.Request{Method: "GET"}); got != "" {
		t.Errorf("target = %q for a request without a URL", got)
	}
}

// poppyRawRequest writes one HTTP/1.1 request by hand, so the request line
// and the header names reach the server exactly as the test spells them.
func poppyRawRequest(t *testing.T, serverURL, method, target string, headers [][2]string) int {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(serverURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var request strings.Builder
	fmt.Fprintf(&request, "%s %s HTTP/1.1\r\n", method, target)
	hasHost := false
	for _, header := range headers {
		if strings.EqualFold(header[0], "Host") {
			hasHost = true
		}
		fmt.Fprintf(&request, "%s: %s\r\n", header[0], header[1])
	}
	if !hasHost {
		request.WriteString("Host: evil.example\r\n")
	}
	request.WriteString("Connection: close\r\n\r\n")
	if _, err := conn.Write([]byte(request.String())); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestContractPoppyRequestCasesThroughTheMiddleware sends each request case
// of the vector over a real connection: the request line, the header names
// and the repeated headers arrive as the vector spells them, and the Host
// header is never the public host.
func TestContractPoppyRequestCasesThroughTheMiddleware(t *testing.T) {
	vector := loadPoppyVector(t)
	for _, c := range vector.RequestCases {
		t.Run(c.Name, func(t *testing.T) {
			opts := poppyVectorOptions(t, c.Options.RequiredScope, c.Options.Resource, c.Options.AllowReplay)
			app := newPoppyApp(t, poppyVerifiedAnswer(t), PoppyMiddlewareOptions{
				PublicOrigin:  c.PublicOrigin,
				RequiredScope: opts.RequiredScope,
				Resource:      opts.Resource,
				AllowReplay:   opts.AllowReplay,
			}, nil)

			target := c.Incoming.Target
			if target == "" {
				// A request line cannot carry an empty target. "/" is what
				// a client sends for it.
				target = "/"
			}
			status := poppyRawRequest(t, app.server.URL, c.Incoming.Method, target, c.Incoming.Headers)
			if status != 200 || app.handlerRuns() != 1 {
				t.Fatalf("status = %d, handler runs = %d", status, app.handlerRuns())
			}
			app.sentURL(t)
			if !equalJSON((*app.lumo)[0].Body, c.ExpectedBody) {
				t.Errorf("body = %s\nwant   %s", (*app.lumo)[0].Raw, poppyJSON(t, c.ExpectedBody))
			}
		})
	}
}

func TestPoppyMiddlewareForwardsOnlyTheProtocolHeaders(t *testing.T) {
	app := newPoppyApp(t, poppyVerifiedAnswer(t), PoppyMiddlewareOptions{}, nil)
	status := poppyRawRequest(t, app.server.URL, "GET", "/api/orders", [][2]string{
		{"poppy-session", "session.jwt"},
		{"POPPY-VERSION", "1.0"},
		{"Poppy-Extensions", "ext-one;v=\"1.0\""},
		{"poppy-extensions", "ext-two;v=\"2.1\""},
		{"Authorization", "DPoP access.token"},
		{"DPoP", "dpop.proof"},
		{"Cookie", "session=secret-cookie"},
		{"X-Api-Key", "secret-api-key"},
		{"Proxy-Authorization", "Basic c2VjcmV0"},
		{"X-Amz-Security-Token", "secret-cloud-token"},
	})
	if status != 200 {
		t.Fatalf("status = %d", status)
	}
	app.sentURL(t)
	call := (*app.lumo)[0]
	want := map[string]any{
		"poppy-session":    "session.jwt",
		"poppy-version":    "1.0",
		"poppy-extensions": "ext-one;v=\"1.0\", ext-two;v=\"2.1\"",
		"authorization":    "DPoP access.token",
		"dpop":             "dpop.proof",
	}
	if !equalJSON(call.Body["headers"], want) {
		t.Errorf("headers = %v", call.Body["headers"])
	}
	for _, secret := range []string{"secret-cookie", "secret-api-key", "c2VjcmV0", "secret-cloud-token"} {
		if strings.Contains(string(call.Raw), secret) {
			t.Errorf("the verification body carries %q", secret)
		}
		for name, values := range call.Header {
			if strings.Contains(strings.Join(values, " "), secret) {
				t.Errorf("the verification call carries %q in the header %s", secret, name)
			}
		}
	}
}

// ── Construction ──────────────────────────────────────────────────────

func TestPoppyMiddlewareFailsEarlyOnBadConfiguration(t *testing.T) {
	client := newPoppyClient(t, poppyNoCall(t))
	for _, origin := range []string{"", "   ", "shop.example.com", "https://shop.example.com?x=1", "https://"} {
		protect, err := client.Poppy.Middleware(PoppyMiddlewareOptions{PublicOrigin: origin})
		if protect != nil || !errors.Is(err, ErrConfig) {
			t.Errorf("%q: expected a configuration error and no middleware, got %v", origin, err)
		}
	}
	if _, err := client.Poppy.Middleware(PoppyMiddlewareOptions{}); err == nil || !strings.Contains(err.Error(), "public origin") {
		t.Errorf("the error must name the public origin: %v", err)
	}
}

func TestPoppyMiddlewareOptionsAreCopied(t *testing.T) {
	scopes := []string{"orders:read"}
	app := newPoppyApp(t, poppyVerifiedAnswer(t), PoppyMiddlewareOptions{RequiredScope: scopes}, nil)
	scopes[0] = "admin"
	app.do(t, "GET", "/api/orders", nil)
	app.sentURL(t)
	if got := (*app.lumo)[0].Body["required_scope"]; got != "orders:read" {
		t.Errorf("required_scope = %v: a later change of the caller's slice reached the middleware", got)
	}
}

func TestPoppyMiddlewareServesConcurrentRequests(t *testing.T) {
	var mu sync.Mutex
	var urls []string
	lumo := func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		urls = append(urls, body["url"].(string))
		mu.Unlock()
		writeJSON(w, 200, map[string]any{
			"active": true, "client_id": "https://agent.example/agent.json", "user_id": body["url"],
			"session": map[string]any{"id": 1, "sid": "sid-1", "new": false},
		})
	}
	client := newPoppyClient(t, lumo)
	protect, err := client.Poppy.Middleware(PoppyMiddlewareOptions{PublicOrigin: poppyPublicOriginForTests})
	if err != nil {
		t.Fatal(err)
	}
	app := httptest.NewServer(protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := PoppyFromContext(r.Context())
		_, _ = io.WriteString(w, who.UserID)
	})))
	defer app.Close()

	const requests = 24
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/api/orders/%d", i)
			resp, err := app.Client().Get(app.URL + path)
			if err != nil {
				t.Error(err)
				return
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			// Each handler sees the result of its own request.
			if string(raw) != poppyPublicOriginForTests+path {
				t.Errorf("request %d got the result %q", i, raw)
			}
		}(i)
	}
	wg.Wait()
	sort.Strings(urls)
	if len(urls) != requests {
		t.Errorf("%d verification calls for %d requests", len(urls), requests)
	}
}

// ── Without the vector ────────────────────────────────────────────────

// TestPoppyMiddlewareInline holds one case of each outcome, so the three
// behaviours are tested without the contract checkout too.
func TestPoppyMiddlewareInline(t *testing.T) {
	t.Run("verified", func(t *testing.T) {
		app := newPoppyApp(t, poppyVerifiedAnswer(t), PoppyMiddlewareOptions{}, nil)
		resp, body := app.do(t, "GET", "/api/catalog?page=2", nil)
		if resp.StatusCode != 200 || body != `{"orders":[]}` || app.handlerRuns() != 1 {
			t.Fatalf("response = %d %q, handler runs = %d", resp.StatusCode, body, app.handlerRuns())
		}
		who := app.verified
		if !app.found || !who.Active || who.ClientID != "https://agent.example/agent.json" ||
			who.UserID != "usr_Q7c1vK" || who.Session.ID != 4821 || !who.Session.IsNew || who.SignedIn || who.Account != nil {
			t.Errorf("verification = %+v", who)
		}
		if got := app.sentURL(t); got != "https://shop.example.com/api/catalog" {
			t.Errorf("url = %q", got)
		}
	})

	refusals := map[string]struct {
		answer      map[string]any
		status      int
		headers     map[string]string
		contentType string
		body        string
	}{
		"with a body": {
			answer: map[string]any{
				"active": false, "error": "invalid_session", "error_description": "The Session JWT has expired.",
				"response": map[string]any{
					"status": 400, "headers": map[string]any{"Cache-Control": "no-store"},
					"body": map[string]any{"error": "invalid_session", "error_description": "The Session JWT has expired."},
				},
			},
			status: 400, headers: map[string]string{"Cache-Control": "no-store"}, contentType: "application/json",
			body: `{"error":"invalid_session","error_description":"The Session JWT has expired."}`,
		},
		"without a body": {
			answer: map[string]any{
				"active": false, "error": "insufficient_scope", "scope": "orders:write",
				"response": map[string]any{
					"status": 403,
					"headers": map[string]any{
						"Cache-Control":    "no-store",
						"WWW-Authenticate": `Bearer error="insufficient_scope", scope="orders:write"`,
					},
					"body": nil,
				},
			},
			status: 403,
			headers: map[string]string{
				"Cache-Control":    "no-store",
				"WWW-Authenticate": `Bearer error="insufficient_scope", scope="orders:write"`,
			},
		},
	}
	for name, c := range refusals {
		t.Run("refused "+name, func(t *testing.T) {
			app := newPoppyApp(t, poppyAnswer{Status: 200, Body: poppyJSON(t, c.answer)}, PoppyMiddlewareOptions{}, nil)
			resp, body := app.do(t, "GET", "/api/orders", nil)
			if resp.StatusCode != c.status || body != c.body || app.handlerRuns() != 0 {
				t.Errorf("response = %d %q, handler runs = %d", resp.StatusCode, body, app.handlerRuns())
			}
			for header, want := range c.headers {
				if got := resp.Header.Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}
			if got := resp.Header.Get("Content-Type"); got != c.contentType {
				t.Errorf("Content-Type = %q, want %q", got, c.contentType)
			}
		})
	}

	failures := map[string]poppyAnswer{
		"the application lacks the scope": {Status: 403, Body: json.RawMessage(
			`{"error":"insufficient_scope","error_description":"Add the \"poppy:verify\" scope to this application."}`)},
		"the application is rate limited": {Status: 429, Headers: map[string]string{"Retry-After": "7"},
			Body: json.RawMessage(`{"error":"too_many_requests","error_description":"Rate limit exceeded"}`)},
		"a 200 answer that is not a result": {Status: 200, Body: json.RawMessage(`{"active":"true"}`)},
	}
	for name, answer := range failures {
		t.Run("failed: "+name, func(t *testing.T) {
			app := newPoppyApp(t, answer, PoppyMiddlewareOptions{}, nil)
			resp, body := app.do(t, "GET", "/api/orders", nil)
			assertPoppyFailure(t, resp, body, "poppy:verify", "insufficient_scope", "too_many_requests", "Rate limit", "active")
			if app.handlerRuns() != 0 {
				t.Error("the handler ran although the verification call failed")
			}
		})
	}
}
