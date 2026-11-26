package lumoauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Personal Agent Protocol Session verification against the cross-SDK
// vector (sdk-contract/vectors/poppy-verification.json). Every case of the
// vector runs here against the core, with a test server in the place of
// LumoAuth. poppy_http_test.go runs the same cases through the net/http
// middleware. The tests below the vector tests run without the contract
// checkout.

// ── The vector ────────────────────────────────────────────────────────

type poppyVector struct {
	ForwardedHeaders []string `json:"forwarded_headers"`
	RequestCases     []struct {
		Name         string `json:"name"`
		PublicOrigin string `json:"public_origin"`
		Incoming     struct {
			Method  string      `json:"method"`
			Target  string      `json:"target"`
			Headers [][2]string `json:"headers"`
		} `json:"incoming"`
		Options struct {
			RequiredScope json.RawMessage `json:"required_scope"`
			Resource      string          `json:"resource"`
			AllowReplay   bool            `json:"allow_replay"`
		} `json:"options"`
		ExpectedBody map[string]any `json:"expected_body"`
	} `json:"request_cases"`
	AnswerCases        []poppyAnswerCase `json:"answer_cases"`
	SessionStatusCases []struct {
		Name    string            `json:"name"`
		Request map[string]string `json:"request"`
		Answer  poppyAnswer       `json:"answer"`
		Expect  struct {
			Status     string  `json:"status"`
			UserID     *string `json:"user_id"`
			AgentID    *string `json:"agent_id"`
			Account    *string `json:"account"`
			SignedIn   bool    `json:"signed_in"`
			LastSeenAt *string `json:"last_seen_at"`
		} `json:"expect"`
	} `json:"session_status_cases"`
	EndSessionCases []struct {
		Name    string            `json:"name"`
		Request map[string]string `json:"request"`
		Answer  poppyAnswer       `json:"answer"`
		Expect  struct {
			Ended      *bool  `json:"ended"`
			ErrorClass string `json:"error_class"`
		} `json:"expect"`
	} `json:"end_session_cases"`
}

type poppyAnswer struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

type poppyAnswerCase struct {
	Name   string      `json:"name"`
	Answer poppyAnswer `json:"answer"`
	Expect struct {
		Outcome string `json:"outcome"`

		ClientID   string  `json:"client_id"`
		ClientName string  `json:"client_name"`
		UserID     string  `json:"user_id"`
		AgentID    *string `json:"agent_id"`
		SessionID  int64   `json:"session_id"`
		SID        string  `json:"sid"`
		SessionNew bool    `json:"session_new"`
		StartedAt  string  `json:"started_at"`
		SignedIn   bool    `json:"signed_in"`
		Account    *struct {
			Sub       string   `json:"sub"`
			Scope     string   `json:"scope"`
			Scopes    []string `json:"scopes"`
			Aud       []string `json:"aud"`
			Exp       int64    `json:"exp"`
			TokenType string   `json:"token_type"`
		} `json:"account"`
		Version    string            `json:"version"`
		Extensions map[string]string `json:"extensions"`

		Error            string  `json:"error"`
		ErrorDescription string  `json:"error_description"`
		Scope            *string `json:"scope"`
		Relay            *struct {
			Status      int               `json:"status"`
			Headers     map[string]string `json:"headers"`
			ContentType *string           `json:"content_type"`
			Body        map[string]any    `json:"body"`
		} `json:"relay"`

		ErrorClass string `json:"error_class"`
		RetryAfter int    `json:"retry_after"`
	} `json:"expect"`
}

func loadPoppyVector(t *testing.T) *poppyVector {
	t.Helper()
	var vector poppyVector
	loadContract(t, contractDir(t), "vectors/poppy-verification.json", &vector)
	if len(vector.RequestCases) == 0 || len(vector.AnswerCases) == 0 ||
		len(vector.SessionStatusCases) == 0 || len(vector.EndSessionCases) == 0 {
		t.Fatal("the Personal Agent Protocol vector has an empty case list")
	}
	return &vector
}

// poppyVectorOptions turns the options of a request case into
// PoppyVerifyOptions. required_scope is a string or a list in the vector.
func poppyVectorOptions(t *testing.T, requiredScope json.RawMessage, resource string, allowReplay bool) *PoppyVerifyOptions {
	t.Helper()
	opts := &PoppyVerifyOptions{Resource: resource, AllowReplay: allowReplay}
	if len(requiredScope) == 0 {
		return opts
	}
	var single string
	if json.Unmarshal(requiredScope, &single) == nil {
		opts.RequiredScope = []string{single}
		return opts
	}
	if err := json.Unmarshal(requiredScope, &opts.RequiredScope); err != nil {
		t.Fatalf("required_scope is neither a string nor a list: %s", requiredScope)
	}
	return opts
}

// poppyVectorHeaders keeps the spelling of the vector's header names, so
// the SDK's own matching without regard to case is what the test checks.
func poppyVectorHeaders(pairs [][2]string) http.Header {
	headers := http.Header{}
	for _, pair := range pairs {
		headers[pair[0]] = append(headers[pair[0]], pair[1])
	}
	return headers
}

// poppyVectorError checks an error against an error class of errors.json.
// Go folds the API error classes into *APIError and tells them apart by
// sentinel.
func poppyVectorError(t *testing.T, err error, class string, retryAfter int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error of class %s, got none", class)
	}
	if !errors.Is(err, ErrLumoAuth) {
		t.Errorf("every SDK error matches ErrLumoAuth, got %T %v", err, err)
	}
	sentinels := map[string]error{
		"LumoAuthAuthenticationError":   ErrAuthentication,
		"LumoAuthPermissionDeniedError": ErrPermissionDenied,
		"LumoAuthNotFoundError":         ErrNotFound,
		"LumoAuthRateLimitError":        ErrRateLimited,
	}
	switch class {
	case "LumoAuthError":
		// A 200 answer that the SDK cannot use: an SDK error, not an API
		// error.
		if errors.Is(err, ErrAPI) || !errors.Is(err, ErrValidation) {
			t.Errorf("expected a validation error, got %T %v", err, err)
		}
	default:
		sentinel, known := sentinels[class]
		if !known {
			t.Fatalf("the vector names an error class that this test does not know: %s", class)
		}
		var apiErr *APIError
		if !errors.Is(err, sentinel) || !errors.As(err, &apiErr) {
			t.Fatalf("expected %s as an *APIError, got %T %v", class, err, err)
		}
		if retryAfter > 0 && apiErr.RetryAfter != time.Duration(retryAfter)*time.Second {
			t.Errorf("RetryAfter = %v, want %ds", apiErr.RetryAfter, retryAfter)
		}
	}
}

// ── The test server in the place of LumoAuth ──────────────────────────

const (
	poppyTestClientID = "shop-api"
	// A secret with characters that percent-encoding would change.
	poppyTestClientSecret = "s3cr3t:with/odd+chars%20&=é"
	poppyTestAPIKey       = "lmk_test_key"
	poppyTestAccessToken  = "user-access-token"
)

type poppyCall struct {
	Method string
	Path   string
	Header http.Header
	Raw    []byte
	Body   map[string]any
}

// poppyLumoAuth answers every call with one status, header set and body,
// and records the calls.
func poppyLumoAuth(calls *[]poppyCall, answer poppyAnswer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		call := poppyCall{Method: r.Method, Path: r.URL.EscapedPath(), Header: r.Header.Clone(), Raw: raw}
		_ = json.Unmarshal(raw, &call.Body)
		*calls = append(*calls, call)

		for name, value := range answer.Headers {
			w.Header().Set(name, value)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(answer.Status)
		_, _ = w.Write(answer.Body)
	}
}

// newPoppyClient builds a client that holds every kind of credential: the
// client credentials, an API key and a bearer token. The Personal Agent
// Protocol calls must send the first kind only.
func newPoppyClient(t *testing.T, handler http.HandlerFunc, opts ...Option) *Client {
	t.Helper()
	base := []Option{
		WithClientCredentials(poppyTestClientID, poppyTestClientSecret),
		WithAccessToken(poppyTestAccessToken),
	}
	client, _ := newTestClient(t, handler, append(base, opts...)...)
	return client
}

// assertPoppyCall checks what every Personal Agent Protocol call must look
// like on the wire, whatever it asks.
func assertPoppyCall(t *testing.T, call poppyCall, wantPath string) {
	t.Helper()
	if call.Method != http.MethodPost || call.Path != wantPath {
		t.Errorf("request = %s %s, want POST %s", call.Method, call.Path, wantPath)
	}
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte(poppyTestClientID+":"+poppyTestClientSecret))
	if got := call.Header.Get("Authorization"); got != wantBasic {
		t.Errorf("Authorization = %q, want the Basic value of the raw client ID and secret", got)
	}
	if len(call.Header.Values("Authorization")) != 1 {
		t.Errorf("Authorization was sent %d times", len(call.Header.Values("Authorization")))
	}
	if got := call.Header.Get("X-API-Key"); got != "" {
		t.Errorf("the API key was sent: %q", got)
	}
	if got := call.Header.Get("DPoP"); got != "" {
		t.Errorf("a DPoP proof was sent: %q", got)
	}
	for name, values := range call.Header {
		for _, value := range values {
			if strings.Contains(value, poppyTestAccessToken) || strings.Contains(value, poppyTestAPIKey) {
				t.Errorf("header %s carries the client's bearer token or API key", name)
			}
		}
	}
	if got := call.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if call.Body == nil {
		t.Fatalf("the body is not a JSON object: %s", call.Raw)
	}
	for _, member := range []string{"client_id", "client_secret", "client_assertion", "client_assertion_type"} {
		if _, present := call.Body[member]; present {
			t.Errorf("the JSON body carries %q", member)
		}
	}
	for _, secret := range []string{poppyTestClientSecret, poppyTestAccessToken, poppyTestAPIKey} {
		if strings.Contains(string(call.Raw), secret) {
			t.Errorf("the JSON body carries a credential")
		}
	}
}

const (
	poppyVerifyPath = "/orgs/acme-corp/api/v1/poppy/sessions/verify"
	poppyStatusPath = "/orgs/acme-corp/api/v1/poppy/sessions/status"
	poppyEndPath    = "/orgs/acme-corp/api/v1/poppy/sessions/end"
)

func poppyJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// poppyVerifiedAnswer is a verified signed-out answer for the tests that
// are not about the answer.
func poppyVerifiedAnswer(t *testing.T) poppyAnswer {
	t.Helper()
	return poppyAnswer{Status: 200, Body: poppyJSON(t, map[string]any{
		"active": true, "client_id": "https://agent.example/agent.json", "client_name": "Example Agent",
		"user_id": "usr_Q7c1vK", "agent_id": nil,
		"session":   map[string]any{"id": 4821, "sid": "Yx2b7Qd_Kp8mR3vT1nWc4A", "new": true, "started_at": "2026-11-26T10:15:00+00:00"},
		"signed_in": false, "account": nil, "version": "1.0", "extensions": map[string]any{},
	})}
}

// ── Vector: request cases ─────────────────────────────────────────────

func TestContractPoppyForwardedHeaders(t *testing.T) {
	vector := loadPoppyVector(t)
	if !equalJSON(poppyForwardedHeaderNames, vector.ForwardedHeaders) {
		t.Errorf("the SDK forwards %v, the vector has %v", poppyForwardedHeaderNames, vector.ForwardedHeaders)
	}
}

func TestContractPoppyRequestCases(t *testing.T) {
	vector := loadPoppyVector(t)
	ctx := context.Background()

	for _, c := range vector.RequestCases {
		opts := poppyVectorOptions(t, c.Options.RequiredScope, c.Options.Resource, c.Options.AllowReplay)
		headers := poppyVectorHeaders(c.Incoming.Headers)

		t.Run(c.Name+"/BuildPoppyVerifyBody", func(t *testing.T) {
			body, err := BuildPoppyVerifyBody(c.PublicOrigin, c.Incoming.Method, c.Incoming.Target, headers, opts)
			if err != nil {
				t.Fatalf("BuildPoppyVerifyBody: %v", err)
			}
			if !equalJSON(body, c.ExpectedBody) {
				t.Errorf("body = %s\nwant   %s", poppyJSON(t, body), poppyJSON(t, c.ExpectedBody))
			}
		})

		t.Run(c.Name+"/VerifyHTTPRequest", func(t *testing.T) {
			var calls []poppyCall
			client := newPoppyClient(t, poppyLumoAuth(&calls, poppyVerifiedAnswer(t)))
			incoming := &http.Request{Method: c.Incoming.Method, RequestURI: c.Incoming.Target, Header: headers}
			if _, err := client.Poppy.VerifyHTTPRequest(ctx, c.PublicOrigin, incoming, opts); err != nil {
				t.Fatalf("VerifyHTTPRequest: %v", err)
			}
			if len(calls) != 1 {
				t.Fatalf("%d calls, want 1", len(calls))
			}
			assertPoppyCall(t, calls[0], poppyVerifyPath)
			if !equalJSON(calls[0].Body, c.ExpectedBody) {
				t.Errorf("body = %s\nwant   %s", calls[0].Raw, poppyJSON(t, c.ExpectedBody))
			}
		})

		// The explicit form takes the complete URL. It applies the same
		// header filter and drops a query that the caller left in.
		t.Run(c.Name+"/VerifyRequest", func(t *testing.T) {
			var calls []poppyCall
			client := newPoppyClient(t, poppyLumoAuth(&calls, poppyVerifiedAnswer(t)))
			publicURL, _ := c.ExpectedBody["url"].(string)
			request := PoppyRequest{Method: c.Incoming.Method, URL: publicURL + "?page=2#top", Headers: headers}
			if _, err := client.Poppy.VerifyRequest(ctx, request, opts); err != nil {
				t.Fatalf("VerifyRequest: %v", err)
			}
			if len(calls) != 1 {
				t.Fatalf("%d calls, want 1", len(calls))
			}
			assertPoppyCall(t, calls[0], poppyVerifyPath)
			if !equalJSON(calls[0].Body, c.ExpectedBody) {
				t.Errorf("body = %s\nwant   %s", calls[0].Raw, poppyJSON(t, c.ExpectedBody))
			}
		})
	}
}

// ── Vector: answer cases ──────────────────────────────────────────────

func assertPoppyVerified(t *testing.T, got *PoppyVerification, c poppyAnswerCase) {
	t.Helper()
	want := c.Expect
	if got == nil || !got.Active {
		t.Fatalf("expected a verified result, got %+v", got)
	}
	if got.ClientID != want.ClientID || got.ClientName != want.ClientName || got.UserID != want.UserID {
		t.Errorf("ClientID, ClientName, UserID = %q, %q, %q", got.ClientID, got.ClientName, got.UserID)
	}
	wantAgentID := ""
	if want.AgentID != nil {
		wantAgentID = *want.AgentID
	}
	if got.AgentID != wantAgentID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, wantAgentID)
	}
	if got.Session == nil {
		t.Fatal("a verified result has a Session")
	}
	wantSession := PoppySession{ID: want.SessionID, SID: want.SID, IsNew: want.SessionNew, StartedAt: want.StartedAt}
	if *got.Session != wantSession {
		t.Errorf("Session = %+v, want %+v", *got.Session, wantSession)
	}
	if got.SignedIn != want.SignedIn {
		t.Errorf("SignedIn = %v, want %v", got.SignedIn, want.SignedIn)
	}
	switch {
	case want.Account == nil:
		if got.Account != nil {
			t.Errorf("Account = %+v, want none", got.Account)
		}
	case got.Account == nil:
		t.Error("Account is missing")
	default:
		a := got.Account
		if a.Subject != want.Account.Sub || a.Scope != want.Account.Scope ||
			a.Expires != want.Account.Exp || a.TokenType != want.Account.TokenType {
			t.Errorf("Account = %+v", a)
		}
		if !equalJSON(a.Scopes(), want.Account.Scopes) {
			t.Errorf("Account.Scopes() = %v, want %v", a.Scopes(), want.Account.Scopes)
		}
		if !equalJSON(a.Audience, want.Account.Aud) {
			t.Errorf("Account.Audience = %v, want %v", a.Audience, want.Account.Aud)
		}
		for _, scope := range want.Account.Scopes {
			if !a.HasScope(scope) {
				t.Errorf("HasScope(%q) = false", scope)
			}
		}
	}
	if got.Version != want.Version {
		t.Errorf("Version = %q, want %q", got.Version, want.Version)
	}
	if got.Extensions == nil || !equalJSON(got.Extensions, want.Extensions) {
		t.Errorf("Extensions = %v, want %v", got.Extensions, want.Extensions)
	}
	if got.Error != "" || got.ErrorDescription != "" || got.Scope != "" || got.Response != nil {
		t.Errorf("a verified result carries refusal members: %+v", got)
	}
	if got.Raw["active"] != true {
		t.Errorf("Raw does not hold the decoded answer: %v", got.Raw)
	}
}

func assertPoppyRefused(t *testing.T, got *PoppyVerification, c poppyAnswerCase) {
	t.Helper()
	want := c.Expect
	if got == nil || got.Active {
		t.Fatalf("expected a refusal, got %+v", got)
	}
	if got.Error != want.Error || got.ErrorDescription != want.ErrorDescription {
		t.Errorf("Error, ErrorDescription = %q, %q", got.Error, got.ErrorDescription)
	}
	wantScope := ""
	if want.Scope != nil {
		wantScope = *want.Scope
	}
	if got.Scope != wantScope {
		t.Errorf("Scope = %q, want %q", got.Scope, wantScope)
	}
	if got.Response == nil || want.Relay == nil {
		t.Fatalf("Response = %+v, relay = %+v", got.Response, want.Relay)
	}
	if got.Response.Status != want.Relay.Status {
		t.Errorf("Response.Status = %d, want %d", got.Response.Status, want.Relay.Status)
	}
	if !equalJSON(got.Response.Headers, want.Relay.Headers) {
		t.Errorf("Response.Headers = %v, want %v", got.Response.Headers, want.Relay.Headers)
	}
	if (got.Response.Body == nil) != (want.Relay.Body == nil) || !equalJSON(got.Response.Body, want.Relay.Body) {
		t.Errorf("Response.Body = %v, want %v", got.Response.Body, want.Relay.Body)
	}
	if got.ClientID != "" || got.UserID != "" || got.Session != nil || got.Account != nil || got.SignedIn {
		t.Errorf("a refusal carries members of a verified result: %+v", got)
	}
}

func TestContractPoppyAnswerCases(t *testing.T) {
	vector := loadPoppyVector(t)
	ctx := context.Background()
	request := PoppyRequest{
		Method:  "GET",
		URL:     "https://shop.example.com/api/orders",
		Headers: http.Header{"Poppy-Session": {"session.jwt"}, "Poppy-Version": {"1.0"}, "Cookie": {"sid=abc"}},
	}

	for _, c := range vector.AnswerCases {
		t.Run(c.Name, func(t *testing.T) {
			var calls []poppyCall
			client := newPoppyClient(t, poppyLumoAuth(&calls, c.Answer))
			got, err := client.Poppy.VerifyRequest(ctx, request, &PoppyVerifyOptions{RequiredScope: []string{"orders:read"}})

			if len(calls) != 1 {
				t.Fatalf("%d calls, want 1", len(calls))
			}
			assertPoppyCall(t, calls[0], poppyVerifyPath)

			switch c.Expect.Outcome {
			case "verified":
				if err != nil {
					t.Fatalf("VerifyRequest: %v", err)
				}
				assertPoppyVerified(t, got, c)
			case "refused":
				if err != nil {
					t.Fatalf("a refusal is not an error: %v", err)
				}
				assertPoppyRefused(t, got, c)
			case "error":
				if got != nil {
					t.Errorf("an error must not come with a result: %+v", got)
				}
				poppyVectorError(t, err, c.Expect.ErrorClass, c.Expect.RetryAfter)
			default:
				t.Fatalf("the vector has an outcome that this test does not know: %q", c.Expect.Outcome)
			}
		})
	}
}

// ── Vector: Session lookup and ending a Session ───────────────────────

func TestContractPoppySessionStatusCases(t *testing.T) {
	vector := loadPoppyVector(t)
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}

	for _, c := range vector.SessionStatusCases {
		t.Run(c.Name, func(t *testing.T) {
			var calls []poppyCall
			client := newPoppyClient(t, poppyLumoAuth(&calls, c.Answer))
			got, err := client.Poppy.GetSessionStatus(context.Background(), c.Request["personal_agent"], c.Request["sid"])
			if err != nil {
				t.Fatalf("GetSessionStatus: %v", err)
			}
			if len(calls) != 1 {
				t.Fatalf("%d calls, want 1", len(calls))
			}
			assertPoppyCall(t, calls[0], poppyStatusPath)
			if !equalJSON(calls[0].Body, c.Request) {
				t.Errorf("body = %s, want %v", calls[0].Raw, c.Request)
			}

			want := c.Expect
			if got.Status != want.Status || got.UserID != text(want.UserID) || got.AgentID != text(want.AgentID) ||
				got.Account != text(want.Account) || got.SignedIn != want.SignedIn || got.LastSeenAt != text(want.LastSeenAt) {
				t.Errorf("status = %+v, want %+v", got, want)
			}
			if got.Active() != (want.Status == PoppyStatusActive) {
				t.Errorf("Active() = %v for the status %q", got.Active(), got.Status)
			}
			if got.Raw["status"] != want.Status {
				t.Errorf("Raw does not hold the decoded answer: %v", got.Raw)
			}
		})
	}
}

func TestContractPoppyEndSessionCases(t *testing.T) {
	vector := loadPoppyVector(t)

	for _, c := range vector.EndSessionCases {
		t.Run(c.Name, func(t *testing.T) {
			var calls []poppyCall
			client := newPoppyClient(t, poppyLumoAuth(&calls, c.Answer))
			ended, err := client.Poppy.EndSession(context.Background(), c.Request["personal_agent"], c.Request["sid"])
			if len(calls) != 1 {
				t.Fatalf("%d calls, want 1", len(calls))
			}
			assertPoppyCall(t, calls[0], poppyEndPath)
			if !equalJSON(calls[0].Body, c.Request) {
				t.Errorf("body = %s, want %v", calls[0].Raw, c.Request)
			}

			if c.Expect.ErrorClass != "" {
				if ended {
					t.Error("an error must not report an ended Session")
				}
				poppyVectorError(t, err, c.Expect.ErrorClass, 0)
				return
			}
			if c.Expect.Ended == nil {
				t.Fatal("the case expects neither a result nor an error")
			}
			if err != nil {
				t.Fatalf("EndSession: %v", err)
			}
			if ended != *c.Expect.Ended {
				t.Errorf("ended = %v, want %v", ended, *c.Expect.Ended)
			}
		})
	}
}

// ── Without the vector ────────────────────────────────────────────────

// poppyNoCall fails the test when a request reaches LumoAuth.
func poppyNoCall(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request should have been sent, got %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func TestBuildPoppyVerifyBody(t *testing.T) {
	headers := http.Header{
		"poppy-session":    {"session.jwt"},
		"POPPY-VERSION":    {"1.0"},
		"Poppy-Extensions": {"", "ext-one;v=\"1.0\"", "ext-two;v=\"2.1\""},
		"Authorization":    {"DPoP access.token"},
		"Dpop":             {"dpop.proof"},
		"Cookie":           {"sid=abc"},
		"X-Api-Key":        {"must-not-leave"},
		"X-Forwarded-Host": {"evil.example"},
		"Host":             {"evil.example"},
	}

	t.Run("the whole body", func(t *testing.T) {
		body, err := BuildPoppyVerifyBody("https://example.com/shop///", "post", "/api/orders/1?x=1#y", headers,
			&PoppyVerifyOptions{RequiredScope: []string{"orders:read", "", " orders:write "}, Resource: "https://example.com", AllowReplay: true})
		if err != nil {
			t.Fatalf("BuildPoppyVerifyBody: %v", err)
		}
		want := map[string]any{
			"method": "POST",
			"url":    "https://example.com/shop/api/orders/1",
			"headers": map[string]any{
				"poppy-session":    "session.jwt",
				"poppy-version":    "1.0",
				"poppy-extensions": "ext-one;v=\"1.0\", ext-two;v=\"2.1\"",
				"authorization":    "DPoP access.token",
				"dpop":             "dpop.proof",
			},
			"required_scope": "orders:read orders:write",
			"resource":       "https://example.com",
			"allow_replay":   true,
		}
		if !equalJSON(body, want) {
			t.Errorf("body = %s\nwant   %s", poppyJSON(t, body), poppyJSON(t, want))
		}
	})

	t.Run("nil options and nil headers", func(t *testing.T) {
		body, err := BuildPoppyVerifyBody("http://localhost:8787", "GET", "", nil, nil)
		if err != nil {
			t.Fatalf("BuildPoppyVerifyBody: %v", err)
		}
		want := map[string]any{"method": "GET", "url": "http://localhost:8787/", "headers": map[string]any{}}
		if !equalJSON(body, want) {
			t.Errorf("body = %s", poppyJSON(t, body))
		}
		// "headers" is a JSON object even when it is empty.
		if raw := string(poppyJSON(t, body)); !strings.Contains(raw, `"headers":{}`) {
			t.Errorf("an empty header set must be an object: %s", raw)
		}
	})

	t.Run("the path is kept as the client sent it", func(t *testing.T) {
		cases := map[string]string{
			"/api/files/a%20b/..%2Fc//d?x=1":         "https://shop.example.com/api/files/a%20b/..%2Fc//d",
			"/a/../b/./c%2f%2F":                      "https://shop.example.com/a/../b/./c%2f%2F",
			"/":                                      "https://shop.example.com/",
			"?only=query":                            "https://shop.example.com/",
			"#frag":                                  "https://shop.example.com/",
			"//evil.example/x":                       "https://shop.example.com//evil.example/x",
			"/redirect?to=https://evil.example/":     "https://shop.example.com/redirect",
			"https://evil.example/api/orders?x=1":    "https://shop.example.com/api/orders",
			"HTTP://evil.example":                    "https://shop.example.com/",
			"http://evil.example:8080/a%20b#frag":    "https://shop.example.com/a%20b",
			"/api/path-with-colon://not-a-scheme/x":  "https://shop.example.com/api/path-with-colon://not-a-scheme/x",
			"/api/orders/%E2%82%AC?q=http://x.test/": "https://shop.example.com/api/orders/%E2%82%AC",
		}
		for target, want := range cases {
			body, err := BuildPoppyVerifyBody("https://shop.example.com", "GET", target, nil, nil)
			if err != nil {
				t.Errorf("%q: %v", target, err)
				continue
			}
			if body["url"] != want {
				t.Errorf("%q: url = %q, want %q", target, body["url"], want)
			}
		}
	})

	t.Run("a target that is not a path is refused", func(t *testing.T) {
		for _, target := range []string{"*", "shop.example.com:443", "api/orders", "ftp://host/x"} {
			if _, err := BuildPoppyVerifyBody("https://shop.example.com", "GET", target, nil, nil); !errors.Is(err, ErrValidation) {
				t.Errorf("%q: expected a validation error, got %v", target, err)
			}
		}
	})

	t.Run("a missing method is refused", func(t *testing.T) {
		if _, err := BuildPoppyVerifyBody("https://shop.example.com", " ", "/", nil, nil); !errors.Is(err, ErrValidation) {
			t.Errorf("expected a validation error, got %v", err)
		}
	})

	t.Run("a missing or malformed public origin is a configuration error", func(t *testing.T) {
		for _, origin := range []string{
			"", "  ", "/", "shop.example.com", "//shop.example.com", "ftp://shop.example.com", "https://",
			"https:///path", "https://user:pw@shop.example.com", "https://shop.example.com?x=1",
			"https://shop.example.com/#top", "https://shop.example.com/a?",
		} {
			if _, err := BuildPoppyVerifyBody(origin, "GET", "/", nil, nil); !errors.Is(err, ErrConfig) {
				t.Errorf("%q: expected a configuration error, got %v", origin, err)
			}
		}
	})

	t.Run("names that differ only in case are joined in a fixed order", func(t *testing.T) {
		mixed := http.Header{"poppy-extensions": {"c"}, "Poppy-Extensions": {"b"}, "POPPY-EXTENSIONS": {"a"}}
		for i := 0; i < 20; i++ {
			body, _ := BuildPoppyVerifyBody("https://shop.example.com", "GET", "/", mixed, nil)
			if got := body["headers"].(map[string]string)["poppy-extensions"]; got != "a, b, c" {
				t.Fatalf("poppy-extensions = %q", got)
			}
		}
	})
}

func TestPoppyCredentials(t *testing.T) {
	ctx := context.Background()
	request := PoppyRequest{Method: "GET", URL: "https://shop.example.com/", Headers: http.Header{}}

	// Every call of the namespace, so a new one cannot skip the check.
	calls := map[string]func(c *Client) error{
		"VerifyRequest": func(c *Client) error {
			_, err := c.Poppy.VerifyRequest(ctx, request, nil)
			return err
		},
		"VerifyHTTPRequest": func(c *Client) error {
			_, err := c.Poppy.VerifyHTTPRequest(ctx, "https://shop.example.com", httptest.NewRequest("GET", "/", nil), nil)
			return err
		},
		"GetSessionStatus": func(c *Client) error {
			_, err := c.Poppy.GetSessionStatus(ctx, "https://agent.example/agent.json", "sid")
			return err
		},
		"EndSession": func(c *Client) error {
			_, err := c.Poppy.EndSession(ctx, "https://agent.example/agent.json", "sid")
			return err
		},
		"Middleware": func(c *Client) error {
			_, err := c.Poppy.Middleware(PoppyMiddlewareOptions{PublicOrigin: "https://shop.example.com"})
			return err
		},
	}

	t.Run("missing credentials are a configuration error before any call", func(t *testing.T) {
		// An API key and a bearer token do not stand in for them.
		client, _ := newTestClient(t, poppyNoCall(t), WithAccessToken(poppyTestAccessToken))
		for name, call := range calls {
			err := call(client)
			if !errors.Is(err, ErrConfig) {
				t.Errorf("%s: expected a configuration error, got %v", name, err)
				continue
			}
			if !strings.Contains(err.Error(), "poppy:verify") || !strings.Contains(err.Error(), "WithClientCredentials") {
				t.Errorf("%s: the error must name the scope and the option: %v", name, err)
			}
		}
	})

	t.Run("a client ID with a colon is refused before any call", func(t *testing.T) {
		client, _ := newTestClient(t, poppyNoCall(t), WithClientCredentials("https://agent.example/agent.json", "secret"))
		for name, call := range calls {
			if err := call(client); !errors.Is(err, ErrConfig) {
				t.Errorf("%s: expected a configuration error, got %v", name, err)
			}
		}
	})

	t.Run("New refuses half of the credentials", func(t *testing.T) {
		for _, opt := range []Option{WithClientCredentials("shop-api", ""), WithClientCredentials("", "secret")} {
			if _, err := New(WithAPIKey("lmk_x"), WithOrgID("acme-corp"), opt); !errors.Is(err, ErrConfig) {
				t.Errorf("expected a configuration error, got %v", err)
			}
		}
	})

	t.Run("client credentials alone are enough for New", func(t *testing.T) {
		t.Setenv(EnvAPIKey, "")
		var got []poppyCall
		server := httptest.NewServer(poppyLumoAuth(&got, poppyVerifiedAnswer(t)))
		t.Cleanup(server.Close)
		client, err := New(WithBaseURL(server.URL), WithOrgID("acme-corp"),
			WithClientCredentials(poppyTestClientID, poppyTestClientSecret))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := client.Poppy.VerifyRequest(ctx, request, nil); err != nil {
			t.Fatalf("VerifyRequest: %v", err)
		}
		assertPoppyCall(t, got[0], poppyVerifyPath)
	})

	t.Run("no other credential is sent, whatever the client holds", func(t *testing.T) {
		signer, err := NewDPoPSigner()
		if err != nil {
			t.Fatal(err)
		}
		var got []poppyCall
		client := newPoppyClient(t, poppyLumoAuth(&got, poppyVerifiedAnswer(t)),
			WithDPoP(signer),
			WithHeader("X-API-Key", poppyTestAPIKey),
			WithHeader("Authorization", "Bearer "+poppyTestAccessToken),
			WithTokenProvider(func(context.Context) (string, error) {
				t.Error("the token provider must not be asked for a Personal Agent Protocol call")
				return poppyTestAccessToken, nil
			}),
		)
		if _, err := client.Poppy.VerifyRequest(ctx, request, nil); err != nil {
			t.Fatalf("VerifyRequest: %v", err)
		}
		if _, err := client.Poppy.GetSessionStatus(ctx, "https://agent.example/agent.json", "sid"); !errors.Is(err, ErrValidation) {
			// The verified answer is not a Session status: that is fine
			// here, the call itself is what the test looks at.
			t.Fatalf("GetSessionStatus: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("%d calls, want 2", len(got))
		}
		assertPoppyCall(t, got[0], poppyVerifyPath)
		assertPoppyCall(t, got[1], poppyStatusPath)
	})

	t.Run("the other namespaces keep their own credential", func(t *testing.T) {
		var header http.Header
		client := newPoppyClient(t, func(w http.ResponseWriter, r *http.Request) {
			header = r.Header.Clone()
			writeJSON(w, 200, map[string]any{"allowed": true})
		})
		if _, err := client.Permissions.Check(ctx, "document.edit", nil); err != nil {
			t.Fatalf("Check: %v", err)
		}
		if header.Get("Authorization") != "Bearer "+poppyTestAccessToken {
			t.Errorf("Authorization = %q: the client credentials must not leave the Poppy namespace", header.Get("Authorization"))
		}
	})

	t.Run("the client of WebAuth uses the web application's credentials", func(t *testing.T) {
		var got []poppyCall
		server := httptest.NewServer(poppyLumoAuth(&got, poppyVerifiedAnswer(t)))
		t.Cleanup(server.Close)
		auth, err := NewWebAuth(WebConfig{
			BaseURL: server.URL, Organization: "acme-corp", SessionSecret: strings.Repeat("s", 32),
			ClientID: poppyTestClientID, ClientSecret: poppyTestClientSecret,
		})
		if err != nil {
			t.Fatalf("NewWebAuth: %v", err)
		}
		if _, err := auth.Client().Poppy.VerifyRequest(ctx, request, nil); err != nil {
			t.Fatalf("VerifyRequest: %v", err)
		}
		assertPoppyCall(t, got[0], poppyVerifyPath)
	})

	t.Run("an organization is required", func(t *testing.T) {
		t.Setenv(EnvOrgID, "")
		client, err := New(WithBaseURL("https://lumoauth.invalid"), WithClientCredentials("shop-api", "secret"))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		for name, call := range calls {
			if err := call(client); !errors.Is(err, ErrConfig) {
				t.Errorf("%s: expected a configuration error, got %v", name, err)
			}
		}
	})
}

func TestPoppyArgumentsAreCheckedBeforeAnyCall(t *testing.T) {
	ctx := context.Background()
	client := newPoppyClient(t, poppyNoCall(t))

	bad := map[string]func() error{
		"no method": func() error {
			_, err := client.Poppy.VerifyRequest(ctx, PoppyRequest{URL: "https://shop.example.com/"}, nil)
			return err
		},
		"no URL": func() error {
			_, err := client.Poppy.VerifyRequest(ctx, PoppyRequest{Method: "GET", URL: " "}, nil)
			return err
		},
		"no request": func() error {
			_, err := client.Poppy.VerifyHTTPRequest(ctx, "https://shop.example.com", nil, nil)
			return err
		},
		"status without a personal agent": func() error {
			_, err := client.Poppy.GetSessionStatus(ctx, "", "sid")
			return err
		},
		"status without a sid": func() error {
			_, err := client.Poppy.GetSessionStatus(ctx, "https://agent.example/agent.json", "")
			return err
		},
		"end without a personal agent": func() error {
			_, err := client.Poppy.EndSession(ctx, "", "sid")
			return err
		},
		"end without a sid": func() error {
			_, err := client.Poppy.EndSession(ctx, "https://agent.example/agent.json", "")
			return err
		},
	}
	for name, call := range bad {
		if err := call(); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: expected a validation error, got %v", name, err)
		}
	}

	if _, err := client.Poppy.VerifyHTTPRequest(ctx, "", httptest.NewRequest("GET", "/", nil), nil); !errors.Is(err, ErrConfig) {
		t.Errorf("a missing public origin is a configuration error, got %v", err)
	}
}

// TestPoppyAnswersFailClosed holds the shapes that the vector does not
// list. None of them may come back as a verified result.
func TestPoppyAnswersFailClosed(t *testing.T) {
	ctx := context.Background()
	request := PoppyRequest{Method: "GET", URL: "https://shop.example.com/", Headers: http.Header{}}

	session := map[string]any{"id": 4821, "sid": "sid-1", "new": false, "started_at": "2026-11-26T10:15:00+00:00"}
	account := map[string]any{"sub": "user-1", "scope": "orders:read", "aud": []any{"https://shop.example.com"}, "exp": 1795000000, "token_type": "Bearer"}
	verified := func(change func(body map[string]any)) map[string]any {
		body := map[string]any{
			"active": true, "client_id": "https://agent.example/agent.json", "user_id": "usr_1",
			"session": session, "signed_in": false, "account": nil,
		}
		change(body)
		return body
	}
	refused := func(change func(body, response map[string]any)) map[string]any {
		response := map[string]any{
			"status": 400, "headers": map[string]any{"Cache-Control": "no-store"},
			"body": map[string]any{"error": "invalid_session"},
		}
		body := map[string]any{"active": false, "error": "invalid_session", "response": response}
		change(body, response)
		return body
	}

	malformed := map[string]any{
		"not an object":   []any{map[string]any{"active": true}},
		"a JSON string":   "active",
		"active is null":  verified(func(b map[string]any) { b["active"] = nil }),
		"active is 1":     verified(func(b map[string]any) { b["active"] = 1 }),
		"no client_id":    verified(func(b map[string]any) { delete(b, "client_id") }),
		"empty client_id": verified(func(b map[string]any) { b["client_id"] = "" }),
		"client_id is a number": verified(func(b map[string]any) {
			b["client_id"] = 7
		}),
		"no user_id":            verified(func(b map[string]any) { delete(b, "user_id") }),
		"session is null":       verified(func(b map[string]any) { b["session"] = nil }),
		"session is a list":     verified(func(b map[string]any) { b["session"] = []any{} }),
		"session without id":    verified(func(b map[string]any) { b["session"] = map[string]any{"sid": "sid-1"} }),
		"session id is text":    verified(func(b map[string]any) { b["session"] = map[string]any{"id": "4821", "sid": "sid-1"} }),
		"session id fractional": verified(func(b map[string]any) { b["session"] = map[string]any{"id": 48.5, "sid": "sid-1"} }),
		"session without sid":   verified(func(b map[string]any) { b["session"] = map[string]any{"id": 4821} }),
		"session new is text":   verified(func(b map[string]any) { b["session"] = map[string]any{"id": 4821, "sid": "sid-1", "new": "no"} }),
		"signed in without an account": verified(func(b map[string]any) {
			b["signed_in"] = true
		}),
		"account without signed_in true": verified(func(b map[string]any) {
			b["account"] = account
		}),
		"signed_in is text": verified(func(b map[string]any) { b["signed_in"] = "false" }),
		"account is a string": verified(func(b map[string]any) {
			b["signed_in"], b["account"] = true, "user-1"
		}),
		"account without sub": verified(func(b map[string]any) {
			b["signed_in"], b["account"] = true, map[string]any{"scope": "orders:read"}
		}),
		"account aud is a string": verified(func(b map[string]any) {
			b["signed_in"], b["account"] = true, map[string]any{"sub": "user-1", "aud": "https://shop.example.com"}
		}),
		"account exp is text": verified(func(b map[string]any) {
			b["signed_in"], b["account"] = true, map[string]any{"sub": "user-1", "exp": "soon"}
		}),
		"extensions is a list": verified(func(b map[string]any) { b["extensions"] = []any{"ext-one"} }),
		"extension version is a number": verified(func(b map[string]any) {
			b["extensions"] = map[string]any{"ext-one": 1.0}
		}),

		"refusal without error":    refused(func(b, r map[string]any) { delete(b, "error") }),
		"refusal error is empty":   refused(func(b, r map[string]any) { b["error"] = "" }),
		"refusal scope is a list":  refused(func(b, r map[string]any) { b["scope"] = []any{"orders:read"} }),
		"response is null":         refused(func(b, r map[string]any) { b["response"] = nil }),
		"response is a string":     refused(func(b, r map[string]any) { b["response"] = "400" }),
		"response without status":  refused(func(b, r map[string]any) { delete(r, "status") }),
		"response status is text":  refused(func(b, r map[string]any) { r["status"] = "400" }),
		"response status is 200":   refused(func(b, r map[string]any) { r["status"] = 200 }),
		"response status is 302":   refused(func(b, r map[string]any) { r["status"] = 302 }),
		"response status is 1000":  refused(func(b, r map[string]any) { r["status"] = 1000 }),
		"response without headers": refused(func(b, r map[string]any) { delete(r, "headers") }),
		"response headers a list":  refused(func(b, r map[string]any) { r["headers"] = []any{} }),
		"response header a number": refused(func(b, r map[string]any) { r["headers"] = map[string]any{"Retry-After": 42} }),
		"response body is a list":  refused(func(b, r map[string]any) { r["body"] = []any{} }),
		"response body is text":    refused(func(b, r map[string]any) { r["body"] = "invalid_session" }),
	}
	for name, body := range malformed {
		t.Run(name, func(t *testing.T) {
			var calls []poppyCall
			client := newPoppyClient(t, poppyLumoAuth(&calls, poppyAnswer{Status: 200, Body: poppyJSON(t, body)}))
			got, err := client.Poppy.VerifyRequest(ctx, request, nil)
			if got != nil || !errors.Is(err, ErrValidation) || errors.Is(err, ErrAPI) {
				t.Fatalf("got %+v, err %v; want a validation error and no result", got, err)
			}

			// Decoding by hand is no way around the checks.
			var direct PoppyVerification
			if err := json.Unmarshal(poppyJSON(t, body), &direct); err == nil {
				t.Errorf("json.Unmarshal accepted the answer: %+v", direct)
			}
			if direct.Active {
				t.Error("a refused decoding left Active set")
			}
		})
	}

	t.Run("a body that is not JSON", func(t *testing.T) {
		for _, raw := range []string{"", "<html>verified</html>", `{"active": true`, "null"} {
			var calls []poppyCall
			client := newPoppyClient(t, poppyLumoAuth(&calls, poppyAnswer{Status: 200, Body: json.RawMessage(raw)}))
			got, err := client.Poppy.VerifyRequest(ctx, request, nil)
			if got != nil || !errors.Is(err, ErrValidation) {
				t.Errorf("%q: got %+v, err %v", raw, got, err)
			}
		}
	})

	t.Run("a success status other than 200 is not a result", func(t *testing.T) {
		for _, status := range []int{201, 202, 204, 206} {
			var calls []poppyCall
			answer := poppyVerifiedAnswer(t)
			answer.Status = status
			client := newPoppyClient(t, poppyLumoAuth(&calls, answer))
			got, err := client.Poppy.VerifyRequest(ctx, request, nil)
			if got != nil || !errors.Is(err, ErrValidation) {
				t.Errorf("%d: got %+v, err %v", status, got, err)
			}
			if ended, err := client.Poppy.EndSession(ctx, "https://agent.example/agent.json", "sid"); ended || err == nil {
				t.Errorf("%d: EndSession = %v, %v", status, ended, err)
			}
		}
	})

	t.Run("an error status with a verified body is an error", func(t *testing.T) {
		for _, status := range []int{400, 401, 403, 404, 429, 500, 502, 503} {
			var calls []poppyCall
			answer := poppyVerifiedAnswer(t)
			answer.Status = status
			client := newPoppyClient(t, poppyLumoAuth(&calls, answer))
			got, err := client.Poppy.VerifyRequest(ctx, request, nil)
			if got != nil || !errors.Is(err, ErrAPI) || StatusCode(err) != status {
				t.Errorf("%d: got %+v, err %v", status, got, err)
			}
		}
	})

	t.Run("LumoAuth is not reachable", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		server.Close()
		client, err := New(WithBaseURL(server.URL), WithOrgID("acme-corp"), WithClientCredentials("shop-api", "secret"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := client.Poppy.VerifyRequest(ctx, request, nil)
		if got != nil || !errors.Is(err, ErrNetwork) {
			t.Errorf("got %+v, err %v; want a network error", got, err)
		}
	})

	t.Run("a tolerated answer: members that the server may leave out", func(t *testing.T) {
		body := map[string]any{
			"active": true, "client_id": "https://agent.example/agent.json", "user_id": "usr_1",
			"session": map[string]any{"id": 4821, "sid": "sid-1"},
			"account": map[string]any{"sub": "user-1", "exp": nil},
			"later":   map[string]any{"added": "by a later server"},
		}
		var calls []poppyCall
		client := newPoppyClient(t, poppyLumoAuth(&calls, poppyAnswer{Status: 200, Body: poppyJSON(t, body)}))
		got, err := client.Poppy.VerifyRequest(ctx, request, nil)
		if err != nil {
			t.Fatalf("VerifyRequest: %v", err)
		}
		if !got.Active || !got.SignedIn || got.Account.Subject != "user-1" || got.Account.Expires != 0 ||
			got.Account.Audience == nil || len(got.Account.Scopes()) != 0 || got.Extensions == nil ||
			got.Session.IsNew || got.Raw["later"] == nil {
			t.Errorf("verification = %+v, account = %+v", got, got.Account)
		}
	})
}

func TestPoppySessionAnswersFailClosed(t *testing.T) {
	ctx := context.Background()
	agent, sid := "https://agent.example/agent.json", "sid-1"

	t.Run("status", func(t *testing.T) {
		for name, body := range map[string]any{
			"no status":         map[string]any{"signed_in": true},
			"status is null":    map[string]any{"status": nil, "signed_in": true},
			"status is empty":   map[string]any{"status": "", "signed_in": true},
			"status is a bool":  map[string]any{"status": true, "signed_in": true},
			"signed_in is text": map[string]any{"status": "active", "signed_in": "true"},
			"account an object": map[string]any{"status": "active", "account": map[string]any{"sub": "user-1"}},
			"a list":            []any{},
		} {
			var calls []poppyCall
			client := newPoppyClient(t, poppyLumoAuth(&calls, poppyAnswer{Status: 200, Body: poppyJSON(t, body)}))
			got, err := client.Poppy.GetSessionStatus(ctx, agent, sid)
			if got != nil || !errors.Is(err, ErrValidation) {
				t.Errorf("%s: got %+v, err %v", name, got, err)
			}
		}
	})

	t.Run("a status that this SDK does not know is passed on and is not active", func(t *testing.T) {
		var calls []poppyCall
		client := newPoppyClient(t, poppyLumoAuth(&calls, poppyAnswer{Status: 200, Body: poppyJSON(t, map[string]any{"status": "paused"})}))
		got, err := client.Poppy.GetSessionStatus(ctx, agent, sid)
		if err != nil || got.Status != "paused" || got.Active() || got.SignedIn {
			t.Errorf("got %+v, err %v", got, err)
		}
	})

	t.Run("end", func(t *testing.T) {
		for name, body := range map[string]any{
			"no ended":      map[string]any{},
			"ended is text": map[string]any{"ended": "true"},
			"ended is null": map[string]any{"ended": nil},
			"ended is 1":    map[string]any{"ended": 1},
			"a list":        []any{true},
		} {
			var calls []poppyCall
			client := newPoppyClient(t, poppyLumoAuth(&calls, poppyAnswer{Status: 200, Body: poppyJSON(t, body)}))
			ended, err := client.Poppy.EndSession(ctx, agent, sid)
			if ended || !errors.Is(err, ErrValidation) {
				t.Errorf("%s: ended = %v, err %v", name, ended, err)
			}
		}
	})

	t.Run("errors of the calling application", func(t *testing.T) {
		for status, sentinel := range map[int]error{401: ErrAuthentication, 403: ErrPermissionDenied, 404: ErrNotFound, 429: ErrRateLimited} {
			var calls []poppyCall
			answer := poppyAnswer{Status: status, Headers: map[string]string{"Retry-After": "7"},
				Body: poppyJSON(t, map[string]any{"error": "refused", "status": "active", "ended": true})}
			client := newPoppyClient(t, poppyLumoAuth(&calls, answer))
			if got, err := client.Poppy.GetSessionStatus(ctx, agent, sid); got != nil || !errors.Is(err, sentinel) {
				t.Errorf("%d: status = %+v, err %v", status, got, err)
			}
			ended, err := client.Poppy.EndSession(ctx, agent, sid)
			if ended || !errors.Is(err, sentinel) {
				t.Errorf("%d: ended = %v, err %v", status, ended, err)
			}
			if apiErr, ok := AsAPIError(err); status == 429 && (!ok || apiErr.RetryAfter != 7*time.Second) {
				t.Errorf("RetryAfter = %v", apiErr)
			}
		}
	})
}
