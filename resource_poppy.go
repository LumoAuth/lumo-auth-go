package lumoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Personal Agent Protocol ("Poppy" 1.0, https://personalagentprotocol.org)
// for an organization's own API.
//
// A personal agent sends the Poppy-Session header to your API, not to
// LumoAuth. Your API forwards the method, the public URL and five protocol
// headers, and LumoAuth answers with who the request is from, or with the
// exact HTTP response that the personal agent must get. The behaviour is
// fixed by sdk-contract/vectors/poppy-verification.json.

// poppyForwardedHeaderNames are the request headers that the protocol
// reads, in lower case. VerifyRequest and BuildPoppyVerifyBody send these
// and no other header, so a cookie or an API key of the incoming request
// never reaches LumoAuth. The list is not exported: nothing outside this
// file may add a header to it.
var poppyForwardedHeaderNames = [...]string{"poppy-session", "poppy-version", "poppy-extensions", "authorization", "dpop"}

// PoppyResource verifies requests from personal agents, and looks up and
// ends their Sessions.
//
// Its three calls authenticate as one of your organization's confidential
// applications, with HTTP Basic: the client ID and the client secret of
// WithClientCredentials. The application's allowed scopes must include
// poppy:verify. The calls never send the client's bearer token or API key.
//
//	client, err := lumoauth.New(
//	    lumoauth.WithOrgID("acme-corp"),
//	    lumoauth.WithClientCredentials(clientID, clientSecret),
//	)
//
// On a net/http server, Middleware does the whole job for a route.
type PoppyResource struct {
	http         *httpClient
	clientID     string
	clientSecret string
}

// PoppyRequest is a request that a personal agent sent to your API.
type PoppyRequest struct {
	// Method is the method of the request. Required.
	Method string
	// URL is the public address that the personal agent called, for example
	// "https://shop.example.com/api/orders". Build it from your configured
	// public origin and the request path, never from the Host header. The
	// query and the fragment are dropped. Required.
	URL string
	// Headers are the headers of the request. You can pass all of them:
	// only Poppy-Session, Poppy-Version, Poppy-Extensions, Authorization
	// and DPoP are sent.
	Headers http.Header
}

// PoppyVerifyOptions are the checks that one operation asks for.
type PoppyVerifyOptions struct {
	// RequiredScope lists the scopes that the operation needs. An entry may
	// also hold several scopes separated by spaces. Leave it empty for an
	// operation that works signed out.
	RequiredScope []string
	// Resource is the resource identifier of your service. Set it when the
	// service takes only access tokens that were issued for it, as an MCP
	// server does.
	Resource string
	// AllowReplay accepts a Session JWT that was verified before. Use it
	// only when one request is verified in several places.
	AllowReplay bool
}

// VerifyRequest asks LumoAuth who a request from a personal agent is from.
//
//	verification, err := client.Poppy.VerifyRequest(ctx, lumoauth.PoppyRequest{
//	    Method:  r.Method,
//	    URL:     "https://shop.example.com" + r.URL.EscapedPath(),
//	    Headers: r.Header,
//	}, &lumoauth.PoppyVerifyOptions{RequiredScope: []string{"orders:read"}})
//	if err != nil {
//	    http.Error(w, "internal error", http.StatusInternalServerError)
//	    return
//	}
//	if !verification.Active {
//	    lumoauth.WritePoppyRefusal(w, verification)
//	    return
//	}
//
// A refusal is not an error. It comes back with Active set to false and the
// response to send in Response. An error means that the call itself failed:
// the SDK could not reach LumoAuth, or LumoAuth rejected your application
// (401, 403, 404 or 429). Never send such an error to the personal agent.
// An answer that is neither a verified result nor a well-formed refusal is
// an error too.
//
// opts may be nil.
func (r *PoppyResource) VerifyRequest(ctx context.Context, request PoppyRequest, opts *PoppyVerifyOptions) (*PoppyVerification, error) {
	if strings.TrimSpace(request.URL) == "" {
		return nil, NewValidationError("a URL is required: the public address that the personal agent called")
	}
	body, err := poppyVerifyBody(request.Method, request.URL, request.Headers, opts)
	if err != nil {
		return nil, err
	}
	return r.verify(ctx, body)
}

// VerifyHTTPRequest is VerifyRequest for a *http.Request. It builds the URL
// from publicOrigin and the request target as the client sent it (see
// BuildPoppyVerifyBody), and it does not read the request body.
//
//	verification, err := client.Poppy.VerifyHTTPRequest(ctx, "https://shop.example.com", r, nil)
//
// Take publicOrigin from your configuration.
func (r *PoppyResource) VerifyHTTPRequest(ctx context.Context, publicOrigin string, req *http.Request, opts *PoppyVerifyOptions) (*PoppyVerification, error) {
	if req == nil {
		return nil, NewValidationError("a request is required")
	}
	body, err := BuildPoppyVerifyBody(publicOrigin, req.Method, poppyRequestTarget(req), req.Header, opts)
	if err != nil {
		return nil, err
	}
	return r.verify(ctx, body)
}

func (r *PoppyResource) verify(ctx context.Context, body map[string]any) (*PoppyVerification, error) {
	var verification PoppyVerification
	if err := r.post(ctx, RoutePoppyVerifyRequest, body, &verification); err != nil {
		return nil, err
	}
	return &verification, nil
}

// GetSessionStatus says whether a Session still stands and whether its
// account is still signed in to the personal agent. It needs no request
// from the personal agent. personalAgent is the ClientID of a verified
// result, and sid is its Session.SID.
//
// An unknown Session is not an error: Status is PoppyStatusUnknown.
func (r *PoppyResource) GetSessionStatus(ctx context.Context, personalAgent, sid string) (*PoppySessionStatus, error) {
	body, err := poppySessionBody(personalAgent, sid)
	if err != nil {
		return nil, err
	}
	var status PoppySessionStatus
	if err := r.post(ctx, RoutePoppyGetSessionStatus, body, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// EndSession ends a Session. Later requests with its sid are refused with
// session_ended, and the personal agent starts a new Session. The user
// stays signed in.
//
// It returns false when the Session had ended before. An unknown Session is
// an error that matches ErrNotFound.
func (r *PoppyResource) EndSession(ctx context.Context, personalAgent, sid string) (bool, error) {
	body, err := poppySessionBody(personalAgent, sid)
	if err != nil {
		return false, err
	}
	var answer poppyEndAnswer
	if err := r.post(ctx, RoutePoppyEndSession, body, &answer); err != nil {
		return false, err
	}
	return answer.ended, nil
}

// credentials returns the client ID and secret for HTTP Basic, or the
// configuration error that names what is missing.
func (r *PoppyResource) credentials() (*basicCredentials, error) {
	if r.clientID == "" || r.clientSecret == "" {
		return nil, NewConfigError(
			"the Personal Agent Protocol calls need the client ID and the client secret of a " +
				"confidential application whose allowed scopes include poppy:verify: " +
				"pass WithClientCredentials to lumoauth.New")
	}
	if strings.Contains(r.clientID, ":") {
		return nil, NewConfigError(
			"the client ID contains a colon, which HTTP Basic cannot carry: use a confidential " +
				"application of your organization whose allowed scopes include poppy:verify")
	}
	return &basicCredentials{id: r.clientID, secret: r.clientSecret}, nil
}

// post sends one Personal Agent Protocol call with HTTP Basic and decodes
// a 200 answer into out. Any other status is an error: an *APIError for an
// error status, a *ValidationError for another 2xx status. A 200 answer
// that out cannot decode is a *ValidationError.
func (r *PoppyResource) post(ctx context.Context, route string, body map[string]any, out any) error {
	basic, err := r.credentials()
	if err != nil {
		return err
	}
	method, path, err := r.http.resolve(route, nil)
	if err != nil {
		return err
	}
	resp, err := r.http.doRaw(ctx, method, path, &request{JSON: body, Basic: basic})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return newNetworkError(fmt.Sprintf("reading response from %s failed: %v", path, readErr), readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiErrorFromResponse(resp, raw)
	}
	if resp.StatusCode != http.StatusOK {
		return validationErrorf("unexpected status %d from %s: the endpoint answers 200", resp.StatusCode, path)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return validationErrorf("unexpected answer from %s: %v", path, err)
	}
	return nil
}

// ── Request bodies ────────────────────────────────────────────────────

// BuildPoppyVerifyBody builds the JSON body of a verification call for an
// incoming request. It is a pure function: it makes no call and reads no
// configuration.
//
//   - method is sent in upper case.
//   - url is publicOrigin without trailing slashes, followed by the path of
//     target as the client sent it. The query and the fragment are dropped,
//     and an empty path is "/". publicOrigin may carry a base path. The URL
//     is never built from the Host header.
//   - headers holds only Poppy-Session, Poppy-Version, Poppy-Extensions,
//     Authorization and DPoP, matched without regard to case, under their
//     lower-case names. A repeated header is joined with ", ". A missing
//     or empty header is left out.
//   - required_scope, resource and allow_replay are sent only when opts
//     sets them.
//
// target is the request target of the request line, for example
// "/api/orders?page=2". On a net/http server that is r.RequestURI.
//
// It returns a *ConfigError for a missing or invalid publicOrigin and a
// *ValidationError for a missing method or a target that is not a path.
// opts may be nil.
func BuildPoppyVerifyBody(publicOrigin, method, target string, headers http.Header, opts *PoppyVerifyOptions) (map[string]any, error) {
	origin, err := poppyPublicOrigin(publicOrigin)
	if err != nil {
		return nil, err
	}
	path, err := poppyTargetPath(target)
	if err != nil {
		return nil, err
	}
	return poppyVerifyBody(method, origin+path, headers, opts)
}

// poppyVerifyBody builds the body from a complete URL. VerifyRequest and
// BuildPoppyVerifyBody share it, so both apply the same header filter.
func poppyVerifyBody(method, requestURL string, headers http.Header, opts *PoppyVerifyOptions) (map[string]any, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return nil, NewValidationError("a method is required: the method of the request that the personal agent sent")
	}
	body := map[string]any{
		"method":  method,
		"url":     poppyWithoutQuery(strings.TrimSpace(requestURL)),
		"headers": poppyForwardedHeaders(headers),
	}
	if opts != nil {
		if scope := poppyScope(opts.RequiredScope); scope != "" {
			body["required_scope"] = scope
		}
		if opts.Resource != "" {
			body["resource"] = opts.Resource
		}
		if opts.AllowReplay {
			body["allow_replay"] = true
		}
	}
	return body, nil
}

// poppySessionBody builds the body of a Session lookup or of ending one.
func poppySessionBody(personalAgent, sid string) (map[string]any, error) {
	if personalAgent == "" {
		return nil, NewValidationError("a personal agent is required: pass the ClientID of the verified result")
	}
	if sid == "" {
		return nil, NewValidationError("a Session ID is required: pass Session.SID of the verified result")
	}
	return map[string]any{"personal_agent": personalAgent, "sid": sid}, nil
}

// poppyPublicOrigin validates the configured public origin and removes its
// trailing slashes.
func poppyPublicOrigin(publicOrigin string) (string, error) {
	origin := strings.TrimRight(strings.TrimSpace(publicOrigin), "/")
	if origin == "" {
		return "", NewConfigError(
			"a public origin is required: the address that personal agents call, for example " +
				"\"https://shop.example.com\". Take it from your configuration, never from the Host header")
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" ||
		parsed.User != nil || strings.ContainsAny(origin, "?#") {
		return "", NewConfigError(
			"the public origin must be an http(s) address without credentials, query or fragment, " +
				"for example \"https://shop.example.com\"")
	}
	return origin, nil
}

// poppyTargetPath returns the path of a request target as the client sent
// it: no decoding, no cleaning. The query and the fragment are dropped, and
// an empty path is "/". An absolute-form target ("https://host/path") gives
// its path.
func poppyTargetPath(target string) (string, error) {
	path := poppyWithoutQuery(target)
	if scheme, rest, found := strings.Cut(path, "://"); found && (strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")) {
		// Absolute-form (RFC 9112, section 3.2.2): drop the authority. The
		// host of the URL still comes from the public origin.
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			return "/", nil
		}
		path = rest[slash:]
	}
	if path == "" {
		return "/", nil
	}
	if !strings.HasPrefix(path, "/") {
		return "", NewValidationError("the request target is not a path: it must start with \"/\"")
	}
	return path, nil
}

// poppyWithoutQuery cuts a URL or a request target at its query or
// fragment.
func poppyWithoutQuery(value string) string {
	if cut := strings.IndexAny(value, "?#"); cut >= 0 {
		return value[:cut]
	}
	return value
}

// poppyForwardedHeaders keeps the protocol's headers and nothing else.
// Header names are matched without regard to case, so a hand-built
// http.Header with non-canonical keys works too.
func poppyForwardedHeaders(headers http.Header) map[string]string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	// A fixed order for names that differ only in case.
	sort.Strings(names)

	forwarded := map[string]string{}
	for _, wanted := range poppyForwardedHeaderNames {
		var values []string
		for _, name := range names {
			if !strings.EqualFold(name, wanted) {
				continue
			}
			for _, value := range headers[name] {
				if value != "" {
					values = append(values, value)
				}
			}
		}
		if len(values) > 0 {
			forwarded[wanted] = strings.Join(values, ", ")
		}
	}
	return forwarded
}

// poppyScope renders the required scopes for the wire: one space between
// entries, empty entries left out.
func poppyScope(scopes []string) string {
	kept := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope = strings.TrimSpace(scope); scope != "" {
			kept = append(kept, scope)
		}
	}
	return strings.Join(kept, " ")
}

// poppyRequestTarget returns the request target as the client sent it.
// r.RequestURI is the request line's own value, so a router prefix or
// http.StripPrefix in front of the caller does not shorten it. A request
// that was not read from the network has none, and then r.URL is used.
func poppyRequestTarget(r *http.Request) string {
	if r.RequestURI != "" {
		return r.RequestURI
	}
	if r.URL != nil {
		return r.URL.EscapedPath()
	}
	return ""
}

// ── Answers ───────────────────────────────────────────────────────────

// poppyReader reads the members of a decoded JSON object strictly. A member
// of the wrong type is an error, never a zero value. It keeps the first
// error. Error texts name members and never quote a value.
type poppyReader struct {
	fields map[string]any
	prefix string
	err    *error
}

// decodePoppyObject decodes a JSON object twice: once with exact numbers
// for the strict reader, and once the standard way for Raw.
func decodePoppyObject(data []byte) (*poppyReader, map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var tree any
	if err := decoder.Decode(&tree); err != nil {
		return nil, nil, errors.New("the answer is not JSON")
	}
	fields, ok := tree.(map[string]any)
	if !ok {
		return nil, nil, errors.New("the answer is not a JSON object")
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, errors.New("the answer is not a JSON object")
	}
	var first error
	return &poppyReader{fields: fields, err: &first}, raw, nil
}

func (r *poppyReader) fail(key, problem string) {
	if *r.err == nil {
		*r.err = fmt.Errorf("%q %s", r.prefix+key, problem)
	}
}

// value returns a member. A missing member and a null one are both absent.
func (r *poppyReader) value(key string) (any, bool) {
	value, ok := r.fields[key]
	if !ok || value == nil {
		return nil, false
	}
	return value, true
}

func (r *poppyReader) optionalString(key string) string {
	value, ok := r.value(key)
	if !ok {
		return ""
	}
	text, isString := value.(string)
	if !isString {
		r.fail(key, "is not a string")
	}
	return text
}

func (r *poppyReader) requiredString(key string) string {
	value, ok := r.value(key)
	if !ok {
		r.fail(key, "is missing")
		return ""
	}
	text, isString := value.(string)
	if !isString || text == "" {
		r.fail(key, "is not a non-empty string")
	}
	return text
}

func (r *poppyReader) optionalBool(key string) (value, present bool) {
	raw, ok := r.value(key)
	if !ok {
		return false, false
	}
	flag, isBool := raw.(bool)
	if !isBool {
		r.fail(key, "is not a boolean")
		return false, false
	}
	return flag, true
}

func (r *poppyReader) requiredBool(key string) bool {
	value, present := r.optionalBool(key)
	if !present {
		r.fail(key, "is missing or is not a boolean")
	}
	return value
}

func (r *poppyReader) optionalInt(key string) (value int64, present bool) {
	raw, ok := r.value(key)
	if !ok {
		return 0, false
	}
	number, isNumber := raw.(json.Number)
	if !isNumber {
		r.fail(key, "is not an integer")
		return 0, false
	}
	integer, err := number.Int64()
	if err != nil {
		r.fail(key, "is not an integer")
		return 0, false
	}
	return integer, true
}

func (r *poppyReader) requiredInt(key string) int64 {
	value, present := r.optionalInt(key)
	if !present {
		r.fail(key, "is missing or is not an integer")
	}
	return value
}

func (r *poppyReader) object(key string) (*poppyReader, bool) {
	raw, ok := r.value(key)
	if !ok {
		return nil, false
	}
	fields, isObject := raw.(map[string]any)
	if !isObject {
		r.fail(key, "is not an object")
		return nil, false
	}
	return &poppyReader{fields: fields, prefix: r.prefix + key + ".", err: r.err}, true
}

// stringMap reads an object whose values are all strings.
func (r *poppyReader) stringMap(key string) (map[string]string, bool) {
	object, ok := r.object(key)
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(object.fields))
	for name, value := range object.fields {
		text, isString := value.(string)
		if !isString {
			r.fail(key, "has a value that is not a string")
			return nil, false
		}
		out[name] = text
	}
	return out, true
}

// stringList reads a list of strings.
func (r *poppyReader) stringList(key string) []string {
	raw, ok := r.value(key)
	if !ok {
		return nil
	}
	items, isList := raw.([]any)
	if !isList {
		r.fail(key, "is not a list")
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, isString := item.(string)
		if !isString {
			r.fail(key, "has an entry that is not a string")
			return nil
		}
		out = append(out, text)
	}
	return out
}

// parsePoppyVerification decodes the answer of the verification endpoint.
// It fails closed: the answer must be a verified result with its Session,
// or a refusal with the response to relay. Anything else is an error.
func parsePoppyVerification(data []byte) (*PoppyVerification, error) {
	reader, raw, err := decodePoppyObject(data)
	if err != nil {
		return nil, err
	}
	active, isBool := reader.fields["active"].(bool)
	if !isBool {
		return nil, errors.New(`"active" is missing or is not a boolean`)
	}

	verification := &PoppyVerification{Active: active, Raw: raw}
	if active {
		parsePoppyVerified(reader, verification)
	} else {
		parsePoppyRefusal(reader, raw, verification)
	}
	if *reader.err != nil {
		return nil, *reader.err
	}
	return verification, nil
}

func parsePoppyVerified(reader *poppyReader, v *PoppyVerification) {
	v.ClientID = reader.requiredString("client_id")
	v.ClientName = reader.optionalString("client_name")
	v.UserID = reader.requiredString("user_id")
	v.AgentID = reader.optionalString("agent_id")
	v.Version = reader.optionalString("version")

	session, ok := reader.object("session")
	if !ok {
		reader.fail("session", "is missing")
		return
	}
	isNew, _ := session.optionalBool("new")
	v.Session = &PoppySession{
		ID:        session.requiredInt("id"),
		SID:       session.requiredString("sid"),
		IsNew:     isNew,
		StartedAt: session.optionalString("started_at"),
	}

	if account, ok := reader.object("account"); ok {
		expires, _ := account.optionalInt("exp")
		v.Account = &PoppyAccount{
			Subject:   account.requiredString("sub"),
			Scope:     account.optionalString("scope"),
			Audience:  account.stringList("aud"),
			Expires:   expires,
			TokenType: account.optionalString("token_type"),
		}
		if v.Account.Audience == nil {
			v.Account.Audience = []string{}
		}
	}
	// signed_in and account say the same thing. An answer in which they
	// disagree is not a result that a handler can act on.
	v.SignedIn = v.Account != nil
	if signedIn, present := reader.optionalBool("signed_in"); present && signedIn != v.SignedIn {
		reader.fail("signed_in", "does not agree with \"account\"")
	}

	v.Extensions = map[string]string{}
	if extensions, ok := reader.stringMap("extensions"); ok {
		v.Extensions = extensions
	}
}

func parsePoppyRefusal(reader *poppyReader, raw map[string]any, v *PoppyVerification) {
	v.Error = reader.requiredString("error")
	v.ErrorDescription = reader.optionalString("error_description")
	v.Scope = reader.optionalString("scope")

	response, ok := reader.object("response")
	if !ok {
		reader.fail("response", "is missing")
		return
	}
	status := response.requiredInt("status")
	if status < 400 || status > 599 {
		response.fail("status", "is not an HTTP error status")
	}
	headers, ok := response.stringMap("headers")
	if !ok {
		response.fail("headers", "is missing")
	}
	relay := &PoppyRelayResponse{Status: int(status), Headers: headers}
	if _, present := response.value("body"); present {
		if _, isObject := response.object("body"); isObject {
			// The standard decoding, so that Body and Raw hold the same
			// kinds of values.
			rawResponse, _ := raw["response"].(map[string]any)
			relay.Body, _ = rawResponse["body"].(map[string]any)
		}
	}
	v.Response = relay
}

// parsePoppySessionStatus decodes the answer of the Session lookup.
func parsePoppySessionStatus(data []byte) (*PoppySessionStatus, error) {
	reader, raw, err := decodePoppyObject(data)
	if err != nil {
		return nil, err
	}
	signedIn, _ := reader.optionalBool("signed_in")
	status := &PoppySessionStatus{
		Status:     reader.requiredString("status"),
		UserID:     reader.optionalString("user_id"),
		AgentID:    reader.optionalString("agent_id"),
		Account:    reader.optionalString("account"),
		SignedIn:   signedIn,
		LastSeenAt: reader.optionalString("last_seen_at"),
		Raw:        raw,
	}
	if *reader.err != nil {
		return nil, *reader.err
	}
	return status, nil
}

// poppyEndAnswer is the answer of ending a Session: {"ended": bool}.
type poppyEndAnswer struct {
	ended bool
}

func (a *poppyEndAnswer) UnmarshalJSON(data []byte) error {
	reader, _, err := decodePoppyObject(data)
	if err != nil {
		return err
	}
	a.ended = reader.requiredBool("ended")
	return *reader.err
}
