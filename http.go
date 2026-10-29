package lumoauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// httpClient is the transport shared by every resource namespace. It
//
//   - injects credentials: a tokenProvider yields a bearer token
//     (Authorization: Bearer …), an apiKey is sent as X-API-Key. The two are
//     never sent together — the server rejects ambiguous credentials.
//   - maps error statuses onto the typed errors in errors.go, reading
//     error / code / error_description / message out of JSON bodies.
//   - wraps transport failures in *NetworkError.
//   - decodes successful JSON responses into a caller-supplied value.
type httpClient struct {
	baseURL       string
	orgID         string
	apiKey        string
	tokenProvider TokenProvider
	doer          *http.Client
	timeout       time.Duration
	userAgent     string
	headers       map[string]string
	// dpop, when set, binds token requests to its key and presents bound
	// tokens with the DPoP scheme plus a proof (RFC 9449).
	dpop *DPoPSigner
}

// TokenProvider returns the bearer token to authenticate a request with. It
// is called once per request, so implementations can refresh transparently.
type TokenProvider func(ctx context.Context) (string, error)

const defaultTimeout = 30 * time.Second

func newHTTPClient(baseURL string) *httpClient {
	return &httpClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		doer:    &http.Client{Timeout: defaultTimeout},
		timeout: defaultTimeout,
	}
}

// insecureTLS reconfigures the client to skip certificate validation. Local
// development only.
func (c *httpClient) insecureTLS() {
	transport, ok := c.doer.Transport.(*http.Transport)
	if !ok || transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		transport = transport.Clone()
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.InsecureSkipVerify = true
	c.doer.Transport = transport
}

// request describes one outbound call.
type request struct {
	// JSON is marshalled as the request body with Content-Type
	// application/json. Mutually exclusive with Form and Raw.
	JSON any
	// Raw is sent verbatim as the request body. AAuth uses it so the bytes
	// on the wire are exactly the bytes that were signed.
	Raw []byte
	// Form is sent as application/x-www-form-urlencoded (OAuth endpoints).
	Form url.Values
	// Query is appended to the URL.
	Query url.Values
	// Headers are merged in last and win over the SDK's own.
	Headers map[string]string
	// NoAuth suppresses credential injection (OAuth token endpoints
	// authenticate through the form body instead).
	NoAuth bool
	// Timeout overrides the client default for this call.
	Timeout time.Duration
}

// call invokes a route from the registry, filling {orgId} from the client
// when the caller did not supply it, and decodes the response into out.
func (c *httpClient) call(ctx context.Context, routeName string, params map[string]string, req *request, out any) error {
	method, path, err := c.resolve(routeName, params)
	if err != nil {
		return err
	}
	return c.do(ctx, method, path, req, out)
}

// resolve turns a route name plus params into a concrete method and path.
func (c *httpClient) resolve(routeName string, params map[string]string) (method, path string, err error) {
	route, ok := Routes[routeName]
	if !ok {
		return "", "", configErrorf("unknown route %q", routeName)
	}
	filled := make(map[string]string, len(params)+1)
	for k, v := range params {
		filled[k] = v
	}
	if strings.Contains(route.Path, "{orgId}") && filled["orgId"] == "" {
		if c.orgID == "" {
			return "", "", configErrorf(
				"org ID is required for %q — pass WithOrgID to the client or set LUMOAUTH_ORG_ID",
				routeName)
		}
		filled["orgId"] = c.orgID
	}
	path, err = BuildPath(route.Path, filled)
	if err != nil {
		return "", "", err
	}
	return route.Method, path, nil
}

// orgPath prefixes a path with the org-scoped API base.
func (c *httpClient) orgPath(path string) (string, error) {
	if c.orgID == "" {
		return "", NewConfigError(
			"org ID is required for this call — pass WithOrgID to the client or set LUMOAUTH_ORG_ID")
	}
	return "/orgs/" + url.PathEscape(c.orgID) + "/api/v1" + path, nil
}

// do sends a request to a path (joined to baseURL) or an absolute URL, maps
// the status onto the error taxonomy, and decodes JSON into out. out may be
// nil to discard the body.
func (c *httpClient) do(ctx context.Context, method, pathOrURL string, req *request, out any) error {
	_, err := c.doHeaders(ctx, method, pathOrURL, req, out)
	return err
}

// doHeaders is do, also returning the response headers whenever a response
// was received — on success and on an *APIError alike. The token endpoint
// reads DPoP-Nonce out of them.
func (c *httpClient) doHeaders(ctx context.Context, method, pathOrURL string, req *request, out any) (http.Header, error) {
	resp, err := c.doRaw(ctx, method, pathOrURL, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return resp.Header, newNetworkError(
			fmt.Sprintf("reading response from %s failed: %v", pathOrURL, readErr), readErr)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.Header, apiErrorFromResponse(resp, body)
	}

	if out == nil || resp.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(body)) == 0 {
		return resp.Header, nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return resp.Header, NewValidationError(fmt.Sprintf(
			"could not decode the response from %s: %v", pathOrURL, err))
	}
	return resp.Header, nil
}

// doRaw performs the request and returns the response untouched. Transport
// failures are still wrapped; HTTP statuses are not interpreted.
func (c *httpClient) doRaw(ctx context.Context, method, pathOrURL string, req *request) (*http.Response, error) {
	if req == nil {
		req = &request{}
	}

	target := pathOrURL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = c.baseURL + target
	}
	if len(req.Query) > 0 {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target += sep + req.Query.Encode()
	}

	var body io.Reader
	contentType := ""
	switch {
	case req.Form != nil:
		body = strings.NewReader(req.Form.Encode())
		contentType = "application/x-www-form-urlencoded"
	case req.Raw != nil:
		body = bytes.NewReader(req.Raw)
		contentType = "application/json"
	case req.JSON != nil:
		encoded, err := json.Marshal(req.JSON)
		if err != nil {
			return nil, NewValidationError(fmt.Sprintf("could not encode the request body: %v", err))
		}
		body = bytes.NewReader(encoded)
		contentType = "application/json"
	}

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	httpReq, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), target, body)
	if err != nil {
		return nil, validationErrorf("could not build the request for %s: %v", target, err)
	}

	httpReq.Header.Set("Accept", "application/json")
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}
	if c.userAgent != "" {
		httpReq.Header.Set("User-Agent", c.userAgent)
	}
	for k, v := range c.headers {
		httpReq.Header.Set(k, v)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	if err := c.injectCredentials(ctx, httpReq, req); err != nil {
		return nil, err
	}

	resp, err := c.doer.Do(httpReq)
	if err != nil {
		return nil, newNetworkError(fmt.Sprintf("request to %s failed: %v", target, err), err)
	}
	if c.dpop != nil {
		// A server that uses DPoP nonces hands out the next one on every
		// response; the following proof for that origin must carry it.
		c.dpop.RememberNonce(resp)
	}
	return resp, nil
}

// injectCredentials adds exactly one credential header, unless the caller
// already supplied one or asked for an unauthenticated request.
func (c *httpClient) injectCredentials(ctx context.Context, httpReq *http.Request, req *request) error {
	if req.NoAuth {
		return nil
	}
	if authorization := httpReq.Header.Get("Authorization"); authorization != "" {
		// A caller-supplied bearer token that turns out to be DPoP-bound
		// still needs the proof, or the server refuses it as a replay.
		if token, ok := strings.CutPrefix(authorization, "Bearer "); ok {
			return c.presentToken(httpReq, token)
		}
		return nil
	}
	if httpReq.Header.Get("X-API-Key") != "" {
		return nil
	}
	if c.tokenProvider != nil {
		token, err := c.tokenProvider(ctx)
		if err != nil {
			return err
		}
		if token != "" {
			return c.presentToken(httpReq, token)
		}
	}
	if c.apiKey != "" {
		// API keys travel in X-API-Key, leaving Authorization free for
		// bearer tokens. Sending both is a server-side error.
		httpReq.Header.Set("X-API-Key", c.apiKey)
	}
	return nil
}

// presentToken sets the Authorization header for an access token: the DPoP
// scheme plus a proof when a signer is configured and the token is bound to
// a key (cnf.jkt), the Bearer scheme otherwise.
func (c *httpClient) presentToken(httpReq *http.Request, token string) error {
	if c.dpop == nil || !DPoPBound(token) {
		httpReq.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
	return c.dpop.AuthorizeRequest(httpReq, token)
}

// apiErrorFromResponse builds the typed error for a non-2xx response.
func apiErrorFromResponse(resp *http.Response, body []byte) *APIError {
	parsed := parseBody(resp, body)
	message, code := extractError(resp.StatusCode, parsed)
	apiErr := newAPIError(resp.StatusCode, code, message, parsed)
	if resp.StatusCode == http.StatusTooManyRequests {
		apiErr.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	}
	return apiErr
}

// parseBody decodes a response body: a map for JSON objects, the raw string
// otherwise, nil when empty.
func parseBody(resp *http.Response, body []byte) any {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil
	}
	// Try JSON regardless of Content-Type — some endpoints omit it.
	var decoded any
	if err := json.Unmarshal(trimmed, &decoded); err == nil {
		return decoded
	}
	return string(trimmed)
}

// extractError pulls a message and code out of a decoded error body,
// checking the same key order as the JS and Python SDKs.
func extractError(status int, body any) (message, code string) {
	message = fmt.Sprintf("HTTP %d %s", status, strings.TrimSpace(http.StatusText(status)))

	switch typed := body.(type) {
	case map[string]any:
		for _, key := range []string{"error_description", "message", "detail", "error"} {
			if value, ok := typed[key].(string); ok && value != "" {
				message = value
				break
			}
		}
		for _, key := range []string{"code", "error"} {
			if value, ok := typed[key].(string); ok && value != "" {
				code = value
				break
			}
		}
	case string:
		if trimmed := strings.TrimSpace(typed); trimmed != "" {
			if len(trimmed) > 500 {
				trimmed = trimmed[:500]
			}
			message = fmt.Sprintf("HTTP %d — %s", status, trimmed)
		}
	}
	return message, code
}

// parseRetryAfter reads a Retry-After header in either supported form:
// delay-seconds, or an HTTP date.
func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds * float64(time.Second))
	}
	if when, err := http.ParseTime(value); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay
		}
	}
	return 0
}

// bearerToken resolves the current bearer token, if the client has a
// provider. Used by flows that must present the token in a request body.
func (c *httpClient) bearerToken(ctx context.Context) (string, error) {
	if c.tokenProvider == nil {
		return "", nil
	}
	return c.tokenProvider(ctx)
}
