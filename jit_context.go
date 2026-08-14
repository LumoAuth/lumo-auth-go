package lumoauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

// Defaults for human-in-the-loop approval polling on JIT requests.
const (
	DefaultJitPollInterval = 5 * time.Second
	DefaultJitPollTimeout  = 5 * time.Minute
)

// TokenSource is the minimal contract JITContext needs: where the instance
// lives, which org it belongs to, and a bearer token that stays fresh.
// *Agent satisfies it.
type TokenSource interface {
	BaseURL() string
	OrgID() string
	AccessToken(ctx context.Context) (string, error)
}

// JITContext manages one ephemeral task and the scoped permissions
// requested under it.
//
// The lifecycle is: create a task, request permissions against it, exchange
// approved requests for short-lived tokens, then complete the task — which
// revokes every token issued under it. Close makes that cleanup a defer:
//
//	jit, err := lumoauth.NewJITContext(agent)
//	if err != nil {
//	    return err
//	}
//	defer jit.Close(ctx)
//
//	if _, err := jit.CreateTask(ctx, lumoauth.CreateTaskParams{Name: "Analyse Q4 report"}); err != nil {
//	    return err
//	}
//	result, err := jit.RequestPermission(ctx, map[string]any{
//	    "type": "file_access", "actions": []string{"read"}, "identifier": "report_q4.pdf",
//	}, nil)
//	if err != nil {
//	    return err
//	}
//	if result.Approved() {
//	    token, err := jit.Token(ctx, result.RequestID)
//	    …
//	}
type JITContext struct {
	source         TokenSource
	client         *Client
	resource       *JitResource
	delegatedToken string

	taskID        string
	caepSessionID string
}

// JITContextOption configures a JITContext.
type JITContextOption func(*JITContext)

// WithDelegatedToken makes JIT calls under an on-behalf-of token (from
// DelegateOnBehalfOf or a DelegationChain) instead of the agent's own.
func WithDelegatedToken(token string) JITContextOption {
	return func(j *JITContext) { j.delegatedToken = token }
}

// NewJITContext builds a JIT context over any authenticated token source.
func NewJITContext(source TokenSource, opts ...JITContextOption) (*JITContext, error) {
	if source == nil {
		return nil, NewConfigError("a token source is required (pass an *Agent)")
	}
	jit := &JITContext{source: source}
	for _, opt := range opts {
		opt(jit)
	}

	jit.client = newClient(&clientConfig{
		baseURL:       source.BaseURL(),
		orgID:         source.OrgID(),
		tokenProvider: jit.bearer,
		userAgent:     userAgent(),
	})
	jit.resource = jit.client.Jit
	return jit, nil
}

// TaskID returns the current task's ID, or "" when no task is open.
func (j *JITContext) TaskID() string { return j.taskID }

// CaepSessionID returns the CAEP session ID for the current task, when the
// server issued one.
func (j *JITContext) CaepSessionID() string { return j.caepSessionID }

// bearer resolves the token for JIT calls: the delegated token when one is
// set, otherwise the source's own.
func (j *JITContext) bearer(ctx context.Context) (string, error) {
	if j.delegatedToken != "" {
		return j.delegatedToken, nil
	}
	token, err := j.source.AccessToken(ctx)
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", NewConfigError("no access token available — authenticate first")
	}
	return token, nil
}

// ── Delegation ────────────────────────────────────────────────────────

// DelegateOnBehalfOf exchanges the agent's token and a user's token for a
// delegated one (RFC 8693), and uses it for subsequent JIT calls. The
// delegated token carries an `act` claim, so the audit trail names both
// the user and the agent.
func (j *JITContext) DelegateOnBehalfOf(ctx context.Context, userToken string) error {
	if userToken == "" {
		return NewValidationError("a user token is required")
	}
	agentToken, err := j.source.AccessToken(ctx)
	if err != nil {
		return err
	}

	response, err := j.client.Auth.TokenExchange(ctx, TokenExchangeParams{
		SubjectToken: userToken,
		ActorToken:   agentToken,
	})
	if err != nil {
		return err
	}
	j.delegatedToken = response.AccessToken
	return nil
}

// ── Task lifecycle ────────────────────────────────────────────────────

// CreateTask opens an ephemeral task and makes it the context's current
// task.
func (j *JITContext) CreateTask(ctx context.Context, params CreateTaskParams) (*JitTask, error) {
	task, err := j.resource.CreateTask(ctx, params)
	if err != nil {
		return nil, err
	}
	j.taskID = task.TaskID
	j.caepSessionID = task.CaepSessionID
	return task, nil
}

// CompleteTask closes the current task and revokes its JIT tokens. It is a
// no-op when no task is open, and clears the task either way — a failed
// cleanup should not strand the context on a dead task.
func (j *JITContext) CompleteTask(ctx context.Context) error {
	taskID := j.taskID
	if taskID == "" {
		return nil
	}
	j.taskID = ""
	j.caepSessionID = ""
	return j.resource.CompleteTask(ctx, taskID)
}

// Close is CompleteTask under the name defer expects.
func (j *JITContext) Close(ctx context.Context) error { return j.CompleteTask(ctx) }

// EvaluateTask closes a task with an outcome and audit notes. It defaults
// to the current task.
func (j *JITContext) EvaluateTask(ctx context.Context, taskID string, params EvaluateTaskParams) (map[string]any, error) {
	if taskID == "" {
		taskID = j.taskID
	}
	if taskID == "" {
		return nil, NewConfigError("no active task — call CreateTask first")
	}
	return j.resource.EvaluateTask(ctx, taskID, params)
}

// ── Permission requests ───────────────────────────────────────────────

// RequestPermissionOptions tunes a JIT permission request.
type RequestPermissionOptions struct {
	// Justification is the human-readable reason shown to an approver.
	Justification string
	// TTL is the requested token lifetime in seconds, capped at JitMaxTTL.
	TTL int
	// NoWait returns a pending request immediately instead of polling for
	// the human decision.
	NoWait bool
	// PollInterval is the delay between status polls.
	// Defaults to DefaultJitPollInterval.
	PollInterval time.Duration
	// PollTimeout bounds the wait for approval.
	// Defaults to DefaultJitPollTimeout.
	PollTimeout time.Duration
	// TaskID overrides the context's current task.
	TaskID string
}

// RequestPermission asks for a Just-in-Time permission against the current
// task.
//
// Low-risk requests come back approved. Higher-risk ones enter
// human-in-the-loop review; by default this polls until the request
// resolves or the deadline passes, and returns the last state seen — a
// still-pending result means the wait timed out, not a denial. Set NoWait
// to poll yourself with Status.
func (j *JITContext) RequestPermission(ctx context.Context, authorizationDetails map[string]any, opts *RequestPermissionOptions) (*JitRequest, error) {
	if opts == nil {
		opts = &RequestPermissionOptions{}
	}
	taskID := opts.TaskID
	if taskID == "" {
		taskID = j.taskID
	}
	if taskID == "" {
		return nil, NewConfigError("no active task — call CreateTask first")
	}

	result, err := j.resource.Request(ctx, RequestPermissionParams{
		TaskID:               taskID,
		AuthorizationDetails: authorizationDetails,
		Justification:        opts.Justification,
		TTL:                  opts.TTL,
	})
	if err != nil {
		return nil, err
	}

	if result.Pending() && !opts.NoWait {
		return j.waitForApproval(ctx, result, opts)
	}
	return result, nil
}

// waitForApproval polls a pending request until it resolves or the
// deadline passes, returning the last state observed.
func (j *JITContext) waitForApproval(ctx context.Context, initial *JitRequest, opts *RequestPermissionOptions) (*JitRequest, error) {
	interval := opts.PollInterval
	if interval <= 0 {
		interval = DefaultJitPollInterval
	}
	timeout := opts.PollTimeout
	if timeout <= 0 {
		timeout = DefaultJitPollTimeout
	}
	deadline := time.Now().Add(timeout)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return initial, newNetworkError(
				"JIT approval polling cancelled: "+ctx.Err().Error(), ctx.Err())
		case <-ticker.C:
		}

		result, err := j.resource.Status(ctx, initial.RequestID)
		if err != nil {
			return initial, err
		}
		if !result.Pending() {
			return result, nil
		}
	}
	return initial, nil // still pending
}

// Status fetches the current state of a permission request.
func (j *JITContext) Status(ctx context.Context, requestID string) (*JitRequest, error) {
	return j.resource.Status(ctx, requestID)
}

// Token exchanges an approved request for a short-lived JIT access token.
func (j *JITContext) Token(ctx context.Context, requestID string) (string, error) {
	token, err := j.resource.Token(ctx, requestID)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// PendingRequests lists the requests awaiting human approval.
func (j *JITContext) PendingRequests(ctx context.Context) ([]JitRequest, error) {
	return j.resource.Pending(ctx)
}

// ── Making calls with JIT tokens ──────────────────────────────────────

// Call makes a request to any URL using a JIT token. The caller owns the
// returned response and must close its body.
func (j *JITContext) Call(ctx context.Context, jitToken, method, url string, body any) (*http.Response, error) {
	if jitToken == "" {
		return nil, NewValidationError("a JIT token is required")
	}
	return j.client.http.doRaw(ctx, method, url, &request{
		JSON:    body,
		Headers: map[string]string{"Authorization": "Bearer " + jitToken},
	})
}

// CallWithEscalation makes a request and, if the server answers 403 with an
// Insufficient-Authorization-Details header, requests exactly the
// permission that header names, obtains a JIT token, and retries once.
//
// This is the auto-escalation path: the resource server states what it
// needs, and the agent asks for that and nothing more. When the escalation
// is not approved, the original 403 is returned unchanged.
//
// The caller owns the returned response and must close its body.
func (j *JITContext) CallWithEscalation(ctx context.Context, method, url string, body any, opts *RequestPermissionOptions) (*http.Response, error) {
	token, err := j.bearer(ctx)
	if err != nil {
		return nil, err
	}

	response, err := j.client.http.doRaw(ctx, method, url, &request{
		JSON:    body,
		Headers: map[string]string{"Authorization": "Bearer " + token},
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusForbidden {
		return response, nil
	}

	header := response.Header.Get("Insufficient-Authorization-Details")
	if header == "" {
		return response, nil
	}

	required, err := decodeAuthorizationDetails(header)
	if err != nil {
		// The server's hint is unusable; hand back the original 403
		// rather than failing on a header we could not read.
		return response, nil
	}

	if opts == nil {
		opts = &RequestPermissionOptions{Justification: "Required for user request"}
	}
	result, err := j.RequestPermission(ctx, required, opts)
	if err != nil {
		return response, err
	}
	if !result.Approved() {
		return response, nil // escalation refused — original 403 stands
	}

	jitToken, err := j.Token(ctx, result.RequestID)
	if err != nil {
		return response, err
	}
	response.Body.Close()
	return j.Call(ctx, jitToken, method, url, body)
}

// decodeAuthorizationDetails reads the base64-encoded RFC 9396 object a
// resource server sends in Insufficient-Authorization-Details.
func decodeAuthorizationDetails(header string) (map[string]any, error) {
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		if decoded, err = base64.RawStdEncoding.DecodeString(header); err != nil {
			return nil, NewValidationError(
				"could not base64-decode Insufficient-Authorization-Details: " + err.Error())
		}
	}
	var details map[string]any
	if err := json.Unmarshal(decoded, &details); err != nil {
		return nil, NewValidationError(
			"could not decode Insufficient-Authorization-Details as JSON: " + err.Error())
	}
	return details, nil
}
