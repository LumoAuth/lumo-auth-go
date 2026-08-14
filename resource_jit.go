package lumoauth

import (
	"context"
	"encoding/json"
)

// JitMaxTTL is the longest lifetime the server will grant a JIT token.
const JitMaxTTL = 900 // seconds (15 min)

// JitDefaultTTL is the requested lifetime when a call does not specify one.
const JitDefaultTTL = 300 // seconds

// JitResource covers the Just-in-Time permission endpoints: ephemeral
// tasks, RFC 9396 permission requests, and short-lived scoped tokens.
//
// For the full lifecycle with automatic cleanup, use JITContext, which
// wraps this resource.
type JitResource struct {
	http *httpClient
}

// CreateTaskParams describes an ephemeral task.
type CreateTaskParams struct {
	// Name is a human-readable label ("Analyse Q4 report").
	Name string
	// Type categorises the task ("research", "analysis").
	Type string
	// OnBehalfOf is the user's email when the agent acts for someone.
	OnBehalfOf string
}

// CreateTask opens an ephemeral task — an isolated sub-identity that JIT
// permissions attach to, and whose tokens are revoked together when the
// task completes.
func (r *JitResource) CreateTask(ctx context.Context, params CreateTaskParams) (*JitTask, error) {
	body := map[string]any{}
	if params.Name != "" {
		body["name"] = params.Name
	}
	if params.Type != "" {
		body["type"] = params.Type
	}
	if params.OnBehalfOf != "" {
		body["on_behalf_of"] = params.OnBehalfOf
	}

	var task JitTask
	if err := r.http.call(ctx, RouteJitCreateTask, nil, &request{JSON: body}, &task); err != nil {
		return nil, err
	}
	if task.TaskID == "" {
		return nil, NewValidationError("the server did not return a task_id")
	}
	return &task, nil
}

// CompleteTask closes a task and revokes every JIT token issued under it.
func (r *JitResource) CompleteTask(ctx context.Context, taskID string) error {
	if taskID == "" {
		return NewValidationError("a task ID is required")
	}
	return r.http.call(ctx, RouteJitCompleteTask, map[string]string{"taskId": taskID}, nil, nil)
}

// EvaluateTaskParams describes how a task ended.
type EvaluateTaskParams struct {
	// Result is TaskResultCompleted, TaskResultFailed, or
	// TaskResultCancelled. Defaults to completed.
	Result string
	// Notes are attached to the audit record.
	Notes string
}

// EvaluateTask closes a task with an outcome and audit notes — the record
// a supervisor or orchestrator leaves behind.
func (r *JitResource) EvaluateTask(ctx context.Context, taskID string, params EvaluateTaskParams) (map[string]any, error) {
	if taskID == "" {
		return nil, NewValidationError("a task ID is required")
	}
	result := params.Result
	if result == "" {
		result = TaskResultCompleted
	}
	body := map[string]any{"result": result}
	if params.Notes != "" {
		body["notes"] = params.Notes
	}

	var response map[string]any
	if err := r.http.call(ctx, RouteJitEvaluateTask, map[string]string{"taskId": taskID},
		&request{JSON: body}, &response); err != nil {
		return nil, err
	}
	return response, nil
}

// RequestPermissionParams describes an RFC 9396 permission request.
type RequestPermissionParams struct {
	// TaskID is the task the permission attaches to. Required.
	TaskID string
	// AuthorizationDetails is the RFC 9396 structured object, e.g.
	//   {"type": "file_access", "actions": ["read"], "identifier": "report.pdf"}
	// Required.
	AuthorizationDetails map[string]any
	// Justification is the human-readable reason shown to an approver.
	Justification string
	// TTL is the requested token lifetime in seconds; capped at JitMaxTTL.
	// Defaults to JitDefaultTTL.
	TTL int
}

// Request asks for a Just-in-Time permission. Low-risk requests come back
// approved; higher-risk ones enter human-in-the-loop review as pending —
// see JITContext.RequestPermission to wait for the decision.
func (r *JitResource) Request(ctx context.Context, params RequestPermissionParams) (*JitRequest, error) {
	if params.TaskID == "" {
		return nil, NewValidationError("TaskID is required — create a task first")
	}
	if len(params.AuthorizationDetails) == 0 {
		return nil, NewValidationError("AuthorizationDetails is required (RFC 9396)")
	}
	ttl := params.TTL
	if ttl <= 0 {
		ttl = JitDefaultTTL
	}
	if ttl > JitMaxTTL {
		ttl = JitMaxTTL
	}

	body := map[string]any{
		"task_id":               params.TaskID,
		"authorization_details": params.AuthorizationDetails,
		"requested_ttl":         ttl,
	}
	if params.Justification != "" {
		body["justification"] = params.Justification
	}

	var result JitRequest
	if err := r.http.call(ctx, RouteJitRequest, nil, &request{JSON: body}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Status fetches the current state of a permission request.
func (r *JitResource) Status(ctx context.Context, requestID string) (*JitRequest, error) {
	if requestID == "" {
		return nil, NewValidationError("a request ID is required")
	}
	var result JitRequest
	if err := r.http.call(ctx, RouteJitRequestStatus,
		map[string]string{"requestId": requestID}, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Token exchanges an approved request for a short-lived, narrowly scoped
// JIT access token.
func (r *JitResource) Token(ctx context.Context, requestID string) (*TokenResponse, error) {
	if requestID == "" {
		return nil, NewValidationError("a request ID is required")
	}
	var token TokenResponse
	if err := r.http.call(ctx, RouteJitToken,
		map[string]string{"requestId": requestID}, nil, &token); err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, NewValidationError("the JIT token endpoint returned no access_token")
	}
	return &token, nil
}

// Pending lists the permission requests awaiting human approval.
func (r *JitResource) Pending(ctx context.Context) ([]JitRequest, error) {
	var raw json.RawMessage
	if err := r.http.call(ctx, RouteJitPending, nil, nil, &raw); err != nil {
		return nil, err
	}

	// The endpoint returns either a bare array or an envelope with
	// `requests`.
	var requests []JitRequest
	if err := json.Unmarshal(raw, &requests); err == nil {
		return requests, nil
	}
	var envelope struct {
		Requests []JitRequest `json:"requests"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, NewValidationError("could not decode the pending requests response: " + err.Error())
	}
	return envelope.Requests, nil
}
