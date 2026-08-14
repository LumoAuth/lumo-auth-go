package lumoauth

import (
	"context"
	"time"
)

// Defaults for approval polling. The server's push-approval request TTL is
// 120s, so the default deadline sits just inside it.
const (
	DefaultApprovalPollInterval = 1500 * time.Millisecond
	DefaultApprovalTimeout      = 90 * time.Second
)

// ApprovalsResource covers push-approval-for-agent-actions.
//
// The headline call is Require: when an agent is about to do something
// irreversible — wire money, delete data, email customers — it asks first,
// a push lands on the user's phone with the context, and the call returns
// once a human decides.
type ApprovalsResource struct {
	http *httpClient
}

// ApprovalParams describes an approval request.
type ApprovalParams struct {
	// TaskID identifies the task the agent is operating against. Required.
	TaskID string
	// Reason is the description shown on the approver's phone. Required.
	Reason string
	// OnBehalfOf is the user the agent is acting for — email or user ID.
	// Required.
	OnBehalfOf string
	// Impact is the severity tier. Defaults to ImpactMedium.
	Impact ApprovalImpact
	// Meta carries structured fields (vendor, amount, …) shown to the user.
	Meta map[string]any
}

// WaitOptions tunes approval polling.
type WaitOptions struct {
	// PollInterval is the delay between status polls.
	// Defaults to DefaultApprovalPollInterval.
	PollInterval time.Duration
	// Timeout bounds the wait. Defaults to DefaultApprovalTimeout.
	Timeout time.Duration
}

func (o *WaitOptions) pollInterval() time.Duration {
	if o != nil && o.PollInterval > 0 {
		return o.PollInterval
	}
	return DefaultApprovalPollInterval
}

func (o *WaitOptions) timeout() time.Duration {
	if o != nil && o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultApprovalTimeout
}

// Create opens an approval request and returns immediately with the
// pending approval, whose Token identifies it.
func (r *ApprovalsResource) Create(ctx context.Context, params ApprovalParams) (*ApprovalResult, error) {
	if params.TaskID == "" {
		return nil, NewValidationError("TaskID is required")
	}
	if params.Reason == "" {
		return nil, NewValidationError("Reason is required")
	}
	if params.OnBehalfOf == "" {
		return nil, NewValidationError("OnBehalfOf is required")
	}
	impact := params.Impact
	if impact == "" {
		impact = ImpactMedium
	}
	if !impact.Valid() {
		return nil, validationErrorf("invalid impact %q: expected low, medium, high, or critical", impact)
	}

	body := map[string]any{
		"task_id":      params.TaskID,
		"reason":       params.Reason,
		"impact":       impact,
		"on_behalf_of": params.OnBehalfOf,
	}
	if meta := copyStringMap(params.Meta); meta != nil {
		body["meta"] = meta
	}

	var result ApprovalResult
	if err := r.http.call(ctx, RouteApprovalsCreate, nil, &request{JSON: body}, &result); err != nil {
		return nil, err
	}
	if result.Token == "" {
		return nil, NewValidationError("the server did not return an approval_token")
	}
	return &result, nil
}

// Status fetches the current state of an approval request. It only reads
// state, so it is safe to expose to a polling frontend.
func (r *ApprovalsResource) Status(ctx context.Context, approvalToken string) (*ApprovalResult, error) {
	if approvalToken == "" {
		return nil, NewValidationError("an approval token is required")
	}
	var result ApprovalResult
	if err := r.http.call(ctx, RouteApprovalsStatus,
		map[string]string{"token": approvalToken}, nil, &result); err != nil {
		return nil, err
	}
	if result.Token == "" {
		result.Token = approvalToken
	}
	return &result, nil
}

// Wait polls an approval until it leaves pending, the deadline passes, or
// the context is cancelled. It returns the last observed state — a
// still-pending result means the wait timed out, not that the request was
// denied.
func (r *ApprovalsResource) Wait(ctx context.Context, approvalToken string, opts *WaitOptions) (*ApprovalResult, error) {
	interval := opts.pollInterval()
	deadline := time.Now().Add(opts.timeout())

	last := &ApprovalResult{Status: ApprovalPending, Token: approvalToken}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return last, newNetworkError("approval polling cancelled: "+ctx.Err().Error(), ctx.Err())
		case <-ticker.C:
		}

		result, err := r.Status(ctx, approvalToken)
		if err != nil {
			return last, err
		}
		last = result
		if result.Status != ApprovalPending {
			return result, nil
		}
	}
	return last, nil
}

// Require opens an approval request and blocks until a human decides.
//
// It returns an error for anything other than approval, so the happy path
// reads as a guard:
//
//	approval, err := client.Approvals.Require(ctx, lumoauth.ApprovalParams{
//	    TaskID:     "wire-2026-05-07-001",
//	    Reason:     "Wire $4,500 to vendor INV-7741",
//	    Impact:     lumoauth.ImpactHigh,
//	    OnBehalfOf: "ada@acme.com",
//	}, nil)
//	if err != nil {
//	    return err // denied, expired, or the wait timed out
//	}
//	// approval.Token authorises the side-effecting call.
//
// Use errors.Is with ErrApprovalDenied or ErrApprovalTimeout to tell the
// outcomes apart; the *ApprovalError carries the final payload for audit.
// To handle a denial without an error, call Create and Wait yourself.
func (r *ApprovalsResource) Require(ctx context.Context, params ApprovalParams, opts *WaitOptions) (*ApprovalResult, error) {
	created, err := r.Create(ctx, params)
	if err != nil {
		return nil, err
	}

	result, err := r.Wait(ctx, created.Token, opts)
	if err != nil {
		return nil, err
	}
	switch result.Status {
	case ApprovalApproved:
		return result, nil
	case ApprovalDenied:
		return result, newApprovalDenied(result)
	default:
		// Pending at the deadline, or expired server-side.
		return result, newApprovalTimeout(result)
	}
}
