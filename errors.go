package lumoauth

import (
	"errors"
	"fmt"
	"time"
)

// The LumoAuth error taxonomy, mirroring the JS and Python SDKs (same codes):
//
//	BaseError                      (embedded in every SDK error)
//	├── APIError                   (any non-2xx HTTP response)
//	│   ├── 401  AUTHENTICATION_ERROR
//	│   ├── 403  PERMISSION_DENIED
//	│   ├── 404  NOT_FOUND
//	│   └── 429  RATE_LIMITED
//	│       └── BudgetError        (body code budget_exceeded: agent budget spent)
//	├── ValidationError            (bad input / unexpected response shape)
//	├── ConfigError                (missing or invalid configuration)
//	├── NetworkError               (transport failure: DNS, timeout, TLS, …)
//	├── ApprovalError              (denied / timed out / not delivered)
//	└── BudgetError                (agent budget exhausted, checked locally)
//
// A server answer whose body code is budget_exceeded (429, a spent agent
// budget) is an *APIError that matches ErrRateLimited, as every 429 does,
// and also ErrBudgetExceeded: it wraps a *BudgetError, which errors.As
// finds. Code that caught the rate limit keeps working.
//
// Errors are matched with the standard library rather than by type switch:
//
//	if errors.Is(err, lumoauth.ErrPermissionDenied) { … }
//
//	var apiErr *lumoauth.APIError
//	if errors.As(err, &apiErr) { log.Print(apiErr.StatusCode, apiErr.Body) }

// Error codes, identical to the JS and Python SDKs.
const (
	CodeError            = "LUMOAUTH_ERROR"
	CodeAPI              = "API_ERROR"
	CodeAuthentication   = "AUTHENTICATION_ERROR"
	CodePermissionDenied = "PERMISSION_DENIED"
	CodeNotFound         = "NOT_FOUND"
	CodeRateLimited      = "RATE_LIMITED"
	CodeValidation       = "VALIDATION_ERROR"
	CodeConfig           = "CONFIG_ERROR"
	CodeNetwork          = "NETWORK_ERROR"
	CodeApprovalDenied   = "APPROVAL_DENIED"
	CodeApprovalTimeout  = "APPROVAL_TIMEOUT"
	// CodeApprovalNotDelivered marks an ApprovalError for a request that
	// never reached a push device; see ApprovalError.Reason.
	CodeApprovalNotDelivered = "APPROVAL_NOT_DELIVERED"
	CodeBudgetExceeded       = "BUDGET_EXCEEDED"
)

// Sentinel errors for errors.Is. Every error returned by this SDK matches
// ErrLumoAuth; each also matches exactly one of the specific sentinels,
// except the server's budget refusal, which matches ErrRateLimited and
// ErrBudgetExceeded (see above).
var (
	// ErrLumoAuth matches every error produced by this SDK.
	ErrLumoAuth = errors.New("lumoauth error")
	// ErrAPI matches any non-2xx HTTP response, including the four below.
	ErrAPI = errors.New("lumoauth: API error")
	// ErrAuthentication matches HTTP 401 responses.
	ErrAuthentication = errors.New("lumoauth: authentication failed")
	// ErrPermissionDenied matches HTTP 403 responses.
	ErrPermissionDenied = errors.New("lumoauth: permission denied")
	// ErrNotFound matches HTTP 404 responses.
	ErrNotFound = errors.New("lumoauth: not found")
	// ErrRateLimited matches HTTP 429 responses.
	ErrRateLimited = errors.New("lumoauth: rate limited")
	// ErrValidation matches client-side validation failures.
	ErrValidation = errors.New("lumoauth: validation failed")
	// ErrConfig matches missing or invalid configuration.
	ErrConfig = errors.New("lumoauth: configuration error")
	// ErrNetwork matches transport failures (no HTTP response was received).
	ErrNetwork = errors.New("lumoauth: network error")
	// ErrApprovalDenied matches an approval a human explicitly denied.
	ErrApprovalDenied = errors.New("lumoauth: approval denied")
	// ErrApprovalTimeout matches an approval that expired before a response.
	ErrApprovalTimeout = errors.New("lumoauth: approval timed out")
	// ErrApprovalNotDelivered matches an approval request that no push
	// device received, so nobody can approve it in this call.
	ErrApprovalNotDelivered = errors.New("lumoauth: approval not delivered")
	// ErrBudgetExceeded matches an exhausted agent budget.
	ErrBudgetExceeded = errors.New("lumoauth: budget exceeded")
)

// BaseError carries the fields every LumoAuth error has. The concrete error
// types embed it, so errors.Is(err, ErrLumoAuth) holds for all of them.
type BaseError struct {
	// Code is the stable machine-readable code shared with the JS and
	// Python SDKs (see the Code* constants).
	Code string
	// Message is the human-readable description.
	Message string

	kind  error // the sentinel this error matches
	cause error // the underlying error, if any
}

func (e *BaseError) Error() string { return e.Message }

// Unwrap returns the underlying cause, if the error wraps one.
func (e *BaseError) Unwrap() error { return e.cause }

// Is reports whether the error matches ErrLumoAuth or its own sentinel.
func (e *BaseError) Is(target error) bool {
	if target == ErrLumoAuth {
		return true
	}
	return e.kind != nil && target == e.kind
}

// ErrCode returns the error's LumoAuth code. It backs the package-level
// ErrorCode helper across all error types.
func (e *BaseError) ErrCode() string { return e.Code }

func newError(kind error, code, message string) *BaseError {
	return &BaseError{Code: code, Message: message, kind: kind}
}

// APIError is returned when the server responds with a non-2xx status.
type APIError struct {
	*BaseError
	// StatusCode is the HTTP status of the response.
	StatusCode int
	// Body is the decoded response body: map[string]any for JSON objects,
	// a string for anything else, nil for an empty body.
	Body any
	// RetryAfter carries the Retry-After hint on 429 responses (0 if absent).
	RetryAfter time.Duration
	// RequiredScopes lists the scopes a 403 scope refusal names in
	// details.required_scopes; nil when the body has none. The server sends
	//
	//	{"error":"forbidden","message":"Insufficient scope: …","status":403,
	//	 "details":{"required_scopes":["authz:read"],"granted_scopes":[…]}}
	//
	// when the credential lacks a user-delegated scope the route needs.
	RequiredScopes []string
}

// Is additionally matches ErrAPI for every status, so callers can catch all
// server-side failures with a single check.
func (e *APIError) Is(target error) bool {
	return target == ErrAPI || e.BaseError.Is(target)
}

func newAPIError(status int, code, message string, body any) *APIError {
	kind := ErrAPI
	switch status {
	case 401:
		kind = ErrAuthentication
	case 403:
		kind = ErrPermissionDenied
	case 404:
		kind = ErrNotFound
	case 429:
		kind = ErrRateLimited
	}
	if code == "" {
		code = defaultCodeForStatus(status)
	}
	return &APIError{
		BaseError:      newError(kind, code, message),
		StatusCode:     status,
		Body:           body,
		RequiredScopes: requiredScopesFrom(body),
	}
}

// requiredScopesFrom reads details.required_scopes from a decoded JSON
// error body, keeping only non-empty strings.
func requiredScopesFrom(body any) []string {
	m, ok := body.(map[string]any)
	if !ok {
		return nil
	}
	details, ok := m["details"].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := details["required_scopes"].([]any)
	if !ok {
		return nil
	}
	var scopes []string
	for _, item := range raw {
		if s, ok := item.(string); ok && s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

func defaultCodeForStatus(status int) string {
	switch status {
	case 401:
		return CodeAuthentication
	case 403:
		return CodePermissionDenied
	case 404:
		return CodeNotFound
	case 429:
		return CodeRateLimited
	default:
		return CodeAPI
	}
}

// ValidationError is returned when client-side validation fails: bad
// arguments, or a response whose shape the SDK cannot use.
type ValidationError struct {
	*BaseError
	// Issues holds per-field detail when the server supplied it.
	Issues []any
	// Reason is a stable, machine-readable cause set by the token
	// verifiers (one of the TokenRejected* constants); "" elsewhere. Read
	// it with RejectionReason.
	Reason string
}

// NewValidationError builds a ValidationError. Exported so callers writing
// their own resources on top of Client can produce consistent errors.
func NewValidationError(message string, issues ...any) *ValidationError {
	return &ValidationError{
		BaseError: newError(ErrValidation, CodeValidation, message),
		Issues:    issues,
	}
}

func validationErrorf(format string, args ...any) *ValidationError {
	return NewValidationError(fmt.Sprintf(format, args...))
}

// ConfigError is returned when a required option is missing or invalid.
type ConfigError struct {
	*BaseError
}

// NewConfigError builds a ConfigError.
func NewConfigError(message string) *ConfigError {
	return &ConfigError{BaseError: newError(ErrConfig, CodeConfig, message)}
}

func configErrorf(format string, args ...any) *ConfigError {
	return NewConfigError(fmt.Sprintf(format, args...))
}

// NetworkError is returned when a request fails before an HTTP response was
// received (DNS, connection, TLS, timeout, or a cancelled context).
type NetworkError struct {
	*BaseError
}

func newNetworkError(message string, cause error) *NetworkError {
	err := newError(ErrNetwork, CodeNetwork, message)
	err.cause = cause
	return &NetworkError{BaseError: err}
}

// Reasons carried by an ApprovalError with Code CodeApprovalNotDelivered.
const (
	// ApprovalReasonEmailFallbackSent means the user has no enrolled push
	// device, so the server sent an email notice instead. The email holds no
	// approval link. The server gives the same answer for an unknown user.
	ApprovalReasonEmailFallbackSent = "email_fallback_sent"
	// ApprovalReasonNoEnrolledDevice means the user has no enrolled push
	// device and the server could not send the email notice either.
	ApprovalReasonNoEnrolledDevice = "no_enrolled_device"
)

// ApprovalError is returned when a push approval was denied by a human
// (ErrApprovalDenied), expired before anyone responded (ErrApprovalTimeout),
// or never reached a push device (ErrApprovalNotDelivered). Code tells the
// three apart: CodeApprovalDenied, CodeApprovalTimeout or
// CodeApprovalNotDelivered.
type ApprovalError struct {
	*BaseError
	// Approval is the last observed approval payload, for audit. It is nil
	// when the request was not delivered.
	Approval *ApprovalResult
	// Reason is set when Code is CodeApprovalNotDelivered:
	// ApprovalReasonEmailFallbackSent or ApprovalReasonNoEnrolledDevice.
	Reason string
	// TaskID is the task the request named, when the server echoed it.
	TaskID string
}

func newApprovalDenied(result *ApprovalResult) *ApprovalError {
	return &ApprovalError{
		BaseError: newError(ErrApprovalDenied, CodeApprovalDenied, "approval was denied"),
		Approval:  result,
	}
}

func newApprovalTimeout(result *ApprovalResult) *ApprovalError {
	return &ApprovalError{
		BaseError: newError(ErrApprovalTimeout, CodeApprovalTimeout,
			"approval timed out before the user responded"),
		Approval: result,
	}
}

// newApprovalNotDelivered builds the not-delivered error. message is the
// server's explanation, or "" for a default one.
func newApprovalNotDelivered(reason, message, taskID string) *ApprovalError {
	if message != "" {
		message = "approval was not delivered: " + message
	} else {
		switch reason {
		case ApprovalReasonEmailFallbackSent:
			message = "approval was not delivered: the user has no enrolled push device, so an email notice was sent instead"
		default:
			message = "approval was not delivered: the user has no enrolled push device"
		}
	}
	return &ApprovalError{
		BaseError: newError(ErrApprovalNotDelivered, CodeApprovalNotDelivered, message),
		Reason:    reason,
		TaskID:    taskID,
	}
}

// BudgetError is returned when an agent's budget policy blocks an action:
// by Agent.CheckBudget, which checks locally and makes no request, and for a
// server answer with the body code budget_exceeded (429).
type BudgetError struct {
	*BaseError
	// Budget is the policy that blocked the action. It is set by
	// CheckBudget; a server refusal carries no policy, so it is nil there.
	Budget *AgentBudget
	// RetryAfter is the server's Retry-After hint: the time until the spent
	// window starts again. 0 for CheckBudget.
	RetryAfter time.Duration
}

func newBudgetExceeded(budget *AgentBudget) *BudgetError {
	return &BudgetError{
		BaseError: newError(ErrBudgetExceeded, CodeBudgetExceeded, "agent budget exceeded"),
		Budget:    budget,
	}
}

// Body codes that select a more specific error than the HTTP status does
// (sdk-contract/errors.json, body_code_map).
const bodyCodeBudgetExceeded = "budget_exceeded"

// withBodyCodeError attaches the error that the response's body code names.
// A budget_exceeded answer gets a *BudgetError as its cause, so the error
// matches ErrBudgetExceeded as well as the sentinel of its status, and the
// returned value stays the *APIError that v1.7.0 returned.
func withBodyCodeError(apiErr *APIError, bodyCode string) *APIError {
	if bodyCode == bodyCodeBudgetExceeded {
		budgetErr := newBudgetExceeded(nil)
		budgetErr.Message = apiErr.Message
		budgetErr.RetryAfter = apiErr.RetryAfter
		apiErr.cause = budgetErr
	}
	return apiErr
}

// AsAPIError extracts the *APIError from an error chain, reporting whether
// one was present. Shorthand for errors.As.
func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	ok := errors.As(err, &apiErr)
	return apiErr, ok
}

// StatusCode returns the HTTP status carried by err, or 0 if the error did
// not come from an HTTP response.
func StatusCode(err error) int {
	if apiErr, ok := AsAPIError(err); ok {
		return apiErr.StatusCode
	}
	return 0
}

// ErrorCode returns the LumoAuth error code carried by err (one of the Code*
// constants, or a server-supplied code), or "" for errors from elsewhere.
func ErrorCode(err error) string {
	var coded interface{ ErrCode() string }
	if errors.As(err, &coded) {
		return coded.ErrCode()
	}
	return ""
}
