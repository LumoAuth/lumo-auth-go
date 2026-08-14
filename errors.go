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
//	├── ValidationError            (bad input / unexpected response shape)
//	├── ConfigError                (missing or invalid configuration)
//	├── NetworkError               (transport failure: DNS, timeout, TLS, …)
//	├── ApprovalError              (denied / timed out)
//	└── BudgetError                (agent budget exhausted)
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
	CodeBudgetExceeded   = "BUDGET_EXCEEDED"
)

// Sentinel errors for errors.Is. Every error returned by this SDK matches
// ErrLumoAuth; each also matches exactly one of the specific sentinels.
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
		BaseError:  newError(kind, code, message),
		StatusCode: status,
		Body:       body,
	}
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

// ApprovalError is returned when a push approval was denied by a human
// (ErrApprovalDenied) or expired before anyone responded (ErrApprovalTimeout).
type ApprovalError struct {
	*BaseError
	// Approval is the last observed approval payload, for audit.
	Approval *ApprovalResult
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

// BudgetError is returned when an agent's budget policy blocks an action.
type BudgetError struct {
	*BaseError
	// Budget is the policy that blocked the action.
	Budget *AgentBudget
}

func newBudgetExceeded(budget *AgentBudget) *BudgetError {
	return &BudgetError{
		BaseError: newError(ErrBudgetExceeded, CodeBudgetExceeded, "agent budget exceeded"),
		Budget:    budget,
	}
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
