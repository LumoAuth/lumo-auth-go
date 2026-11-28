package lumoauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestErrorSentinels(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		sentinel error
		code     string
	}{
		{"401", newAPIError(401, "", "nope", nil), ErrAuthentication, CodeAuthentication},
		{"403", newAPIError(403, "", "nope", nil), ErrPermissionDenied, CodePermissionDenied},
		{"404", newAPIError(404, "", "nope", nil), ErrNotFound, CodeNotFound},
		{"429", newAPIError(429, "", "nope", nil), ErrRateLimited, CodeRateLimited},
		{"500", newAPIError(500, "", "boom", nil), ErrAPI, CodeAPI},
		{"validation", NewValidationError("bad"), ErrValidation, CodeValidation},
		{"config", NewConfigError("missing"), ErrConfig, CodeConfig},
		{"network", newNetworkError("down", nil), ErrNetwork, CodeNetwork},
		{"approval denied", newApprovalDenied(nil), ErrApprovalDenied, CodeApprovalDenied},
		{"approval timeout", newApprovalTimeout(nil), ErrApprovalTimeout, CodeApprovalTimeout},
		{"budget", newBudgetExceeded(nil), ErrBudgetExceeded, CodeBudgetExceeded},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.sentinel) {
				t.Errorf("errors.Is(err, %v) = false", tc.sentinel)
			}
			if !errors.Is(tc.err, ErrLumoAuth) {
				t.Error("every SDK error must match ErrLumoAuth")
			}
			if got := ErrorCode(tc.err); got != tc.code {
				t.Errorf("ErrorCode = %q, want %q", got, tc.code)
			}
			// A sentinel must not match an unrelated one.
			if errors.Is(tc.err, ErrBudgetExceeded) && tc.sentinel != ErrBudgetExceeded {
				t.Error("error matched an unrelated sentinel")
			}
		})
	}
}

func TestAPIErrorMatchesErrAPIForEveryStatus(t *testing.T) {
	for _, status := range []int{401, 403, 404, 429, 500} {
		err := newAPIError(status, "", "failed", nil)
		if !errors.Is(err, ErrAPI) {
			t.Errorf("status %d should match ErrAPI so callers can catch all server failures", status)
		}
	}
}

func TestAsAPIErrorAndStatusCode(t *testing.T) {
	err := newAPIError(403, "CUSTOM_CODE", "denied", map[string]any{"error": "forbidden"})

	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatal("AsAPIError did not find the API error")
	}
	if apiErr.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if apiErr.Code != "CUSTOM_CODE" {
		t.Errorf("a server-supplied code should win: got %q", apiErr.Code)
	}
	if StatusCode(err) != 403 {
		t.Errorf("StatusCode helper = %d, want 403", StatusCode(err))
	}

	// Wrapping must not break extraction.
	wrapped := fmt.Errorf("while checking permissions: %w", err)
	if _, ok := AsAPIError(wrapped); !ok {
		t.Error("AsAPIError should see through fmt.Errorf wrapping")
	}
	if !errors.Is(wrapped, ErrPermissionDenied) {
		t.Error("errors.Is should see through fmt.Errorf wrapping")
	}

	// Non-SDK errors report nothing.
	if _, ok := AsAPIError(errors.New("unrelated")); ok {
		t.Error("AsAPIError matched a non-SDK error")
	}
	if StatusCode(errors.New("unrelated")) != 0 {
		t.Error("StatusCode should be 0 for non-HTTP errors")
	}
	if ErrorCode(errors.New("unrelated")) != "" {
		t.Error("ErrorCode should be empty for non-SDK errors")
	}
}

func TestNetworkErrorUnwrapsCause(t *testing.T) {
	cause := errors.New("dial tcp: connection refused")
	err := newNetworkError("request failed", cause)

	if !errors.Is(err, cause) {
		t.Error("the transport cause should stay reachable through Unwrap")
	}
	if !errors.Is(err, ErrNetwork) {
		t.Error("a network error should match ErrNetwork")
	}
}

func TestRateLimitErrorCarriesRetryAfter(t *testing.T) {
	err := newAPIError(429, "", "slow down", nil)
	err.RetryAfter = 30 * time.Second

	apiErr, _ := AsAPIError(err)
	if apiErr.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v, want 30s", apiErr.RetryAfter)
	}
}

func TestErrorsImplementErrorInterface(t *testing.T) {
	// Guards against the embedded-field-shadows-method trap: a type
	// embedding *BaseError must still satisfy `error`.
	var _ error = &APIError{BaseError: newError(ErrAPI, CodeAPI, "x")}
	var _ error = NewValidationError("x")
	var _ error = NewConfigError("x")
	var _ error = newNetworkError("x", nil)
	var _ error = newApprovalDenied(nil)
	var _ error = newBudgetExceeded(nil)

	if got := NewConfigError("missing base URL").Error(); got != "missing base URL" {
		t.Errorf("Error() = %q, want the message", got)
	}
}

func TestBudgetExceededResponseIsABudgetAndARateLimitError(t *testing.T) {
	// The server's refusal for a spent agent budget
	// (AgentBudgetExceededException): 429, Retry-After, body code
	// budget_exceeded.
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "budget_exceeded", "error_description": "Agent budget exceeded",
		})
	})
	_, err := client.Agents.Ask(context.Background(), "reports:read", nil)

	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("errors.Is(err, ErrBudgetExceeded) = false for %v", err)
	}
	// Code written for v1.7.0 caught it as a rate limit; it still does.
	if !errors.Is(err, ErrRateLimited) || !errors.Is(err, ErrAPI) || !errors.Is(err, ErrLumoAuth) {
		t.Errorf("the budget error must still match ErrRateLimited, ErrAPI and ErrLumoAuth: %v", err)
	}
	var budgetErr *BudgetError
	if !errors.As(err, &budgetErr) {
		t.Fatalf("errors.As(err, *BudgetError) = false")
	}
	if budgetErr.RetryAfter != 120*time.Second || budgetErr.Code != CodeBudgetExceeded {
		t.Errorf("BudgetError = %+v", budgetErr)
	}
	if budgetErr.Error() != "Agent budget exceeded" {
		t.Errorf("message = %q", budgetErr.Error())
	}
	apiErr, ok := err.(*APIError) // the type stays *APIError, as in v1.7.0
	if !ok || apiErr.StatusCode != 429 || apiErr.RetryAfter != 120*time.Second || apiErr.Code != "budget_exceeded" {
		t.Errorf("APIError = %+v (ok %v)", apiErr, ok)
	}
}

func TestOtherRateLimitsAreNoBudgetError(t *testing.T) {
	for _, body := range []map[string]any{
		{"error": "rate_limited"},
		{"error": "rate_limit_exceeded", "error_description": "Too many attestation attempts; retry later."},
		nil,
	} {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusTooManyRequests, body)
		})
		_, err := client.Agents.Ask(context.Background(), "reports:read", nil)
		if !errors.Is(err, ErrRateLimited) || errors.Is(err, ErrBudgetExceeded) {
			t.Errorf("body %v: want a plain rate limit error, got %v", body, err)
		}
		var budgetErr *BudgetError
		if errors.As(err, &budgetErr) {
			t.Errorf("body %v: unexpected *BudgetError", body)
		}
	}
}
