package lumoauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// jitServer routes the endpoints a JIT flow touches, delegating everything
// else to the caller's handler.
func jitServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			writeJSON(w, 200, map[string]any{"access_token": "agent-token", "expires_in": 3600})
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func newTestJIT(t *testing.T, handler http.HandlerFunc) *JITContext {
	t.Helper()

	server := jitServer(t, handler)
	agent, err := NewAgent(AgentConfig{
		BaseURL: server.URL, OrgID: "acme-corp",
		ClientID: "c", ClientSecret: "s",
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	jit, err := NewJITContext(agent)
	if err != nil {
		t.Fatalf("NewJITContext: %v", err)
	}
	return jit
}

func TestJITContextTaskLifecycle(t *testing.T) {
	var completed []string
	jit := newTestJIT(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/task":
			writeJSON(w, 200, map[string]any{
				"task_id": "task_1", "caep_session_id": "caep_1",
				"expires_at": "2026-08-14T12:00:00Z",
			})
		case strings.HasSuffix(r.URL.Path, "/complete"):
			completed = append(completed, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})

	ctx := context.Background()

	task, err := jit.CreateTask(ctx, CreateTaskParams{Name: "Analyse Q4 report"})
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if task.TaskID != "task_1" {
		t.Errorf("task = %+v", task)
	}
	if jit.TaskID() != "task_1" || jit.CaepSessionID() != "caep_1" {
		t.Errorf("the context should track the current task: %q / %q", jit.TaskID(), jit.CaepSessionID())
	}

	if err := jit.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(completed) != 1 || !strings.Contains(completed[0], "task_1") {
		t.Errorf("completed = %v", completed)
	}
	if jit.TaskID() != "" {
		t.Error("the task should be cleared after completion")
	}

	// Close is safe to call again — the defer pattern depends on it.
	if err := jit.Close(ctx); err != nil {
		t.Errorf("a second Close should be a no-op, got %v", err)
	}
	if len(completed) != 1 {
		t.Errorf("a second Close sent another request: %v", completed)
	}
}

func TestJITContextRequestPermissionAutoApproved(t *testing.T) {
	var calls []capture
	jit := newTestJIT(t, recordingHandler(t, &calls,
		map[string]any{"task_id": "task_1"},
		map[string]any{"request_id": "req_1", "status": "approved", "risk_level": "low"},
		map[string]any{"access_token": "jit-token", "expires_in": 300},
	))

	ctx := context.Background()
	if _, err := jit.CreateTask(ctx, CreateTaskParams{Name: "read report"}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	result, err := jit.RequestPermission(ctx, map[string]any{
		"type": "file_access", "actions": []string{"read"}, "identifier": "report_q4.pdf",
	}, &RequestPermissionOptions{Justification: "user asked for the Q4 summary"})
	if err != nil {
		t.Fatalf("RequestPermission: %v", err)
	}
	if !result.Approved() {
		t.Errorf("result = %+v", result)
	}

	body := calls[1].Body
	if body["task_id"] != "task_1" {
		t.Errorf("the current task should be attached: %v", body)
	}
	if body["justification"] != "user asked for the Q4 summary" {
		t.Errorf("justification = %v", body["justification"])
	}

	token, err := jit.Token(ctx, result.RequestID)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token != "jit-token" {
		t.Errorf("token = %q", token)
	}
}

func TestJITContextPollsForHumanApproval(t *testing.T) {
	var statusPolls int
	jit := newTestJIT(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/task":
			writeJSON(w, 200, map[string]any{"task_id": "task_1"})
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/request":
			writeJSON(w, 200, map[string]any{
				"request_id": "req_1", "status": "pending", "risk_level": "high",
			})
		case strings.HasSuffix(r.URL.Path, "/status"):
			statusPolls++
			status := "pending"
			if statusPolls >= 2 {
				status = "approved"
			}
			writeJSON(w, 200, map[string]any{"request_id": "req_1", "status": status})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})

	ctx := context.Background()
	if _, err := jit.CreateTask(ctx, CreateTaskParams{}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	result, err := jit.RequestPermission(ctx, map[string]any{"type": "wire_transfer"},
		&RequestPermissionOptions{
			PollInterval: time.Millisecond,
			PollTimeout:  2 * time.Second,
		})
	if err != nil {
		t.Fatalf("RequestPermission: %v", err)
	}
	if !result.Approved() {
		t.Errorf("polling should have observed the approval: %+v", result)
	}
	if statusPolls < 2 {
		t.Errorf("polls = %d, want at least 2", statusPolls)
	}
}

func TestJITContextNoWaitReturnsPending(t *testing.T) {
	jit := newTestJIT(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/task":
			writeJSON(w, 200, map[string]any{"task_id": "task_1"})
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/request":
			writeJSON(w, 200, map[string]any{"request_id": "req_1", "status": "pending"})
		default:
			t.Errorf("NoWait should not poll, but hit %q", r.URL.Path)
		}
	})

	ctx := context.Background()
	if _, err := jit.CreateTask(ctx, CreateTaskParams{}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	result, err := jit.RequestPermission(ctx, map[string]any{"type": "wire_transfer"},
		&RequestPermissionOptions{NoWait: true})
	if err != nil {
		t.Fatalf("RequestPermission: %v", err)
	}
	if !result.Pending() {
		t.Errorf("result = %+v, want the pending request back immediately", result)
	}
}

func TestJITContextPollTimeoutReturnsLastState(t *testing.T) {
	jit := newTestJIT(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/task":
			writeJSON(w, 200, map[string]any{"task_id": "task_1"})
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/request":
			writeJSON(w, 200, map[string]any{"request_id": "req_1", "status": "pending"})
		default:
			writeJSON(w, 200, map[string]any{"request_id": "req_1", "status": "pending"})
		}
	})

	ctx := context.Background()
	if _, err := jit.CreateTask(ctx, CreateTaskParams{}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	result, err := jit.RequestPermission(ctx, map[string]any{"type": "wire_transfer"},
		&RequestPermissionOptions{PollInterval: time.Millisecond, PollTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("a timeout should not be an error, got %v", err)
	}
	if !result.Pending() {
		t.Errorf("a timed-out wait should report the last state: %+v", result)
	}
}

func TestJITContextRequiresATask(t *testing.T) {
	jit := newTestJIT(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request should have been sent, got %q", r.URL.Path)
	})

	_, err := jit.RequestPermission(context.Background(), map[string]any{"type": "file_access"}, nil)
	if !errors.Is(err, ErrConfig) {
		t.Errorf("expected a config error without a task, got %v", err)
	}
}

func TestJITContextCallWithEscalation(t *testing.T) {
	required := map[string]any{
		"type": "file_access", "actions": []string{"read"}, "identifier": "report.pdf",
	}
	encoded, _ := json.Marshal(required)
	header := base64.StdEncoding.EncodeToString(encoded)

	var protectedCalls int
	var sawJITToken bool

	server := jitServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/task":
			writeJSON(w, 200, map[string]any{"task_id": "task_1"})
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/request":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			details, _ := body["authorization_details"].(map[string]any)
			if details["identifier"] != "report.pdf" {
				t.Errorf("the escalation should request exactly what the server named: %v", details)
			}
			writeJSON(w, 200, map[string]any{"request_id": "req_1", "status": "approved"})
		case strings.HasSuffix(r.URL.Path, "/token"):
			writeJSON(w, 200, map[string]any{"access_token": "jit-token", "expires_in": 300})
		case r.URL.Path == "/protected":
			protectedCalls++
			if r.Header.Get("Authorization") == "Bearer jit-token" {
				sawJITToken = true
				writeJSON(w, 200, map[string]any{"content": "the report"})
				return
			}
			// First attempt: tell the caller precisely what it lacks.
			w.Header().Set("Insufficient-Authorization-Details", header)
			writeJSON(w, 403, map[string]any{"error": "insufficient_authorization_details"})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})

	agent, err := NewAgent(AgentConfig{
		BaseURL: server.URL, OrgID: "acme-corp", ClientID: "c", ClientSecret: "s",
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	jit, err := NewJITContext(agent)
	if err != nil {
		t.Fatalf("NewJITContext: %v", err)
	}

	ctx := context.Background()
	if _, err := jit.CreateTask(ctx, CreateTaskParams{}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	response, err := jit.CallWithEscalation(ctx, http.MethodGet, server.URL+"/protected", nil, nil)
	if err != nil {
		t.Fatalf("CallWithEscalation: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 after escalation", response.StatusCode)
	}
	if !sawJITToken {
		t.Error("the retry should have carried the JIT token")
	}
	if protectedCalls != 2 {
		t.Errorf("the protected endpoint was called %d times, want 2 (attempt + retry)", protectedCalls)
	}
}

func TestJITContextEscalationRefusedKeepsThe403(t *testing.T) {
	required, _ := json.Marshal(map[string]any{"type": "wire_transfer"})
	header := base64.StdEncoding.EncodeToString(required)

	server := jitServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/task":
			writeJSON(w, 200, map[string]any{"task_id": "task_1"})
		case r.URL.Path == "/orgs/acme-corp/api/v1/jit/request":
			writeJSON(w, 200, map[string]any{"request_id": "req_1", "status": "denied"})
		case r.URL.Path == "/protected":
			w.Header().Set("Insufficient-Authorization-Details", header)
			writeJSON(w, 403, map[string]any{"error": "insufficient_authorization_details"})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})

	agent, _ := NewAgent(AgentConfig{
		BaseURL: server.URL, OrgID: "acme-corp", ClientID: "c", ClientSecret: "s",
	})
	jit, _ := NewJITContext(agent)

	ctx := context.Background()
	if _, err := jit.CreateTask(ctx, CreateTaskParams{}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	response, err := jit.CallWithEscalation(ctx, http.MethodGet, server.URL+"/protected", nil,
		&RequestPermissionOptions{NoWait: true})
	if err != nil {
		t.Fatalf("CallWithEscalation: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want the original 403 when escalation is refused", response.StatusCode)
	}
}

func TestJITContextDelegatedTokenWins(t *testing.T) {
	var seen string
	server := jitServer(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		writeJSON(w, 200, map[string]any{"task_id": "task_1"})
	})

	agent, _ := NewAgent(AgentConfig{
		BaseURL: server.URL, OrgID: "acme-corp", ClientID: "c", ClientSecret: "s",
	})
	jit, err := NewJITContext(agent, WithDelegatedToken("delegated-token"))
	if err != nil {
		t.Fatalf("NewJITContext: %v", err)
	}

	if _, err := jit.CreateTask(context.Background(), CreateTaskParams{}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if seen != "Bearer delegated-token" {
		t.Errorf("Authorization = %q, want the delegated token", seen)
	}
}

func TestJITContextDelegateOnBehalfOf(t *testing.T) {
	var exchangeForm map[string][]string
	var taskAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			_ = r.ParseForm()
			if r.Form.Get("grant_type") == GrantTypeTokenExchange {
				exchangeForm = r.Form
				writeJSON(w, 200, map[string]any{"access_token": "delegated-token"})
				return
			}
			writeJSON(w, 200, map[string]any{"access_token": "agent-token", "expires_in": 3600})
			return
		}
		taskAuth = r.Header.Get("Authorization")
		writeJSON(w, 200, map[string]any{"task_id": "task_1"})
	}))
	defer server.Close()

	agent, _ := NewAgent(AgentConfig{
		BaseURL: server.URL, OrgID: "acme-corp", ClientID: "c", ClientSecret: "s",
	})
	jit, _ := NewJITContext(agent)

	ctx := context.Background()
	if err := jit.DelegateOnBehalfOf(ctx, "user-token"); err != nil {
		t.Fatalf("DelegateOnBehalfOf: %v", err)
	}

	if exchangeForm["subject_token"][0] != "user-token" {
		t.Errorf("subject_token = %v, want the user's token", exchangeForm["subject_token"])
	}
	if exchangeForm["actor_token"][0] != "agent-token" {
		t.Errorf("actor_token = %v, want the agent's token", exchangeForm["actor_token"])
	}

	if _, err := jit.CreateTask(ctx, CreateTaskParams{}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if taskAuth != "Bearer delegated-token" {
		t.Errorf("after delegation the context should use the delegated token, got %q", taskAuth)
	}
}
