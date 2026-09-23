package lumoauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// capture records what a resource actually sent, so the tests assert on
// the wire format rather than on the SDK's own bookkeeping.
type capture struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]any
	Form   url.Values
}

// recordingHandler captures each request and replies with the queued
// response for that call index (the last one repeats).
func recordingHandler(t *testing.T, calls *[]capture, responses ...any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		record := capture{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}

		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(r.Header.Get("Content-Type"), "form-urlencoded") {
			record.Form, _ = url.ParseQuery(string(raw))
		} else if len(raw) > 0 {
			_ = json.Unmarshal(raw, &record.Body)
		}
		*calls = append(*calls, record)

		index := len(*calls) - 1
		if index >= len(responses) {
			index = len(responses) - 1
		}
		if index < 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, 200, responses[index])
	}
}

// ── Permissions ───────────────────────────────────────────────────────

func TestPermissionsResource(t *testing.T) {
	ctx := context.Background()

	t.Run("Check", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"allowed": true, "permission": "document.edit", "user_id": 42}))

		allowed, err := client.Permissions.Check(ctx, "document.edit", &CheckOptions{
			Context: map[string]any{"department": "eng"},
			UserID:  "user-7",
		})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !allowed {
			t.Error("Check should report the server's decision")
		}
		if calls[0].Path != "/api/v1/authz/check" || calls[0].Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", calls[0].Method, calls[0].Path)
		}
		if calls[0].Body["permission"] != "document.edit" {
			t.Errorf("body = %v", calls[0].Body)
		}
		if calls[0].Body["user_id"] != "user-7" {
			t.Errorf("user_id should be forwarded: %v", calls[0].Body)
		}
		if ctx, _ := calls[0].Body["context"].(map[string]any); ctx["department"] != "eng" {
			t.Errorf("context should be forwarded: %v", calls[0].Body)
		}
	})

	t.Run("CheckDetailed decodes a numeric user_id", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"allowed": false, "permission": "document.edit", "user_id": 42}))

		result, err := client.Permissions.CheckDetailed(ctx, "document.edit", nil)
		if err != nil {
			t.Fatalf("CheckDetailed: %v", err)
		}
		if result.UserID != "42" {
			t.Errorf("UserID = %q, want 42 — the API sends it as a string or a number", result.UserID)
		}
	})

	t.Run("CheckBulk", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"results": map[string]bool{"document.edit": true, "document.delete": false},
			"user_id": "user_1",
		}))

		result, err := client.Permissions.CheckBulk(ctx, []string{"document.edit", "document.delete"}, nil)
		if err != nil {
			t.Fatalf("CheckBulk: %v", err)
		}
		if !result.Results["document.edit"] || result.Results["document.delete"] {
			t.Errorf("results = %v", result.Results)
		}
		if calls[0].Path != "/api/v1/authz/check-bulk" {
			t.Errorf("path = %q", calls[0].Path)
		}
	})

	t.Run("CheckAny and CheckAll hit their own endpoints", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{"allowed": true}))

		if _, err := client.Permissions.CheckAny(ctx, []string{"a", "b"}, nil); err != nil {
			t.Fatalf("CheckAny: %v", err)
		}
		if _, err := client.Permissions.CheckAll(ctx, []string{"a", "b"}, nil); err != nil {
			t.Fatalf("CheckAll: %v", err)
		}
		if calls[0].Path != "/api/v1/authz/check-any" {
			t.Errorf("CheckAny path = %q", calls[0].Path)
		}
		if calls[1].Path != "/api/v1/authz/check-all" {
			t.Errorf("CheckAll path = %q", calls[1].Path)
		}
	})

	t.Run("List and ListSlugs", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"user_id": "user_1",
			"count":   2,
			"permissions": []map[string]any{
				{"slug": "document.edit", "source": "role:editor"},
				{"slug": "document.view", "source": "role:viewer"},
			},
		}))

		slugs, err := client.Permissions.ListSlugs(ctx)
		if err != nil {
			t.Fatalf("ListSlugs: %v", err)
		}
		if len(slugs) != 2 || slugs[0] != "document.edit" {
			t.Errorf("slugs = %v", slugs)
		}
	})

	t.Run("rejects empty input before calling out", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			t.Error("no request should have been sent")
		})

		if _, err := client.Permissions.Check(ctx, "", nil); !errors.Is(err, ErrValidation) {
			t.Errorf("an empty permission should be a validation error, got %v", err)
		}
		if _, err := client.Permissions.CheckBulk(ctx, nil, nil); !errors.Is(err, ErrValidation) {
			t.Errorf("an empty permission list should be a validation error, got %v", err)
		}
	})
}

// ── Zanzibar ──────────────────────────────────────────────────────────

func TestZanzibarResource(t *testing.T) {
	ctx := context.Background()

	t.Run("Check", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"allowed": true, "object": "document:readme", "relation": "viewer"}))

		allowed, err := client.Zanzibar.Check(ctx, "document:readme", "viewer", "user:bob")
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !allowed {
			t.Error("Check should report the server's decision")
		}
		if calls[0].Path != "/api/v1/authz/zanzibar/check" {
			t.Errorf("path = %q", calls[0].Path)
		}
		if calls[0].Body["subject"] != "user:bob" {
			t.Errorf("body = %v", calls[0].Body)
		}
	})

	t.Run("relation helpers", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{"allowed": true}))

		helpers := []struct {
			call func() (bool, error)
			want string
		}{
			{func() (bool, error) { return client.Zanzibar.IsViewer(ctx, "doc:1", "user:a") }, "viewer"},
			{func() (bool, error) { return client.Zanzibar.IsEditor(ctx, "doc:1", "user:a") }, "editor"},
			{func() (bool, error) { return client.Zanzibar.IsOwner(ctx, "doc:1", "user:a") }, "owner"},
			{func() (bool, error) { return client.Zanzibar.IsMember(ctx, "doc:1", "user:a") }, "member"},
			{func() (bool, error) { return client.Zanzibar.IsAdmin(ctx, "doc:1", "user:a") }, "admin"},
		}
		for i, helper := range helpers {
			if _, err := helper.call(); err != nil {
				t.Fatalf("helper %d: %v", i, err)
			}
			if calls[i].Body["relation"] != helper.want {
				t.Errorf("helper %d sent relation %v, want %q", i, calls[i].Body["relation"], helper.want)
			}
		}
	})

	t.Run("Expand", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"tree": map[string]any{
				"type":     "union",
				"object":   "document:readme",
				"relation": "viewer",
				"children": []any{
					map[string]any{
						"type":     "leaf",
						"object":   "document:readme",
						"relation": "viewer",
						"subjects": []any{"user:alice", "team:eng#member"},
					},
				},
			},
		}))

		tree, err := client.Zanzibar.Expand(ctx, "document:readme", "viewer")
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		if calls[0].Path != "/api/v1/authz/zanzibar/expand" {
			t.Errorf("path = %q", calls[0].Path)
		}
		// Expand takes no subject; sending one would be a different call.
		if _, ok := calls[0].Body["subject"]; ok {
			t.Errorf("Expand must not send a subject, body = %v", calls[0].Body)
		}
		if tree.Type != "union" || len(tree.Children) != 1 {
			t.Fatalf("tree = %+v", tree)
		}
		if got := tree.Children[0].Subjects; len(got) != 2 || got[0] != "user:alice" {
			t.Errorf("leaf subjects = %v", got)
		}
	})

	t.Run("Expand rejects a response without a tree", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"allowed":true}`))
		})

		if _, err := client.Zanzibar.Expand(ctx, "document:readme", "viewer"); !errors.Is(err, ErrValidation) {
			t.Errorf("a tree-less response should be a validation error, got %v", err)
		}
	})

	t.Run("validates tuple format", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			t.Error("no request should have been sent")
		})

		// Expand validates the same object/relation halves, minus the subject.
		for _, pair := range [][2]string{{"readme", "viewer"}, {"document:readme", ""}, {"", "viewer"}} {
			if _, err := client.Zanzibar.Expand(ctx, pair[0], pair[1]); !errors.Is(err, ErrValidation) {
				t.Errorf("pair %v should be rejected client-side, got %v", pair, err)
			}
		}

		cases := [][3]string{
			{"readme", "viewer", "user:bob"},     // object missing a namespace
			{"document:readme", "", "user:bob"},  // no relation
			{"document:readme", "viewer", "bob"}, // subject missing a namespace
			{"", "viewer", "user:bob"},           // empty object
		}
		for _, tuple := range cases {
			if _, err := client.Zanzibar.Check(ctx, tuple[0], tuple[1], tuple[2]); !errors.Is(err, ErrValidation) {
				t.Errorf("tuple %v should be rejected client-side, got %v", tuple, err)
			}
		}
	})
}

// ── ABAC ──────────────────────────────────────────────────────────────

func TestAbacResource(t *testing.T) {
	ctx := context.Background()

	t.Run("Check translates to camelCase and keeps the raw decision", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"allowed": true,
			"reason":  "policy matched",
			"matchedPolicies": []map[string]any{
				{"id": "p1", "name": "Business hours", "effect": "allow", "priority": 10},
			},
			"evaluationContext": map[string]any{"environment": map[string]any{"hour": 14}},
		}))

		decision, err := client.Abac.Check(ctx, AbacCheckParams{
			ResourceType: "document",
			Action:       "read",
			ResourceID:   "doc-123",
			Context:      map[string]any{"environment": map[string]any{"ip": "10.0.0.1"}},
		})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}

		if !decision.Allowed || decision.Reason != "policy matched" {
			t.Errorf("decision = %+v", decision)
		}
		if len(decision.MatchedPolicies) != 1 || decision.MatchedPolicies[0].Effect != "allow" {
			t.Errorf("matched policies = %+v", decision.MatchedPolicies)
		}
		// Fields the SDK does not model stay reachable through Raw.
		if _, ok := decision.Raw["evaluationContext"]; !ok {
			t.Error("Raw should carry the whole decision, including evaluationContext")
		}

		if calls[0].Path != "/orgs/acme-corp/api/v1/abac/check" {
			t.Errorf("path = %q", calls[0].Path)
		}
		if calls[0].Body["resourceType"] != "document" || calls[0].Body["resourceId"] != "doc-123" {
			t.Errorf("the wire format is camelCase: %v", calls[0].Body)
		}
	})

	t.Run("CheckBulk", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"results": []map[string]any{{"allowed": true}, {"allowed": false}},
		}))

		decisions, err := client.Abac.CheckBulk(ctx, []AbacCheckParams{
			{ResourceType: "document", Action: "read", ResourceID: "1"},
			{ResourceType: "document", Action: "delete", ResourceID: "2"},
		})
		if err != nil {
			t.Fatalf("CheckBulk: %v", err)
		}
		if len(decisions) != 2 || !decisions[0].Allowed || decisions[1].Allowed {
			t.Errorf("decisions = %+v", decisions)
		}

		requests, _ := calls[0].Body["requests"].([]any)
		if len(requests) != 2 {
			t.Fatalf("sent %d requests, want 2", len(requests))
		}
	})

	t.Run("CheckBulk enforces the server cap client-side", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			t.Error("no request should have been sent")
		})

		tooMany := make([]AbacCheckParams, AbacMaxBulkRequests+1)
		for i := range tooMany {
			tooMany[i] = AbacCheckParams{ResourceType: "document", Action: "read"}
		}
		if _, err := client.Abac.CheckBulk(ctx, tooMany); !errors.Is(err, ErrValidation) {
			t.Errorf("expected a validation error over the cap, got %v", err)
		}
	})

	t.Run("attribute management", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"clearance": "secret"}))

		if err := client.Abac.SetUserAttribute(ctx, "user-1", "clearance", "secret"); err != nil {
			t.Fatalf("SetUserAttribute: %v", err)
		}
		if calls[0].Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", calls[0].Method)
		}
		if calls[0].Path != "/orgs/acme-corp/api/v1/abac/users/user-1/attributes/clearance" {
			t.Errorf("path = %q", calls[0].Path)
		}
		if calls[0].Body["value"] != "secret" {
			t.Errorf("body = %v", calls[0].Body)
		}

		if err := client.Abac.SetResourceAttribute(ctx, "document", "doc-1", "sensitivity", "high"); err != nil {
			t.Fatalf("SetResourceAttribute: %v", err)
		}
		want := "/orgs/acme-corp/api/v1/abac/resources/document/doc-1/attributes/sensitivity"
		if calls[1].Path != want {
			t.Errorf("path = %q, want %q", calls[1].Path, want)
		}
	})

	t.Run("AttributeDefinitions accepts both response shapes", func(t *testing.T) {
		definitions := []map[string]any{
			{"id": "1", "name": "Clearance", "slug": "clearance", "attributeType": "user"},
		}

		// Bare array.
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, definitions))
		got, err := client.Abac.AttributeDefinitions(ctx, "")
		if err != nil {
			t.Fatalf("AttributeDefinitions (array): %v", err)
		}
		if len(got) != 1 || got[0].Slug != "clearance" {
			t.Errorf("definitions = %+v", got)
		}

		// Envelope with `data`.
		var envelopeCalls []capture
		envelopeClient, _ := newTestClient(t, recordingHandler(t, &envelopeCalls,
			map[string]any{"data": definitions}))
		got, err = envelopeClient.Abac.AttributeDefinitions(ctx, "")
		if err != nil {
			t.Fatalf("AttributeDefinitions (envelope): %v", err)
		}
		if len(got) != 1 || got[0].Slug != "clearance" {
			t.Errorf("definitions = %+v", got)
		}
	})

	t.Run("validates required arguments", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			t.Error("no request should have been sent")
		})

		if _, err := client.Abac.Check(ctx, AbacCheckParams{Action: "read"}); !errors.Is(err, ErrValidation) {
			t.Errorf("a missing resource type should be rejected, got %v", err)
		}
		if _, err := client.Abac.Check(ctx, AbacCheckParams{ResourceType: "document"}); !errors.Is(err, ErrValidation) {
			t.Errorf("a missing action should be rejected, got %v", err)
		}
	})
}

// ── Agents ────────────────────────────────────────────────────────────

func TestAgentsResource(t *testing.T) {
	ctx := context.Background()

	t.Run("Ask", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"allowed":  false,
			"action":   "document.delete",
			"reason":   "requires human approval",
			"audit_id": "audit_99",
		}))

		result, err := client.Agents.Ask(ctx, "document.delete", map[string]any{"id": "doc_99"})
		if err != nil {
			t.Fatalf("Ask: %v", err)
		}
		if result.Allowed || result.Reason != "requires human approval" || result.AuditID != "audit_99" {
			t.Errorf("result = %+v", result)
		}
		if calls[0].Path != "/orgs/acme-corp/api/v1/agents/ask" {
			t.Errorf("path = %q", calls[0].Path)
		}
		if ctx, _ := calls[0].Body["context"].(map[string]any); ctx["id"] != "doc_99" {
			t.Errorf("context should be forwarded: %v", calls[0].Body)
		}
	})

	t.Run("Me", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"identity":     map[string]any{"id": "agent_1", "name": "Analyser"},
			"capabilities": []string{"read:documents"},
			"workspace":    map[string]any{"id": "ws_1"},
		}))

		identity, err := client.Agents.Me(ctx)
		if err != nil {
			t.Fatalf("Me: %v", err)
		}
		if identity.ID() != "agent_1" {
			t.Errorf("ID() = %q", identity.ID())
		}
		if len(identity.Capabilities) != 1 {
			t.Errorf("capabilities = %v", identity.Capabilities)
		}
	})

	t.Run("Register", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"agent_id": "agent_1", "status": "active"}))

		registration, err := client.Agents.Register(ctx, RegisterParams{
			Name:         "Document Analyser",
			ClientID:     "client_1",
			Description:  "Reads quarterly reports",
			Capabilities: []string{"read:documents"},
			JWKSURI:      "https://agent.example.com/.well-known/jwks.json",
		})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if registration.AgentID != "agent_1" {
			t.Errorf("registration = %+v", registration)
		}
		if calls[0].Body["jwks_uri"] != "https://agent.example.com/.well-known/jwks.json" {
			t.Errorf("body = %v", calls[0].Body)
		}
	})

	t.Run("Capabilities and Budget read UserInfo", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"sub":          "agent_1",
			"capabilities": []string{"read:documents", "tool:search_web"},
			"budget_policy": map[string]any{
				"max_tokens_per_day": 100000,
				"tokens_used_today":  100000,
			},
		}))

		capabilities, err := client.Agents.Capabilities(ctx)
		if err != nil {
			t.Fatalf("Capabilities: %v", err)
		}
		if len(capabilities) != 2 {
			t.Errorf("capabilities = %v", capabilities)
		}
		if calls[0].Path != "/orgs/acme-corp/api/v1/oauth/userinfo" {
			t.Errorf("path = %q", calls[0].Path)
		}

		budget, err := client.Agents.Budget(ctx)
		if err != nil {
			t.Fatalf("Budget: %v", err)
		}
		if !budget.Exhausted() {
			t.Error("a budget at its daily cap should report exhausted")
		}
	})

	t.Run("Budget is never nil", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{"sub": "agent_1"}))

		budget, err := client.Agents.Budget(ctx)
		if err != nil {
			t.Fatalf("Budget: %v", err)
		}
		if budget == nil {
			t.Fatal("Budget returned nil for an agent with no policy")
		}
		if budget.Exhausted() {
			t.Error("an agent with no budget policy is never exhausted")
		}
	})
}

// ── JIT ───────────────────────────────────────────────────────────────

func TestJitResource(t *testing.T) {
	ctx := context.Background()

	t.Run("CreateTask", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"task_id":         "task_1",
			"caep_session_id": "caep_1",
			"expires_at":      "2026-08-14T12:00:00Z",
		}))

		task, err := client.Jit.CreateTask(ctx, CreateTaskParams{
			Name: "Analyse Q4", Type: "analysis", OnBehalfOf: "ada@acme.com",
		})
		if err != nil {
			t.Fatalf("CreateTask: %v", err)
		}
		if task.TaskID != "task_1" || task.CaepSessionID != "caep_1" {
			t.Errorf("task = %+v", task)
		}
		if calls[0].Body["on_behalf_of"] != "ada@acme.com" || calls[0].Body["type"] != "analysis" {
			t.Errorf("body = %v", calls[0].Body)
		}
	})

	t.Run("Request caps the TTL at the server maximum", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"request_id": "req_1", "status": "approved"}))

		if _, err := client.Jit.Request(ctx, RequestPermissionParams{
			TaskID:               "task_1",
			AuthorizationDetails: map[string]any{"type": "file_access"},
			TTL:                  99999,
		}); err != nil {
			t.Fatalf("Request: %v", err)
		}
		if ttl, _ := calls[0].Body["requested_ttl"].(float64); int(ttl) != JitMaxTTL {
			t.Errorf("requested_ttl = %v, want it capped at %d", calls[0].Body["requested_ttl"], JitMaxTTL)
		}
	})

	t.Run("Request applies the default TTL", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"request_id": "req_1", "status": "approved"}))

		if _, err := client.Jit.Request(ctx, RequestPermissionParams{
			TaskID:               "task_1",
			AuthorizationDetails: map[string]any{"type": "file_access"},
		}); err != nil {
			t.Fatalf("Request: %v", err)
		}
		if ttl, _ := calls[0].Body["requested_ttl"].(float64); int(ttl) != JitDefaultTTL {
			t.Errorf("requested_ttl = %v, want %d", calls[0].Body["requested_ttl"], JitDefaultTTL)
		}
	})

	t.Run("Token", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"access_token": "jit_token", "expires_in": 300}))

		token, err := client.Jit.Token(ctx, "req_1")
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
		if token.AccessToken != "jit_token" {
			t.Errorf("token = %+v", token)
		}
		if calls[0].Path != "/orgs/acme-corp/api/v1/jit/request/req_1/token" {
			t.Errorf("path = %q", calls[0].Path)
		}
	})

	t.Run("Pending accepts both response shapes", func(t *testing.T) {
		requests := []map[string]any{{"request_id": "req_1", "status": "pending"}}

		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, requests))
		got, err := client.Jit.Pending(ctx)
		if err != nil {
			t.Fatalf("Pending (array): %v", err)
		}
		if len(got) != 1 {
			t.Errorf("got %d pending requests", len(got))
		}

		var envelopeCalls []capture
		envelopeClient, _ := newTestClient(t, recordingHandler(t, &envelopeCalls,
			map[string]any{"requests": requests}))
		got, err = envelopeClient.Jit.Pending(ctx)
		if err != nil {
			t.Fatalf("Pending (envelope): %v", err)
		}
		if len(got) != 1 {
			t.Errorf("got %d pending requests", len(got))
		}
	})

	t.Run("EvaluateTask defaults to completed", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{"ok": true}))

		if _, err := client.Jit.EvaluateTask(ctx, "task_1", EvaluateTaskParams{Notes: "all good"}); err != nil {
			t.Fatalf("EvaluateTask: %v", err)
		}
		if calls[0].Body["result"] != TaskResultCompleted {
			t.Errorf("result = %v, want %q", calls[0].Body["result"], TaskResultCompleted)
		}
	})
}

// ── Approvals ─────────────────────────────────────────────────────────

func TestApprovalsResource(t *testing.T) {
	ctx := context.Background()

	t.Run("Create", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"approval_token": "appr_1",
			"status":         "pending",
			"task_id":        "wire-001",
			"impact":         "high",
		}))

		result, err := client.Approvals.Create(ctx, ApprovalParams{
			TaskID:     "wire-001",
			Reason:     "Wire $4,500 to INV-7741",
			Impact:     ImpactHigh,
			OnBehalfOf: "ada@acme.com",
			Meta:       map[string]any{"amount": 4500},
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if result.Token != "appr_1" || result.Status != ApprovalPending {
			t.Errorf("result = %+v", result)
		}
		if calls[0].Path != "/orgs/acme-corp/api/v1/agents/me/approvals" {
			t.Errorf("path = %q", calls[0].Path)
		}
		if calls[0].Body["on_behalf_of"] != "ada@acme.com" || calls[0].Body["impact"] != "high" {
			t.Errorf("body = %v", calls[0].Body)
		}
	})

	t.Run("Create defaults impact to medium and validates it", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"approval_token": "appr_1", "status": "pending"}))

		if _, err := client.Approvals.Create(ctx, ApprovalParams{
			TaskID: "t", Reason: "r", OnBehalfOf: "ada@acme.com",
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if calls[0].Body["impact"] != string(ImpactMedium) {
			t.Errorf("impact = %v, want medium", calls[0].Body["impact"])
		}

		if _, err := client.Approvals.Create(ctx, ApprovalParams{
			TaskID: "t", Reason: "r", OnBehalfOf: "ada@acme.com", Impact: "catastrophic",
		}); !errors.Is(err, ErrValidation) {
			t.Errorf("an invalid impact should be rejected client-side, got %v", err)
		}
	})

	t.Run("Require returns on approval", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"approval_token": "appr_1", "status": "pending"},
			map[string]any{
				"approval_token": "appr_1",
				"status":         "approved",
				"task_id":        "wire-001",
				"approved_by":    map[string]any{"user_id": 7, "email": "ada@acme.com"},
			},
		))

		result, err := client.Approvals.Require(ctx, ApprovalParams{
			TaskID: "wire-001", Reason: "Wire funds", OnBehalfOf: "ada@acme.com",
		}, &WaitOptions{PollInterval: time.Millisecond, Timeout: time.Second})
		if err != nil {
			t.Fatalf("Require: %v", err)
		}
		if !result.Approved() {
			t.Errorf("result = %+v", result)
		}
		if result.ApprovedBy == nil || result.ApprovedBy.Email != "ada@acme.com" {
			t.Errorf("approver = %+v", result.ApprovedBy)
		}
	})

	t.Run("Require reports a denial as an error carrying the payload", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"approval_token": "appr_1", "status": "pending"},
			map[string]any{"approval_token": "appr_1", "status": "denied", "reason": "too large"},
		))

		result, err := client.Approvals.Require(ctx, ApprovalParams{
			TaskID: "wire-001", Reason: "Wire funds", OnBehalfOf: "ada@acme.com",
		}, &WaitOptions{PollInterval: time.Millisecond, Timeout: time.Second})

		if !errors.Is(err, ErrApprovalDenied) {
			t.Fatalf("expected ErrApprovalDenied, got %v", err)
		}
		if result == nil || result.Status != ApprovalDenied {
			t.Errorf("the final payload should still be returned: %+v", result)
		}

		var approvalErr *ApprovalError
		if !errors.As(err, &approvalErr) || approvalErr.Approval == nil {
			t.Error("the error should carry the approval payload for audit")
		}
	})

	t.Run("Require times out while still pending", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"approval_token": "appr_1", "status": "pending"}))

		_, err := client.Approvals.Require(ctx, ApprovalParams{
			TaskID: "wire-001", Reason: "Wire funds", OnBehalfOf: "ada@acme.com",
		}, &WaitOptions{PollInterval: time.Millisecond, Timeout: 20 * time.Millisecond})

		if !errors.Is(err, ErrApprovalTimeout) {
			t.Errorf("expected ErrApprovalTimeout, got %v", err)
		}
	})
}

// ── MCP ───────────────────────────────────────────────────────────────

func TestMcpResource(t *testing.T) {
	ctx := context.Background()

	t.Run("Token exchanges for an audience-scoped token", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"access_token": "mcp_token", "expires_in": 600, "token_type": "Bearer"}),
			WithAccessToken("agent-token"))

		token, err := client.Mcp.Token(ctx, "urn:mcp:financial-data", "")
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
		if token != "mcp_token" {
			t.Errorf("token = %q", token)
		}

		form := calls[0].Form
		if form.Get("grant_type") != GrantTypeTokenExchange {
			t.Errorf("grant_type = %q", form.Get("grant_type"))
		}
		if form.Get("audience") != "urn:mcp:financial-data" {
			t.Errorf("audience = %q", form.Get("audience"))
		}
		if form.Get("subject_token") != "agent-token" {
			t.Errorf("subject_token = %q, want the client's own token", form.Get("subject_token"))
		}
	})

	t.Run("Token accepts an explicit subject token", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"access_token": "mcp_token"}), WithAccessToken("agent-token"))

		if _, err := client.Mcp.Token(ctx, "urn:mcp:data", "explicit-subject"); err != nil {
			t.Fatalf("Token: %v", err)
		}
		if calls[0].Form.Get("subject_token") != "explicit-subject" {
			t.Errorf("subject_token = %q", calls[0].Form.Get("subject_token"))
		}
	})

	t.Run("Token requires a subject", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			t.Error("no request should have been sent")
		})

		// An API-key client has no bearer token to exchange.
		if _, err := client.Mcp.Token(ctx, "urn:mcp:data", ""); !errors.Is(err, ErrConfig) {
			t.Errorf("expected a config error, got %v", err)
		}
		if _, err := client.Mcp.Token(ctx, "", "subject"); !errors.Is(err, ErrValidation) {
			t.Errorf("a missing server ID should be a validation error, got %v", err)
		}
	})
}

// ── Auth ──────────────────────────────────────────────────────────────

func TestAuthResource(t *testing.T) {
	ctx := context.Background()

	t.Run("AuthorizationURL", func(t *testing.T) {
		client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {})

		got, err := client.Auth.AuthorizationURL(AuthorizationURLParams{
			ClientID:      "client_1",
			RedirectURI:   "https://app.example.com/callback",
			State:         "state-123",
			CodeChallenge: "challenge-value",
			Extra:         map[string]string{"login_hint": "ada@acme.com"},
		})
		if err != nil {
			t.Fatalf("AuthorizationURL: %v", err)
		}

		parsed, err := url.Parse(got)
		if err != nil {
			t.Fatalf("parsing the URL: %v", err)
		}
		if parsed.Path != "/orgs/acme-corp/api/v1/oauth/authorize" {
			t.Errorf("path = %q", parsed.Path)
		}
		if !strings.HasPrefix(got, server.URL) {
			t.Errorf("the URL should point at the configured instance: %q", got)
		}

		query := parsed.Query()
		for key, want := range map[string]string{
			"response_type":         "code",
			"client_id":             "client_1",
			"redirect_uri":          "https://app.example.com/callback",
			"scope":                 "openid profile email",
			"state":                 "state-123",
			"code_challenge":        "challenge-value",
			"code_challenge_method": "S256",
			"login_hint":            "ada@acme.com",
		} {
			if query.Get(key) != want {
				t.Errorf("%s = %q, want %q", key, query.Get(key), want)
			}
		}
	})

	t.Run("AuthorizationURL validates its inputs", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {})

		if _, err := client.Auth.AuthorizationURL(AuthorizationURLParams{
			RedirectURI: "https://app.example.com/callback",
		}); !errors.Is(err, ErrValidation) {
			t.Errorf("a missing client ID should be rejected, got %v", err)
		}
	})

	t.Run("ExchangeCode", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{
			"access_token":  "at",
			"refresh_token": "rt",
			"expires_in":    3600,
			"scope":         "openid profile",
		}))

		token, err := client.Auth.ExchangeCode(ctx, ExchangeCodeParams{
			Code:         "auth-code",
			RedirectURI:  "https://app.example.com/callback",
			ClientID:     "client_1",
			ClientSecret: "secret",
			CodeVerifier: "verifier",
		})
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}
		if token.AccessToken != "at" || token.RefreshToken != "rt" {
			t.Errorf("token = %+v", token)
		}
		if got := token.Scopes(); len(got) != 2 || got[0] != "openid" {
			t.Errorf("Scopes() = %v", got)
		}

		form := calls[0].Form
		if form.Get("grant_type") != "authorization_code" || form.Get("code_verifier") != "verifier" {
			t.Errorf("form = %v", form)
		}
	})

	t.Run("TokenExchange", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls,
			map[string]any{"access_token": "delegated"}))

		if _, err := client.Auth.TokenExchange(ctx, TokenExchangeParams{
			SubjectToken: "user-token",
			ActorToken:   "agent-token",
			Scopes:       []string{"read:documents"},
		}); err != nil {
			t.Fatalf("TokenExchange: %v", err)
		}

		form := calls[0].Form
		if form.Get("grant_type") != GrantTypeTokenExchange {
			t.Errorf("grant_type = %q", form.Get("grant_type"))
		}
		if form.Get("subject_token_type") != TokenTypeAccessToken ||
			form.Get("actor_token_type") != TokenTypeAccessToken {
			t.Errorf("both token types should be declared: %v", form)
		}
		if form.Get("scope") != "read:documents" {
			t.Errorf("scope = %q", form.Get("scope"))
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{}))

		if err := client.Auth.Revoke(ctx, RevokeParams{
			Token:         "rt",
			TokenTypeHint: "refresh_token",
			ClientID:      "client_1",
			ClientSecret:  "secret",
		}); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if calls[0].Path != "/orgs/acme-corp/api/v1/oauth/revoke" {
			t.Errorf("path = %q", calls[0].Path)
		}
		if calls[0].Form.Get("token_type_hint") != "refresh_token" {
			t.Errorf("form = %v", calls[0].Form)
		}
	})

	t.Run("a token response with no access_token is an error", func(t *testing.T) {
		var calls []capture
		client, _ := newTestClient(t, recordingHandler(t, &calls, map[string]any{"expires_in": 3600}))

		if _, err := client.Auth.ClientCredentials(ctx, "cid", "secret"); !errors.Is(err, ErrValidation) {
			t.Errorf("expected a validation error, got %v", err)
		}
	})
}

// ── Delegation primitives ─────────────────────────────────────────────

func TestParseActorChain(t *testing.T) {
	// user → orchestrator → search-tool, as nested `act` claims.
	claims := map[string]any{
		"sub": "user:ada",
		"act": map[string]any{
			"sub": "agent:orchestrator",
			"act": map[string]any{"sub": "agent:search-tool"},
		},
	}
	payload, _ := json.Marshal(claims)
	token := "header." + b64url(payload) + ".signature"

	chain, err := ParseActorChain(token)
	if err != nil {
		t.Fatalf("ParseActorChain: %v", err)
	}
	want := []string{"agent:orchestrator", "agent:search-tool"}
	if len(chain) != len(want) {
		t.Fatalf("chain = %v, want %v", chain, want)
	}
	for i := range want {
		if chain[i] != want[i] {
			t.Errorf("chain[%d] = %q, want %q", i, chain[i], want[i])
		}
	}

	subject, err := TokenSubject(token)
	if err != nil {
		t.Fatalf("TokenSubject: %v", err)
	}
	if subject != "user:ada" {
		t.Errorf("subject = %q", subject)
	}
}

func TestParseActorChainRejectsMalformedTokens(t *testing.T) {
	if _, err := ParseActorChain("not-a-jwt"); !errors.Is(err, ErrValidation) {
		t.Errorf("expected a validation error, got %v", err)
	}
	if _, err := TokenSubject("header.!!!not-base64!!!.sig"); !errors.Is(err, ErrValidation) {
		t.Errorf("expected a validation error, got %v", err)
	}
}
