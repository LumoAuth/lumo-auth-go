package lumoauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The contract cases (sdk-contract/vectors/agent-capabilities.json) are checked
// against the server's own matcher by the contract repo, and against this SDK
// here. The inline cases run even without the contract checkout.

type capabilityVector struct {
	Normalize []struct {
		Input    string `json:"input"`
		Expected string `json:"expected"`
	} `json:"normalize"`
	Covers []struct {
		Capability string `json:"capability"`
		Action     string `json:"action"`
		Expected   bool   `json:"expected"`
	} `json:"covers"`
	AnyCovers []struct {
		Capabilities []string `json:"capabilities"`
		Action       string   `json:"action"`
		Expected     bool     `json:"expected"`
	} `json:"any_covers"`
}

func TestContractCapabilityVector(t *testing.T) {
	var v capabilityVector
	loadContract(t, contractDir(t), "vectors/agent-capabilities.json", &v)
	if len(v.Normalize) == 0 || len(v.Covers) == 0 || len(v.AnyCovers) == 0 {
		t.Fatal("the capability vector has no cases")
	}
	for _, c := range v.Normalize {
		if got := NormalizeCapability(c.Input); got != c.Expected {
			t.Errorf("NormalizeCapability(%q) = %q, want %q", c.Input, got, c.Expected)
		}
	}
	for _, c := range v.Covers {
		if got := CapabilityCovers(c.Capability, c.Action); got != c.Expected {
			t.Errorf("CapabilityCovers(%q, %q) = %v, want %v", c.Capability, c.Action, got, c.Expected)
		}
	}
	for _, c := range v.AnyCovers {
		if got := AnyCapabilityCovers(c.Capabilities, c.Action); got != c.Expected {
			t.Errorf("AnyCapabilityCovers(%q, %q) = %v, want %v", c.Capabilities, c.Action, got, c.Expected)
		}
	}
}

func TestCapabilityRulesInline(t *testing.T) {
	if got := NormalizeCapability(" Tool:Search-Web "); got != "tool.search.web" {
		t.Errorf("NormalizeCapability = %q", got)
	}
	if got := NormalizeCapability("Ünits.Read"); got != "Ünits.read" {
		t.Errorf("only ASCII letters are lower-cased, as PHP strtolower: %q", got)
	}
	for _, c := range []struct {
		capability, action string
		want               bool
	}{
		{"tool:search_web", "tool.search_web", true},
		{"invoices.*", "invoices.read.draft", true},
		{"invoices.*", "invoices", false},
		{"*.read", "invoices.read", false},
		{"*", "", false},
	} {
		if got := CapabilityCovers(c.capability, c.action); got != c.want {
			t.Errorf("CapabilityCovers(%q, %q) = %v, want %v", c.capability, c.action, got, c.want)
		}
	}
	if AnyCapabilityCovers(nil, "users.view") {
		t.Error("an empty list covers nothing")
	}
}

func TestAgentHasCapabilityMatchesLikeTheServer(t *testing.T) {
	agent, _ := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			writeJSON(w, 200, map[string]any{"access_token": "t", "expires_in": 3600})
		case strings.HasSuffix(r.URL.Path, "/oauth/userinfo"):
			// The server returns capabilities in their stored form.
			writeJSON(w, 200, map[string]any{
				"sub":          "agent_1",
				"capabilities": []string{"tool.search_web", "invoices.*"},
			})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})
	ctx := context.Background()
	for _, c := range []struct {
		capability string
		want       bool
	}{
		{"tool:search_web", true},  // spelled as registered
		{"tool.search_web", true},  // stored form
		{"invoices.approve", true}, // through invoices.*
		{"Invoices:Read:Draft", true},
		{"invoices", false}, // a wildcard never covers its prefix
		{"tool:send_email", false},
	} {
		got, err := agent.HasCapability(ctx, c.capability)
		if err != nil {
			t.Fatalf("HasCapability(%q): %v", c.capability, err)
		}
		if got != c.want {
			t.Errorf("HasCapability(%q) = %v, want %v", c.capability, got, c.want)
		}
	}
	if err := agent.RequireCapability(ctx, "tool:search_web"); err != nil {
		t.Errorf("RequireCapability on a held capability: %v", err)
	}
	if err := agent.RequireCapability(ctx, "tool:send_email"); !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestAccessTokenClaimsHasCapabilityMatchesLikeTheServer(t *testing.T) {
	claims := &AccessTokenClaims{
		Capabilities: []string{"tool.search_web", "invoices.*"},
		Scope:        "invoices.read",
	}
	if !claims.HasCapability("tool:search_web") || !claims.HasCapability("invoices.approve") {
		t.Error("HasCapability should match the stored form and wildcards")
	}
	if claims.HasCapability("payments.read") {
		t.Error("HasCapability should not invent capabilities")
	}
	if !claims.HasScope("invoices.read") || claims.HasScope("invoices:read") {
		t.Error("scopes stay exact, as in OAuth")
	}
}
