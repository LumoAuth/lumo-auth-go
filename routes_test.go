package lumoauth

import (
	"errors"
	"strings"
	"testing"
)

func TestBuildPath(t *testing.T) {
	cases := []struct {
		name     string
		template string
		params   map[string]string
		want     string
	}{
		{
			"single placeholder",
			"/orgs/{orgId}/api/v1/abac/check",
			map[string]string{"orgId": "acme-corp"},
			"/orgs/acme-corp/api/v1/abac/check",
		},
		{
			"several placeholders",
			"/orgs/{orgId}/api/v1/abac/users/{userId}/attributes/{attributeSlug}",
			map[string]string{"orgId": "acme", "userId": "42", "attributeSlug": "clearance"},
			"/orgs/acme/api/v1/abac/users/42/attributes/clearance",
		},
		{
			"no placeholders",
			"/api/v1/authz/check",
			nil,
			"/api/v1/authz/check",
		},
		{
			"escapes path separators in values",
			"/orgs/{orgId}/api/v1/agents/me/approvals/{token}/status",
			map[string]string{"orgId": "acme", "token": "a/b?c"},
			"/orgs/acme/api/v1/agents/me/approvals/a%2Fb%3Fc/status",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildPath(tc.template, tc.params)
			if err != nil {
				t.Fatalf("BuildPath: %v", err)
			}
			if got != tc.want {
				t.Errorf("BuildPath = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildPathRejectsMissingParameters(t *testing.T) {
	// A missing org ID must fail at the call site, not become a 404.
	_, err := BuildPath("/orgs/{orgId}/api/v1/abac/check", nil)
	if err == nil {
		t.Fatal("expected an error for a missing parameter")
	}
	if !errors.Is(err, ErrConfig) {
		t.Errorf("a missing route parameter should be a config error, got %v", err)
	}
	if !strings.Contains(err.Error(), "orgId") {
		t.Errorf("the error should name the missing parameter: %v", err)
	}

	if _, err := BuildPath("/orgs/{orgId}/x", map[string]string{"orgId": ""}); err == nil {
		t.Error("an empty parameter value should be rejected too")
	}
}

func TestRoutePath(t *testing.T) {
	got, err := RoutePath(RouteAgentsAsk, map[string]string{"orgId": "acme-corp"})
	if err != nil {
		t.Fatalf("RoutePath: %v", err)
	}
	if got != "/orgs/acme-corp/api/v1/agents/ask" {
		t.Errorf("RoutePath = %q", got)
	}

	if _, err := RoutePath("no.such.route", nil); err == nil {
		t.Error("expected an error for an unknown route name")
	}
}

func TestRouteRegistryIsWellFormed(t *testing.T) {
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
	}

	for name, route := range Routes {
		if !validMethods[route.Method] {
			t.Errorf("route %q has an unexpected method %q", name, route.Method)
		}
		if !strings.HasPrefix(route.Path, "/") {
			t.Errorf("route %q path must start with a slash: %q", name, route.Path)
		}
		if strings.Contains(route.Path, "{orgId}") &&
			!strings.HasPrefix(route.Path, "/orgs/{orgId}") {
			t.Errorf("route %q embeds {orgId} somewhere unexpected: %q", name, route.Path)
		}
		// Balanced placeholder braces.
		if strings.Count(route.Path, "{") != strings.Count(route.Path, "}") {
			t.Errorf("route %q has unbalanced braces: %q", name, route.Path)
		}
	}
}

func TestRouteNamesAreSorted(t *testing.T) {
	names := RouteNames()
	if len(names) != len(Routes) {
		t.Fatalf("RouteNames returned %d names for %d routes", len(names), len(Routes))
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("RouteNames is not sorted: %q before %q", names[i-1], names[i])
		}
	}
}

func TestRouteConstantsMatchRegistryKeys(t *testing.T) {
	// Every exported Route* constant must resolve, so a typo in a
	// constant cannot silently produce an unknown-route error at runtime.
	constants := []string{
		RoutePermissionsCheck, RoutePermissionsCheckBulk, RoutePermissionsCheckAny,
		RoutePermissionsCheckAll, RoutePermissionsList,
		RouteZanzibarCheck, RouteZanzibarExpand,
		RouteAbacCheck, RouteAbacCheckBulk, RouteAbacMyAttributes,
		RouteAbacSetUserAttribute, RouteAbacResourceAttributes,
		RouteAbacSetResourceAttribute, RouteAbacAttributeDefinitions,
		RouteOAuthAuthorize, RouteOAuthToken, RouteOAuthRevoke, RouteOAuthUserInfo,
		RouteOAuthLogout, RouteOAuthLoginJSON,
		RouteWebCheckEmail, RouteWebMagicLink,
		RouteAgentsAsk, RouteAgentsMe, RouteAgentsRegister,
		RouteApprovalsCreate, RouteApprovalsStatus,
		RouteJitCreateTask, RouteJitCompleteTask, RouteJitEvaluateTask,
		RouteJitRequest, RouteJitRequestStatus, RouteJitToken, RouteJitPending,
		RouteAAuthAgentToken, RouteAAuthAgentAuth, RouteAAuthTokenRevoke,
		RouteAAuthJWKS, RouteAAuthIssuerMetadata, RouteAAuthAgentMetadata,
		RouteWellKnownAAuthIssuer,
	}

	for _, name := range constants {
		if _, ok := Routes[name]; !ok {
			t.Errorf("route constant %q is not in the registry", name)
		}
	}
	if len(constants) != len(Routes) {
		t.Errorf("%d route constants for %d registry entries — one side is missing an endpoint",
			len(constants), len(Routes))
	}
}
