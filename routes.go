package lumoauth

import (
	"net/url"
	"sort"
	"strings"
)

// Central registry of every LumoAuth endpoint this SDK talks to.
//
// Paths use OpenAPI `{param}` placeholders and are asserted against
// `server/openapi.json` by the route-drift test (routes_drift_test.go).
// Add new endpoints HERE — never as inline string literals in a resource.
// This mirrors `sdk-js/packages/shared/src/routes.ts` and
// `sdk-python/src/lumoauth/_routes.py`; the three registries are meant to
// stay in lockstep.
//
// Entries the server serves but the OpenAPI spec does not document are
// listed in the drift test's knownDrift allowlist with an explanation.

// Route is a single endpoint: an HTTP method and a path template.
type Route struct {
	Method string
	Path   string
}

// Route names. Using constants rather than bare strings means a typo is a
// compile error, and every call site is greppable.
const (
	// ── Permissions (RBAC) — bearer-scoped, unprefixed ────────────────
	RoutePermissionsCheck     = "permissions.check"
	RoutePermissionsCheckBulk = "permissions.checkBulk"
	RoutePermissionsCheckAny  = "permissions.checkAny"
	RoutePermissionsCheckAll  = "permissions.checkAll"
	RoutePermissionsList      = "permissions.list"

	// ── Zanzibar (ReBAC) ──────────────────────────────────────────────
	RouteZanzibarCheck  = "zanzibar.check"
	RouteZanzibarExpand = "zanzibar.expand"

	// ── ABAC — org-scoped ─────────────────────────────────────────────
	RouteAbacCheck                = "abac.check"
	RouteAbacCheckBulk            = "abac.checkBulk"
	RouteAbacMyAttributes         = "abac.myAttributes"
	RouteAbacSetUserAttribute     = "abac.setUserAttribute"
	RouteAbacResourceAttributes   = "abac.resourceAttributes"
	RouteAbacSetResourceAttribute = "abac.setResourceAttribute"
	RouteAbacAttributeDefinitions = "abac.attributeDefinitions"

	// ── OAuth 2.1 / OIDC ──────────────────────────────────────────────
	RouteOAuthAuthorize = "oauth.authorize"
	RouteOAuthToken     = "oauth.token"
	RouteOAuthRevoke    = "oauth.revoke"
	RouteOAuthUserInfo  = "oauth.userinfo"
	RouteOAuthLogout    = "oauth.logout"
	RouteOAuthLoginJSON = "oauth.loginJson"

	// ── Web (HTML) routes used by identifier-first sign-in ────────────
	RouteWebCheckEmail = "web.checkEmail"
	RouteWebMagicLink  = "web.magicLink"

	// ── Agents (identity) ─────────────────────────────────────────────
	RouteAgentsAsk      = "agents.ask"
	RouteAgentsMe       = "agents.me"
	RouteAgentsRegister = "agents.register"

	// ── Approvals (push-approval-for-actions) ─────────────────────────
	RouteApprovalsCreate = "approvals.create"
	RouteApprovalsStatus = "approvals.status"

	// ── JIT (just-in-time permissions) ────────────────────────────────
	RouteJitCreateTask    = "jit.createTask"
	RouteJitCompleteTask  = "jit.completeTask"
	RouteJitEvaluateTask  = "jit.evaluateTask"
	RouteJitRequest       = "jit.request"
	RouteJitRequestStatus = "jit.requestStatus"
	RouteJitToken         = "jit.token"
	RouteJitPending       = "jit.pending"

	// ── AAuth (agent auth protocol) ───────────────────────────────────
	RouteAAuthAgentToken     = "aauth.agentToken"
	RouteAAuthAgentAuth      = "aauth.agentAuth"
	RouteAAuthTokenRevoke    = "aauth.tokenRevoke"
	RouteAAuthJWKS           = "aauth.jwks"
	RouteAAuthIssuerMetadata = "aauth.issuerMetadata"
	RouteAAuthAgentMetadata  = "aauth.agentMetadata"

	// ── Root discovery ────────────────────────────────────────────────
	RouteWellKnownAAuthIssuer = "wellknown.aauthIssuer"
)

// orgBase is the org-scoped API prefix shared by most routes.
const orgBase = "/orgs/{orgId}/api/v1"

// Routes maps every route name to its method and path template.
var Routes = map[string]Route{
	// ── Permissions (RBAC) — bearer-scoped, unprefixed ────────────────
	RoutePermissionsCheck:     {"POST", "/api/v1/authz/check"},
	RoutePermissionsCheckBulk: {"POST", "/api/v1/authz/check-bulk"},
	RoutePermissionsCheckAny:  {"POST", "/api/v1/authz/check-any"},
	RoutePermissionsCheckAll:  {"POST", "/api/v1/authz/check-all"},
	RoutePermissionsList:      {"GET", "/api/v1/authz/permissions"},

	// ── Zanzibar (ReBAC) ──────────────────────────────────────────────
	RouteZanzibarCheck:  {"POST", "/api/v1/authz/zanzibar/check"},
	RouteZanzibarExpand: {"POST", "/api/v1/authz/zanzibar/expand"},

	// ── ABAC — org-scoped ─────────────────────────────────────────────
	RouteAbacCheck:              {"POST", orgBase + "/abac/check"},
	RouteAbacCheckBulk:          {"POST", orgBase + "/abac/check-bulk"},
	RouteAbacMyAttributes:       {"GET", orgBase + "/abac/my-attributes"},
	RouteAbacSetUserAttribute:   {"PUT", orgBase + "/abac/users/{userId}/attributes/{attributeSlug}"},
	RouteAbacResourceAttributes: {"GET", orgBase + "/abac/resources/{resourceType}/{resourceId}/attributes"},
	RouteAbacSetResourceAttribute: {"PUT",
		orgBase + "/abac/resources/{resourceType}/{resourceId}/attributes/{attributeSlug}"},
	RouteAbacAttributeDefinitions: {"GET", orgBase + "/abac/attribute-definitions"},

	// ── OAuth 2.1 / OIDC ──────────────────────────────────────────────
	RouteOAuthAuthorize: {"GET", orgBase + "/oauth/authorize"},
	RouteOAuthToken:     {"POST", orgBase + "/oauth/token"},
	RouteOAuthRevoke:    {"POST", orgBase + "/oauth/revoke"},
	RouteOAuthUserInfo:  {"GET", orgBase + "/oauth/userinfo"},
	RouteOAuthLogout:    {"GET", orgBase + "/oauth/logout"},
	// JSON credential login used by identifier-first sign-in.
	RouteOAuthLoginJSON: {"POST", orgBase + "/oauth/login/json"},

	// ── Web (HTML) routes ─────────────────────────────────────────────
	// knownDrift: served by the web firewall, not the JSON API, so they are
	// absent from openapi.json.
	RouteWebCheckEmail: {"POST", "/orgs/{orgId}/check-email"},
	RouteWebMagicLink:  {"POST", "/orgs/{orgId}/magic-link"},

	// ── Agents (identity) ─────────────────────────────────────────────
	RouteAgentsAsk:      {"POST", orgBase + "/agents/ask"},
	RouteAgentsMe:       {"GET", orgBase + "/agents/me"},
	RouteAgentsRegister: {"POST", orgBase + "/agents/register"},

	// ── Approvals ─────────────────────────────────────────────────────
	RouteApprovalsCreate: {"POST", orgBase + "/agents/me/approvals"},
	RouteApprovalsStatus: {"GET", orgBase + "/agents/me/approvals/{token}/status"},

	// ── JIT (just-in-time permissions) ────────────────────────────────
	RouteJitCreateTask:    {"POST", orgBase + "/jit/task"},
	RouteJitCompleteTask:  {"POST", orgBase + "/jit/task/{taskId}/complete"},
	RouteJitEvaluateTask:  {"POST", orgBase + "/jit/task/{taskId}/evaluate"},
	RouteJitRequest:       {"POST", orgBase + "/jit/request"},
	RouteJitRequestStatus: {"GET", orgBase + "/jit/request/{requestId}/status"},
	RouteJitToken:         {"POST", orgBase + "/jit/request/{requestId}/token"},
	RouteJitPending:       {"GET", orgBase + "/jit/pending"},

	// ── AAuth (agent auth protocol) ───────────────────────────────────
	RouteAAuthAgentToken:     {"POST", orgBase + "/aauth/agent/token"},
	RouteAAuthAgentAuth:      {"GET", orgBase + "/aauth/agent/auth"},
	RouteAAuthTokenRevoke:    {"POST", orgBase + "/aauth/token/revoke"},
	RouteAAuthJWKS:           {"GET", orgBase + "/aauth/jwks.json"},
	RouteAAuthIssuerMetadata: {"GET", orgBase + "/.well-known/aauth-issuer"},
	RouteAAuthAgentMetadata:  {"GET", orgBase + "/.well-known/aauth-agent"},

	// ── Root discovery ────────────────────────────────────────────────
	// knownDrift: served at the instance root; the spec only documents the
	// org-scoped variant above.
	RouteWellKnownAAuthIssuer: {"GET", "/.well-known/aauth-issuer"},
}

// RouteNames returns every registered route name, sorted. Useful for
// diagnostics and for the drift test.
func RouteNames() []string {
	names := make([]string, 0, len(Routes))
	for name := range Routes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// BuildPath fills `{param}` placeholders in a path template. Values are
// URL-escaped.
//
//	BuildPath("/orgs/{orgId}/api/v1/abac/check", map[string]string{"orgId": "acme-corp"})
//	// → "/orgs/acme-corp/api/v1/abac/check"
//
// A missing or empty placeholder value is a ConfigError rather than a
// server-side 404: an absent org ID should fail loudly at the call site.
func BuildPath(template string, params map[string]string) (string, error) {
	var b strings.Builder
	rest := template
	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			b.WriteString(rest)
			return b.String(), nil
		}
		close := strings.IndexByte(rest[open:], '}')
		if close < 0 {
			b.WriteString(rest)
			return b.String(), nil
		}
		close += open

		name := rest[open+1 : close]
		value := params[name]
		if value == "" {
			return "", configErrorf(
				"missing route parameter %q for path %s", name, template)
		}
		b.WriteString(rest[:open])
		b.WriteString(url.PathEscape(value))
		rest = rest[close+1:]
	}
}

// RoutePath looks up a route and builds its concrete path in one call.
func RoutePath(name string, params map[string]string) (string, error) {
	route, ok := Routes[name]
	if !ok {
		return "", configErrorf("unknown route %q", name)
	}
	return BuildPath(route.Path, params)
}
