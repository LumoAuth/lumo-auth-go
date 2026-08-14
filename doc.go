/*
Package lumoauth is the official Go SDK for LumoAuth — authentication and
authorization for applications and AI agents.

It exposes four entry points, one per kind of caller:

  - [Client] — the general-purpose API client. Permission checks (RBAC,
    ReBAC, ABAC), agent identity, delegation, JIT permissions, approvals,
    and MCP tokens, credentialed with an API key or a bearer token.

  - [Agent] — for AI agents acting under their own identity. Wraps Client
    with an OAuth 2.0 client-credentials token it refreshes transparently,
    plus preflight authorization (Ask), capabilities, and budgets.

  - [AAuthClient] — for the AAuth protocol: cryptographic agent identity,
    proof-of-possession tokens, and RFC 9421 HTTP message signing.
    [VerifyAuthToken] is the resource-server side of the same protocol.

  - [WebAuth] — browser sign-in. Wires the OAuth 2.1 Authorization Code +
    PKCE flow into any net/http-compatible router, with sessions in a
    signed cookie.

# Client

	client, err := lumoauth.New(
	    lumoauth.WithAPIKey(os.Getenv("LUMOAUTH_API_KEY")),
	    lumoauth.WithOrgID("acme-corp"),
	)
	if err != nil {
	    return err
	}

	ok, err := client.Permissions.Check(ctx, "document.edit", nil)
	ok, err = client.Zanzibar.IsViewer(ctx, "document:readme", "user:bob")
	decision, err := client.Abac.Check(ctx, lumoauth.AbacCheckParams{
	    ResourceType: "document",
	    Action:       "read",
	    ResourceID:   "doc-123",
	})

Resource namespaces cover the surface an application reaches for. For the
rest of the REST API — admin endpoints, SCIM, audit logs — use
[Client.Do], or hand [Client.APIConfig] to the generated OpenAPI client.

# Agent

	agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{}) // reads env vars
	if err != nil {
	    return err
	}

	if err := agent.RequireCapability(ctx, "tool:search_web"); err != nil {
	    return err
	}
	allowed, err := agent.IsAllowed(ctx, "document.read", map[string]any{"id": "doc_99"})

Before an irreversible action, ask a human:

	approval, err := agent.Approvals.Require(ctx, lumoauth.ApprovalParams{
	    TaskID:     "wire-2026-05-07-001",
	    Reason:     "Wire $4,500 to vendor INV-7741",
	    Impact:     lumoauth.ImpactHigh,
	    OnBehalfOf: "ada@acme.com",
	}, nil)
	if err != nil {
	    return err // denied, expired, or the wait timed out
	}

For narrowly scoped, short-lived permissions, open a [JITContext]; for
acting on behalf of a user, use a [DelegationChain].

# Web sign-in

	auth, err := lumoauth.NewWebAuth(lumoauth.WebConfig{
	    Organization:  os.Getenv("LUMO_ORG_ID"),
	    ClientID:      os.Getenv("LUMO_CLIENT_ID"),
	    ClientSecret:  os.Getenv("LUMO_CLIENT_SECRET"),
	    SessionSecret: os.Getenv("SESSION_SECRET"),
	})
	if err != nil {
	    return err
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", auth.Router())
	mux.Handle("/", auth.Middleware(auth.RequireAuth(dashboard)))

	// In a handler:
	user := lumoauth.UserFromContext(req.Context())

# Errors

Every error this package returns is matched with the standard library
rather than by type switch:

	if errors.Is(err, lumoauth.ErrPermissionDenied) {
	    // 403
	}

	var apiErr *lumoauth.APIError
	if errors.As(err, &apiErr) {
	    log.Printf("HTTP %d: %v", apiErr.StatusCode, apiErr.Body)
	}

The sentinels are [ErrAuthentication], [ErrPermissionDenied],
[ErrNotFound], [ErrRateLimited], [ErrValidation], [ErrConfig],
[ErrNetwork], [ErrApprovalDenied], [ErrApprovalTimeout], and
[ErrBudgetExceeded]; [ErrAPI] matches any non-2xx response and
[ErrLumoAuth] matches all of them. The names and codes are shared with the
JS and Python SDKs.

# Configuration

Options fall back to the environment:

	LUMOAUTH_URL           instance URL      (default https://app.lumoauth.dev)
	LUMOAUTH_ORG_ID        organization slug
	LUMOAUTH_API_KEY       tenant API key    (sent as X-API-Key)
	AGENT_CLIENT_ID        agent OAuth client       (Agent only)
	AGENT_CLIENT_SECRET    agent OAuth secret       (Agent only)

Every endpoint this SDK calls is registered in [Routes]; a drift test
checks the registry against the server's OpenAPI spec, so a renamed route
fails the build rather than 404ing in production.
*/
package lumoauth
