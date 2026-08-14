# lumo-auth-go

Go SDK for [LumoAuth](https://lumoauth.dev) — authorization (RBAC /
Zanzibar / ABAC), agent authentication and capability management, AAuth
cryptographic identity, Just-in-Time (JIT) permissions, and browser
sign-in.

Feature parity with the [JS](../sdk-js) and [Python](../sdk-python) SDKs:
the same namespaces, the same error taxonomy, and byte-compatible RFC 9421
request signing.

## Installation

```bash
go get github.com/lumoauth/lumo-auth-go
```

```go
import lumoauth "github.com/lumoauth/lumo-auth-go"
```

Requires Go 1.22+. The only dependency is `gorilla/sessions`, used by the
web sign-in flow; everything else is standard library.

## Environment variables

| Variable | Description | Default |
| --- | --- | --- |
| `LUMOAUTH_URL` | LumoAuth instance URL | `https://app.lumoauth.dev` |
| `LUMOAUTH_ORG_ID` | Organization slug | *(required for org-scoped calls)* |
| `LUMOAUTH_API_KEY` | API key for `Client` (sent as `X-API-Key`) | — |
| `AGENT_CLIENT_ID` | Agent OAuth client ID | *(required for agents)* |
| `AGENT_CLIENT_SECRET` | Agent OAuth client secret | *(required for agents)* |

Every one can also be passed directly to `New`, `NewAgent`, `NewAAuthClient`,
or `NewWebAuth`.

## Which entry point?

| You are… | Use |
| --- | --- |
| A backend service checking permissions | `lumoauth.New` → `Client` |
| An AI agent acting under its own identity | `lumoauth.NewAgent` → `Agent` |
| An agent with a signing key (AAuth) | `lumoauth.NewAAuthClient` → `AAuthClient` |
| A resource server verifying AAuth tokens | `lumoauth.VerifyAuthToken` |
| A web app signing users in | `lumoauth.NewWebAuth` → `WebAuth` |

---

## Quick start — `Client`

The general-purpose client. Curated namespaces cover the common surface;
everything else is reachable through `Do` or the generated OpenAPI client.

```go
client, err := lumoauth.New(
    lumoauth.WithAPIKey(os.Getenv("LUMOAUTH_API_KEY")),
    lumoauth.WithOrgID("acme-corp"),
)
if err != nil {
    return err
}

// RBAC
allowed, err := client.Permissions.Check(ctx, "document.edit", nil)

// ReBAC (Zanzibar)
allowed, err = client.Zanzibar.IsViewer(ctx, "document:readme", "user:bob")

// ABAC
decision, err := client.Abac.Check(ctx, lumoauth.AbacCheckParams{
    ResourceType: "document",
    Action:       "read",
    ResourceID:   "doc-123",
})
```

### Options

```go
lumoauth.WithBaseURL(url)            // instance URL
lumoauth.WithOrgID(slug)             // organization
lumoauth.WithAPIKey(key)             // X-API-Key credential
lumoauth.WithAccessToken(token)      // fixed bearer token
lumoauth.WithTokenProvider(fn)       // bearer token resolved per request
lumoauth.WithTimeout(30*time.Second) // per-request timeout
lumoauth.WithHTTPClient(httpClient)  // custom transport / instrumentation
lumoauth.WithHeader(name, value)     // extra header on every request
lumoauth.WithUserAgent(ua)
lumoauth.WithSkipCertValidation()    // local development only
```

An API key and a bearer token are never sent together — the server rejects
ambiguous credentials, so a token provider that returns a token wins.

### Namespaces

| Namespace | Covers |
| --- | --- |
| `client.Auth` | OAuth 2.1: authorization URLs, code exchange, refresh, client credentials, token exchange, revocation, UserInfo |
| `client.Permissions` | RBAC: `Check`, `CheckBulk`, `CheckAny`, `CheckAll`, `List` |
| `client.Zanzibar` | ReBAC: `Check`, plus `IsViewer` / `IsEditor` / `IsOwner` / `IsMember` / `IsAdmin` |
| `client.Abac` | Policy evaluation, bulk checks, user and resource attributes |
| `client.Agents` | `Ask`, `Me`, `Register`, `Capabilities`, `Budget` |
| `client.Delegation` | RFC 8693 primitives (see also `DelegationChain`) |
| `client.Jit` | Ephemeral tasks and scoped tokens (see also `JITContext`) |
| `client.Approvals` | Push approvals: `Create`, `Status`, `Wait`, `Require` |
| `client.Mcp` | Audience-scoped tokens for secured MCP servers |

---

## Quick start — `Agent`

An agent owns an OAuth client-credentials token and refreshes it
transparently, so no call needs an explicit login first.

```go
agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{}) // reads env vars
if err != nil {
    return err
}

// Preflight check before an LLM tool call.
allowed, err := agent.IsAllowed(ctx, "document.read", map[string]any{"id": "doc_99"})

// Capability gate at the top of a tool.
if err := agent.RequireCapability(ctx, "tool:search_web"); err != nil {
    return err // matches lumoauth.ErrPermissionDenied
}

// Budget.
if err := agent.CheckBudget(ctx); err != nil {
    return err // matches lumoauth.ErrBudgetExceeded
}
```

`Agent` exposes `Agents`, `Jit`, `Delegation`, `Approvals`, `Mcp`, and
`Permissions` directly; `agent.Client()` reaches the rest.

Concurrent callers share one in-flight token request, and the token is
renewed 60s before it expires.

### Human approval

```go
approval, err := agent.Approvals.Require(ctx, lumoauth.ApprovalParams{
    TaskID:     "wire-2026-05-07-001",
    Reason:     "Wire $4,500 to vendor INV-7741",
    Impact:     lumoauth.ImpactHigh,
    OnBehalfOf: "ada@acme.com",
    Meta:       map[string]any{"amount": 4500, "vendor": "INV-7741"},
}, nil)

switch {
case errors.Is(err, lumoauth.ErrApprovalDenied):
    return fmt.Errorf("a human declined the transfer")
case errors.Is(err, lumoauth.ErrApprovalTimeout):
    return fmt.Errorf("nobody responded in time")
case err != nil:
    return err
}
// approval.Token authorises the side-effecting call.
```

`Require` returns an error for anything except approval. To handle a denial
without an error, call `Create` and `Wait` yourself.

### JIT permissions

A task scopes permissions to one unit of work; closing it revokes every
token issued under it.

```go
jit, err := lumoauth.NewJITContext(agent)
if err != nil {
    return err
}
defer jit.Close(ctx)

if _, err := jit.CreateTask(ctx, lumoauth.CreateTaskParams{Name: "Analyse Q4 report"}); err != nil {
    return err
}

result, err := jit.RequestPermission(ctx, map[string]any{
    "type":       "file_access",
    "actions":    []string{"read"},
    "identifier": "report_q4.pdf",
}, &lumoauth.RequestPermissionOptions{Justification: "The user asked for a Q4 summary"})
if err != nil {
    return err
}
if result.Approved() {
    token, err := jit.Token(ctx, result.RequestID)
    // ... present the token to the resource
}
```

Low-risk requests come back approved. Higher-risk ones enter
human-in-the-loop review, and `RequestPermission` polls until they resolve
(set `NoWait` to poll yourself). A still-pending result means the wait
timed out, not a denial.

`CallWithEscalation` closes the loop automatically: when a resource answers
403 with an `Insufficient-Authorization-Details` header, it requests exactly
the permission that header names, gets a JIT token, and retries once.

```go
resp, err := jit.CallWithEscalation(ctx, http.MethodGet, "https://api.example.com/reports/q4", nil, nil)
```

### Delegation (Chain of Agency)

```go
chain := lumoauth.NewDelegationChain(agent, "https://agent.example.com/callback")

// 1. Send the user to consent.
url, err := chain.ConsentURL("session-1", []string{"read:documents"}, "")

// 2. Your callback receives ?code=…
err = chain.HandleConsentCallback(ctx, "session-1", code)

// 3. Call as "agent acting for user" — the exchange happens on demand.
err = chain.Do(ctx, "session-1", http.MethodGet, "/orgs/acme-corp/api/v1/documents", nil, &out)

// Sub-agents extend the chain (max depth 3).
subToken, err := chain.DelegateToSubAgent(ctx, "session-1", subAgentToken, "read:documents")

// Revoking invalidates the refresh token and every token derived from it.
err = chain.Revoke(ctx, "session-1")
```

Delegated tokens carry an `act` claim recording the chain.
`lumoauth.ParseActorChain(token)` reads it back for audit (without
verifying the signature — never use it for an authorization decision).

### MCP servers

```go
token, err := agent.MCPToken(ctx, "urn:mcp:financial-data")
```

---

## Quick start — web sign-in

The OAuth 2.1 Authorization Code + PKCE flow, with sessions in a signed
cookie.

```go
auth, err := lumoauth.NewWebAuth(lumoauth.WebConfig{
    Organization:  os.Getenv("LUMO_ORG_ID"),
    ClientID:      os.Getenv("LUMO_CLIENT_ID"),
    ClientSecret:  os.Getenv("LUMO_CLIENT_SECRET"),
    SessionSecret: os.Getenv("SESSION_SECRET"), // 32+ random bytes
})
if err != nil {
    return err
}

mux := http.NewServeMux()
mux.Handle("/auth/", auth.Router())               // /auth/login, /auth/callback, /auth/logout
mux.Handle("/", auth.Middleware(auth.RequireAuth(dashboard)))

// In a handler:
user := lumoauth.UserFromContext(req.Context())
fmt.Fprintf(w, "Hi %s", user.Email)
```

`Router()` returns a plain `http.Handler`, so it mounts into chi,
gorilla/mux, or net/http alike.

- `Middleware` attaches the user and their tokens to the request context;
  it does not enforce anything on its own.
- `RequireAuth` answers 401 for anonymous requests.
- `RequireAuthRedirect("/auth/login")` sends them to sign in instead,
  preserving where they were going.
- `ClientForRequest(req)` returns a `Client` authenticated as the
  signed-in user, so authorization checks run under their identity.
- `RefreshSession(w, req)` renews an expired access token from the stored
  refresh token.

Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` by default.
For local development over plain HTTP, set
`CookieSecure: lumoauth.Bool(false)`.

`return_to` is restricted to same-origin paths, so it cannot be used as an
open redirect.

---

## AAuth — cryptographic agent identity

AAuth extends OAuth 2.1 with agent-held keys, proof-of-possession tokens,
and RFC 9421 HTTP message signing.

```go
// One-time: generate a key and register the JWKS with LumoAuth.
keypair, err := lumoauth.GenerateKeypair("")
// keypair.PrivateKeyPEM → your secret manager
// keypair.JWKS          → register, or serve at /.well-known/jwks.json

client, err := lumoauth.NewAAuthClient(lumoauth.AAuthConfig{
    AgentIdentifier: "https://my-agent.example.com",
    PrivateKeyPEM:   os.Getenv("AGENT_PRIVATE_KEY"),
    OrgID:           "acme-corp",
})

result, err := client.RequestAuthToken(ctx, lumoauth.AuthTokenParams{
    ResourceToken: resourceToken,
    Scope:         "read write",
    AgentToken:    agentToken,
})
if result.AuthorizationRequired {
    // Redirect the user to result.AuthorizationURI, then:
    // client.ExchangeCode(ctx, code, redirectURI, agentToken)
}

resp, err := client.SignedRequest(ctx, http.MethodGet,
    "https://api.example.com/v1/data", result.AuthToken, nil)
```

Also available: `ExchangeToken` (multi-hop with an `act` chain), `Refresh`,
`Revoke`, and discovery (`DiscoverIssuer`, `DiscoverAgents`,
`DiscoverResource`, `JWKS`).

Signing output is byte-compatible with the Python and JS SDKs — a shared
conformance vector is asserted in `aauth_test.go`.

### Verifying tokens (resource-server side)

```go
claims, err := lumoauth.VerifyAuthToken(ctx, bearerToken, lumoauth.VerifyOptions{
    Issuer:   "https://app.lumoauth.dev/orgs/acme-corp/api/v1",
    Resource: "https://api.example.com",
})
if err != nil {
    return err
}

// AAuth tokens are proof-of-possession: verifying the JWT alone would let
// a stolen token through.
if err := claims.VerifyProofOfPossession(req, body); err != nil {
    return err
}

if !claims.HasScope("read") {
    return errors.New("insufficient scope")
}
```

`VerifyAuthToken` checks `typ`, `iss`, the JWS signature against the
issuer's JWKS, `exp`, `aud`, and the presence of `cnf.jwk`. HMAC and `none`
algorithms are always rejected, and the algorithm must match the published
key type. For a busy resource server, pass a cached key set:

```go
cache := lumoauth.NewJWKSCache(issuer, time.Hour, nil)
keys, err := cache.Get(ctx)
claims, err := lumoauth.VerifyAuthToken(ctx, token, lumoauth.VerifyOptions{
    Issuer: issuer, Resource: resource, JWKS: keys,
})
```

Revocation is not covered — use the server's introspection endpoint when
you need revocation-aware checks.

---

## Errors

One taxonomy, shared with the JS and Python SDKs. Match errors with the
standard library rather than by type switch:

```go
if errors.Is(err, lumoauth.ErrPermissionDenied) {
    // 403
}

var apiErr *lumoauth.APIError
if errors.As(err, &apiErr) {
    log.Printf("HTTP %d: %v", apiErr.StatusCode, apiErr.Body)
}
```

| Sentinel | Meaning | Code |
| --- | --- | --- |
| `ErrLumoAuth` | Any error from this SDK | — |
| `ErrAPI` | Any non-2xx response | `API_ERROR` |
| `ErrAuthentication` | 401 | `AUTHENTICATION_ERROR` |
| `ErrPermissionDenied` | 403 | `PERMISSION_DENIED` |
| `ErrNotFound` | 404 | `NOT_FOUND` |
| `ErrRateLimited` | 429 (see `APIError.RetryAfter`) | `RATE_LIMITED` |
| `ErrValidation` | Bad input or unusable response | `VALIDATION_ERROR` |
| `ErrConfig` | Missing or invalid configuration | `CONFIG_ERROR` |
| `ErrNetwork` | Transport failure, no HTTP response | `NETWORK_ERROR` |
| `ErrApprovalDenied` | A human declined | `APPROVAL_DENIED` |
| `ErrApprovalTimeout` | An approval expired | `APPROVAL_TIMEOUT` |
| `ErrBudgetExceeded` | The agent's budget is spent | `BUDGET_EXCEEDED` |

Helpers: `AsAPIError(err)`, `StatusCode(err)`, `ErrorCode(err)`.

Errors wrap their causes, so `errors.Is(err, context.DeadlineExceeded)`
works through a `NetworkError`.

---

## Escape hatch — the full REST API

The curated namespaces cover what applications reach for. For the rest
(admin endpoints, SCIM, audit logs), either call it directly:

```go
path, err := client.OrgPath("/admin/users")

var page struct {
    Data []map[string]any `json:"data"`
}
err = client.Do(ctx, http.MethodGet, path, nil, &page)
```

…or hand the configuration to the generated OpenAPI client. Go cannot
import a package lazily, so this SDK does not depend on the generated
client — it configures one for you:

```go
import lumoauthclient "github.com/lumoauth/api-clients/go"

apiCfg, err := client.APIConfig(ctx)

cfg := lumoauthclient.NewConfiguration()
cfg.Servers = lumoauthclient.ServerConfigurations{{URL: apiCfg.BaseURL}}
cfg.DefaultHeader = apiCfg.DefaultHeader
cfg.HTTPClient = apiCfg.HTTPClient

api := lumoauthclient.NewAPIClient(cfg)
```

`APIConfig` sets exactly one credential header, matching the credential
the client was built with.

---

## Route registry

Every endpoint this SDK calls lives in `routes.go` — never as an inline
string in a resource. A drift test loads `server/openapi.json` and asserts
that each `(method, path)` still exists, so a route renamed server-side
fails the build instead of 404ing in production. Endpoints the spec does
not document are listed in `knownDrift` with a reason.

The same check runs in the JS and Python SDKs against the same spec, and
`TestRouteRegistryMatchesOtherSDKs` flags any endpoint the JS SDK calls
that this one is missing.

## Development

```bash
go test ./...          # unit tests + drift checks
go test -race ./...    # the concurrency paths (token refresh, delegation)
go vet ./...
gofmt -l .
```

## License

MIT — see [LICENSE](./LICENSE).
