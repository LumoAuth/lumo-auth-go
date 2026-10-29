# lumo-auth-go

The Go SDK for [LumoAuth](https://lumoauth.dev). Use it to check what a user or an AI agent
is allowed to do, to sign users in to a `net/http` app, and to give AI agents their own
identity. It covers the following:

- Authorization checks: roles and permissions (RBAC), relationships (Zanzibar) and
  attribute policies (ABAC).
- Sign-in for web apps with OAuth 2.1 and PKCE.
- AI agents: agent credentials, human approvals, Just-in-Time (JIT) permissions, delegation
  and MCP tokens.
- AAuth, the protocol for cryptographic agent identity, with RFC 9421 request signing.
- Verification of AAuth tokens on your own resource server.

The SDK has the same namespaces and the same error codes as the [JS](../sdk-js) and
[Python](../sdk-python) SDKs. Its RFC 9421 signatures match theirs byte for byte.

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Core concepts](#core-concepts)
- [Configuration](#configuration)
- [Guides](#guides)
  - [Check permissions](#check-permissions)
  - [Check relationships (Zanzibar)](#check-relationships-zanzibar)
  - [Check attribute policies (ABAC)](#check-attribute-policies-abac)
  - [Sign users in](#sign-users-in)
  - [Protect `net/http` routes](#protect-nethttp-routes)
  - [OAuth flows without the web helper](#oauth-flows-without-the-web-helper)
  - [Run an AI agent](#run-an-ai-agent)
  - [Ask a human to approve an action](#ask-a-human-to-approve-an-action)
  - [Just-in-Time permissions](#just-in-time-permissions)
  - [Act on behalf of a user (delegation)](#act-on-behalf-of-a-user-delegation)
  - [Get a token for an MCP server](#get-a-token-for-an-mcp-server)
  - [Bind tokens to a key with DPoP](#bind-tokens-to-a-key-with-dpop)
  - [Verify LumoAuth tokens in your MCP server](#verify-lumoauth-tokens-in-your-mcp-server)
  - [Check access to an MCP tool](#check-access-to-an-mcp-tool)
  - [AAuth: cryptographic agent identity](#aauth-cryptographic-agent-identity)
  - [Verify AAuth tokens on a resource server](#verify-aauth-tokens-on-a-resource-server)
  - [Call any other endpoint](#call-any-other-endpoint)
- [Errors](#errors)
- [API reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Versioning and compatibility](#versioning-and-compatibility)
- [Development](#development)
- [Licence](#licence)

## Requirements

- Go 1.22 or later.
- One dependency: `github.com/gorilla/sessions`, for the cookie session of the web sign-in
  helper. Everything else uses the standard library.
- A LumoAuth organization. The hosted instances are `https://app.lumoauth.dev` (US) and
  `https://eu.app.lumoauth.dev` (EU).

## Install

```bash
go get github.com/lumoauth/lumo-auth-go
```

```go
import lumoauth "github.com/lumoauth/lumo-auth-go"
```

## Quick start

### Check a permission from a backend service

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    lumoauth "github.com/lumoauth/lumo-auth-go"
)

func main() {
    ctx := context.Background()

    client, err := lumoauth.New(
        lumoauth.WithAPIKey(os.Getenv("LUMOAUTH_API_KEY")),
        lumoauth.WithOrgID("acme-corp"),
    )
    if err != nil {
        log.Fatal(err)
    }

    allowed, err := client.Permissions.Check(ctx, "document.edit", nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("may edit documents:", allowed)
}
```

With an organization API key, the check runs for the user who created the key. To check a
different user, see [Check permissions](#check-permissions).

### Run an AI agent

```go
agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{}) // reads the environment variables
if err != nil {
    log.Fatal(err)
}

allowed, err := agent.IsAllowed(ctx, "document.read", map[string]any{"id": "doc_99"})
if err != nil {
    log.Fatal(err)
}
fmt.Println("may read doc_99:", allowed)
```

`NewAgent` reads `LUMOAUTH_URL`, `LUMOAUTH_ORG_ID`, `AGENT_CLIENT_ID` and
`AGENT_CLIENT_SECRET`. The agent gets its token on the first call and renews it before it
expires.

## Core concepts

### Organization and base URL

Every LumoAuth customer has an **organization**. Its slug (for example `acme-corp`) appears in
most API paths as `/orgs/{orgId}/api/v1/...`. Set it with `WithOrgID` or `LUMOAUTH_ORG_ID`.
Calls that need an organization return a `ConfigError` when it is missing.

The **base URL** is the LumoAuth instance. It defaults to `https://app.lumoauth.dev`. Set
`https://eu.app.lumoauth.dev` when your organization is in the EU region.

### Credentials

The SDK sends exactly one credential with each request. Which calls work depends on the kind
of credential that you use.

| Credential | How you set it | Sent as | What it may call |
| --- | --- | --- | --- |
| Organization API key (`lmk_…`) | `WithAPIKey` or `LUMOAUTH_API_KEY` | `X-API-Key` header | The admin API, client registration, and the permission checks (`Permissions.Check*`, `Zanzibar.Check` and `Expand`). Nothing else. |
| User access token | `WithAccessToken`, `WithTokenProvider`, or `WebAuth.ClientForRequest` | `Authorization: Bearer` | Calls about the signed-in user. Some calls need a scope; see [Scopes](#scopes). |
| Agent credential | `NewAgent` (client credentials), or an `agk_…` key passed as a bearer token | `Authorization: Bearer` | The agent, approval, JIT and MCP calls, and the permission checks. The agent's capabilities determine what it may do. |

When both a token and an API key are configured, the token wins and the API key is not sent.
The server rejects requests that carry both.

### Scopes

A user access token carries **scopes**. These are the permissions that the user granted to
your app when they signed in. Most calls need no special scope. A few need one:

| Call | Scope that a user access token needs |
| --- | --- |
| `Permissions.List`, `Permissions.ListSlugs` | `authz:read` |
| ABAC checks and attribute reads (`Abac.Check`, `CheckBulk`, `IsAllowed`, `MyAttributes`, `ResourceAttributes`, `AttributeDefinitions`) | `abac:read` |
| ABAC attribute writes (`Abac.SetUserAttribute`, `SetResourceAttribute`) | `abac:write` |
| `Jit.Pending` (the list for human review) | `jit:approve` |
| `Agents.Register` | `admin:agents:write`. Organization API keys cannot register agents. |
| Permission checks, `Zanzibar.Check`, `Agents.Ask`, `Agents.Me`, `Auth.UserInfo` | none |

The `admin` scope satisfies every row. A check about another user or agent (`CheckOptions.UserID`
or `AgentID`, or a Zanzibar subject other than yourself) needs `authz:check`, and so does `Zanzibar.Expand`. Agent credentials do not use these
scopes. The agent's capabilities apply instead.

Request a scope when the user signs in, for example by adding it to `WebConfig.Scope`. When
the token lacks a scope, the server answers 403. The error lists the missing scopes in
`APIError.RequiredScopes`; see [Errors](#errors).

## Configuration

### `lumoauth.New` options

| Option | What it sets | Default |
| --- | --- | --- |
| `WithBaseURL(url)` | The LumoAuth instance | `$LUMOAUTH_URL`, then `https://app.lumoauth.dev` |
| `WithOrgID(slug)` | The organization slug | `$LUMOAUTH_ORG_ID` |
| `WithAPIKey(key)` | An organization API key, sent as `X-API-Key` | `$LUMOAUTH_API_KEY` |
| `WithAccessToken(token)` | A fixed bearer token | none |
| `WithTokenProvider(fn)` | A function that returns a bearer token for each request; use it for tokens that you refresh | none |
| `WithTimeout(d)` | The timeout of each request | 30 seconds |
| `WithHTTPClient(c)` | Your own `*http.Client`, for proxies or instrumentation | a new client |
| `WithHeader(name, value)` | An extra header on every request | none |
| `WithUserAgent(ua)` | The `User-Agent` header | `lumoauth-go/<version>` |
| `WithSkipCertValidation()` | Turns off TLS verification. Use it for local development only. | off |
| `WithDPoP(signer)` | Binds every token the client obtains to a DPoP key, and presents bound tokens with the `DPoP` scheme. See [DPoP](#bind-tokens-to-a-key-with-dpop). | off |

`New` returns a `ConfigError` when no credential is configured. It needs an API key, an
access token or a token provider.

### Environment variables

| Variable | Read by | Meaning |
| --- | --- | --- |
| `LUMOAUTH_URL` | every constructor | The LumoAuth instance |
| `LUMOAUTH_ORG_ID` | every constructor | The organization slug |
| `LUMOAUTH_API_KEY` | `New` | The organization API key |
| `AGENT_CLIENT_ID` | `NewAgent` | The agent's OAuth client ID |
| `AGENT_CLIENT_SECRET` | `NewAgent` | The agent's OAuth client secret |

A value that you pass in code always wins over the environment variable.

### `AgentConfig`

| Field | Meaning | Default |
| --- | --- | --- |
| `BaseURL`, `OrgID` | As above | the environment variables |
| `ClientID`, `ClientSecret` | The agent's OAuth client | `$AGENT_CLIENT_ID`, `$AGENT_CLIENT_SECRET` |
| `Scopes` | Scopes to request when the agent authenticates | the defaults that are registered for the agent |
| `RedirectURI` | The callback URL of the consent flow for delegation | none |
| `Timeout`, `HTTPClient`, `SkipCertValidation` | As for `New` | 30 seconds, a new client, off |
| `DPoP` | A `*DPoPSigner`; the agent's tokens are then bound to its key | none |

`WebConfig` and `AAuthConfig` are described in [Sign users in](#sign-users-in) and
[AAuth](#aauth-cryptographic-agent-identity).

## Guides

In all of the examples, `ctx` is a `context.Context` and `client` is a `*lumoauth.Client` from
`lumoauth.New`.

### Check permissions

A permission is a slug such as `document.edit`. The user gets it through a role.

```go
// One permission.
allowed, err := client.Permissions.Check(ctx, "document.edit", nil)

// The full answer, including the user ID that the server checked.
result, err := client.Permissions.CheckDetailed(ctx, "document.edit", nil)

// Several permissions in one request. The result maps each slug to true or false.
bulk, err := client.Permissions.CheckBulk(ctx, []string{"document.read", "document.edit"}, nil)
fmt.Println(bulk.Results["document.edit"])

// True when the user has at least one of the permissions, or all of them.
anyOf, err := client.Permissions.CheckAny(ctx, []string{"billing.view", "billing.manage"}, nil)
allOf, err := client.Permissions.CheckAll(ctx, []string{"report.read", "report.export"}, nil)
```

`CheckOptions` adds optional values to any check:

- `Context` passes attributes to ABAC policies that apply to the same decision.
- `UserID` asks about another user instead of the caller. It must be the user's LumoAuth ID,
  which is a UUID. `AgentID` does the same for an agent (its `agt_…` ID). Set at most one of them.

```go
allowed, err := client.Permissions.Check(ctx, "document.edit", &lumoauth.CheckOptions{
    UserID: "01a176cb-4095-7bb1-b3fe-7a9b8943e0cf",
})
```

The SDK sends the ID as the request's `subject`. Asking about someone other than yourself needs
the `authz:check` scope or the `authz.check` permission. An organization API key can hold the
`authz:check` scope. Without that right, the server answers 403 with the code
`INSUFFICIENT_PERMISSIONS`. An ID that is not in your organization gets 404 `SUBJECT_NOT_FOUND`.

To list all of the permissions that the caller has, use `List` or `ListSlugs`. These calls
need a user access token with the `authz:read` scope. An organization API key cannot hold that
scope, so the server rejects the call with 403.

```go
slugs, err := client.Permissions.ListSlugs(ctx) // []string{"document.read", ...}
```

### Check relationships (Zanzibar)

Zanzibar checks answer questions such as "is Bob a viewer of this document?". Objects are
written `type:id` and subjects are written `user:id`.

```go
ok, err := client.Zanzibar.Check(ctx, "document:readme", "viewer", "user:bob")

// Helpers for the common relations.
ok, err = client.Zanzibar.IsViewer(ctx, "document:readme", "user:bob")
ok, err = client.Zanzibar.IsEditor(ctx, "document:readme", "user:bob")
ok, err = client.Zanzibar.IsOwner(ctx, "document:readme", "user:bob")
ok, err = client.Zanzibar.IsMember(ctx, "team:design", "user:bob")
ok, err = client.Zanzibar.IsAdmin(ctx, "workspace:acme", "user:bob")

// Expand returns the tree of everyone who holds a relation.
tree, err := client.Zanzibar.Expand(ctx, "document:readme", "viewer")
```

`Expand` returns a `ZanzibarUsersetNode`. Each node has a `Type` (`union`, `intersection` or
`leaf`), its `Children`, and for leaves the `Subjects`. Expanding needs the right to ask about
other subjects: the `authz.check` permission or the `authz:check` scope.

### Check attribute policies (ABAC)

ABAC policies grant or deny access based on attributes of the user, the resource and the
request. ABAC calls are made per organization, so the client needs an org ID. They need a user access token
with `abac:read` (checks and reads) or `abac:write` (writes). Organization API keys are not
accepted on these routes.

```go
client, err := lumoauth.New(
    lumoauth.WithAccessToken(userAccessToken), // a user token with abac:read
    lumoauth.WithOrgID("acme-corp"),
)
if err != nil {
    return err
}

decision, err := client.Abac.Check(ctx, lumoauth.AbacCheckParams{
    ResourceType: "document",
    Action:       "read",
    ResourceID:   "doc-123",
    Context: map[string]any{
        "pep": map[string]any{"ip": endUserIP}, // a value that your gateway forwards
    },
})
if err != nil {
    return err
}
fmt.Println(decision.Allowed, decision.Reason, decision.MatchedPolicies)
```

The SDK sends `Context` as the request's `environment` object, which the policy engine reads.
LumoAuth sets the keys `ip`, `userAgent`, `requestMethod` and `requestPath` from the request
that it received. If you send values under those names, the server moves them under `pep`.
To use an end user's IP address in a policy, send it as `pep.ip` and write the policy against
`pep.ip`.

Other ABAC calls:

```go
// Up to 100 checks in one request (AbacMaxBulkRequests). Results come back in request order.
// The server applies one environment to every check, so give every entry the same Context (or none).
env := map[string]any{"pep": map[string]any{"ip": endUserIP}}
results, err := client.Abac.CheckBulk(ctx, []lumoauth.AbacCheckParams{
    {ResourceType: "document", Action: "read", ResourceID: "doc-1", Context: env},
    {ResourceType: "document", Action: "delete", ResourceID: "doc-2", Context: env},
})
// Each result has Index, ResourceType, Action, ResourceID, Allowed and Reason.
// Error is set when the server could not evaluate that entry.

// A plain yes or no.
ok, err := client.Abac.IsAllowed(ctx, lumoauth.AbacCheckParams{ResourceType: "document", Action: "read"})

// Read attributes.
mine, err := client.Abac.MyAttributes(ctx)
attrs, err := client.Abac.ResourceAttributes(ctx, "document", "doc-123")
defs, err := client.Abac.AttributeDefinitions(ctx, lumoauth.AttributeTypeUser) // or "" for all types

// Write attributes (needs abac:write and the abac.manage permission).
err = client.Abac.SetUserAttribute(ctx, "user_42", "department", "finance")
err = client.Abac.SetResourceAttribute(ctx, "document", "doc-123", "classification", "internal")
```

### Sign users in

`WebAuth` runs the OAuth 2.1 authorization code flow with PKCE. It stores the session in a
signed cookie.

```go
auth, err := lumoauth.NewWebAuth(lumoauth.WebConfig{
    Organization:  os.Getenv("LUMOAUTH_ORG_ID"),
    ClientID:      os.Getenv("LUMO_CLIENT_ID"),
    ClientSecret:  os.Getenv("LUMO_CLIENT_SECRET"),
    SessionSecret: os.Getenv("SESSION_SECRET"), // at least 32 random bytes
})
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("/auth/", auth.Router()) // /auth/login, /auth/callback, /auth/logout
mux.Handle("/", auth.Middleware(auth.RequireAuth(http.HandlerFunc(dashboard))))
log.Fatal(http.ListenAndServe(":8080", mux))
```

```go
func dashboard(w http.ResponseWriter, req *http.Request) {
    user := lumoauth.UserFromContext(req.Context())
    fmt.Fprintf(w, "Hi %s", user.Email)
}
```

Register `https://<your app>/auth/callback` as a redirect URI on the OAuth client in the
LumoAuth portal.

The router handles three paths:

- `/auth/login` sends the user to LumoAuth. Add `?return_to=/some/path` to come back to a page
  after sign-in. Only paths on your own site are accepted, so the parameter cannot be used as an
  open redirect.
- `/auth/callback` exchanges the code for tokens and stores the session.
- `/auth/logout` revokes the refresh token, clears the session and redirects to
  `PostLogoutRedirect`.

`Router()` returns a plain `http.Handler`, so you can mount it in chi, gorilla/mux or
`net/http`. To mount the handlers one by one, use `LoginHandler`, `CallbackHandler` and
`LogoutHandler`.

`WebConfig` fields:

| Field | Meaning | Default |
| --- | --- | --- |
| `BaseURL` | The LumoAuth instance | `$LUMOAUTH_URL`, then `https://app.lumoauth.dev` |
| `Organization` | The organization slug that owns the OAuth client | `$LUMOAUTH_ORG_ID` |
| `ClientID` | The OAuth client of your app (required) | none |
| `ClientSecret` | Required for confidential clients. Public clients use PKCE alone. | none |
| `SessionSecret` | The key of the cookie store (required). Keep it the same across restarts, or every session ends. | none |
| `CallbackPath` | The callback path. It must match a registered redirect URI. | `/auth/callback` |
| `Scope` | The scopes to request, separated by spaces | `openid profile email` |
| `PostLoginRedirect`, `PostLogoutRedirect` | The pages that users go to after sign-in and sign-out | `/` |
| `CookieName` | The name of the session cookie | `lumo_session` |
| `CookieSecure` | The `Secure` flag of the cookie. `nil` means true. | true |
| `SessionMaxAge` | The longest lifetime of the session cookie | 30 days |
| `HTTPClient` | The client for the token and UserInfo calls | a client with a 10-second timeout |
| `SkipCertValidation` | Turns off TLS verification. Use it for local development only. | off |

Add scopes to `Scope` for the calls that your app makes as the user. Add `authz:read` when the
app lists the user's permissions or reads roles from `Agents.Me`. Add `abac:read` when it runs
ABAC checks as the user. For example: `Scope: "openid profile email authz:read"`.

Session cookies are `HttpOnly`, `SameSite=Lax` and `Secure`. For local development over plain
HTTP, set `CookieSecure: lumoauth.Bool(false)`.

### Protect `net/http` routes

`WebAuth` gives you middleware and helpers for handlers:

| Helper | What it does |
| --- | --- |
| `auth.Middleware(next)` | Reads the session and puts the user and tokens on the request context. It does not block anyone. |
| `auth.RequireAuth(next)` | Answers 401 when nobody is signed in. Wrap it inside `Middleware`. |
| `auth.RequireAuthRedirect("/auth/login")` | Sends anonymous users to sign in and brings them back afterwards. |
| `lumoauth.UserFromContext(ctx)` | Returns the signed-in `*User`, or nil. Use it inside `Middleware`. |
| `lumoauth.TokensFromContext(ctx)` | Returns the session's `*SessionTokens`, or nil. |
| `auth.User(req)`, `auth.Tokens(req)` | Read the session directly, without `Middleware`. |
| `auth.RefreshSession(w, req)` | Renews an expired access token with the stored refresh token. It reports whether a refresh happened. |
| `auth.ClientForRequest(req)` | Returns a `*Client` that is authenticated as the signed-in user. |

To check a permission for the signed-in user, run the check with their own token:

```go
func editDocument(w http.ResponseWriter, req *http.Request) {
    client, err := auth.ClientForRequest(req)
    if err != nil {
        http.Error(w, "sign in first", http.StatusUnauthorized)
        return
    }
    ok, err := client.Permissions.Check(req.Context(), "document.edit", nil)
    if err != nil || !ok {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    // ...
}
```

### OAuth flows without the web helper

`client.Auth` exposes the OAuth endpoints directly. Use it when you manage sessions yourself.
Calls to the token and revocation endpoints authenticate with the client ID and secret in the
form body. They never send the client's API key or bearer token.

```go
// 1. Send the user to LumoAuth.
url, err := client.Auth.AuthorizationURL(lumoauth.AuthorizationURLParams{
    ClientID:      clientID,
    RedirectURI:   "https://app.example.com/callback",
    State:         state,
    CodeChallenge: challenge, // PKCE; S256 is used by default
})

// 2. Exchange the code from the callback.
tokens, err := client.Auth.ExchangeCode(ctx, lumoauth.ExchangeCodeParams{
    Code: code, RedirectURI: "https://app.example.com/callback",
    ClientID: clientID, ClientSecret: clientSecret, CodeVerifier: verifier,
})

// 3. Refresh, read the profile, revoke.
fresh, err := client.Auth.RefreshToken(ctx, lumoauth.RefreshTokenParams{
    RefreshToken: tokens.RefreshToken, ClientID: clientID, ClientSecret: clientSecret,
})
profile, err := client.Auth.UserInfo(ctx, fresh.AccessToken)
err = client.Auth.Revoke(ctx, lumoauth.RevokeParams{
    Token: fresh.RefreshToken, TokenTypeHint: "refresh_token",
    ClientID: clientID, ClientSecret: clientSecret,
})

// Machine-to-machine: the client credentials grant.
m2m, err := client.Auth.ClientCredentials(ctx, clientID, clientSecret, "read:reports")
```

Set `AccessType: "offline"` on `AuthorizationURLParams` to ask for a refresh token.

### Run an AI agent

An `Agent` authenticates with the OAuth client credentials grant. It caches the token, renews
it 60 seconds before it expires, and shares one token request between concurrent callers.

```go
agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{
    OrgID:        "acme-corp",
    ClientID:     os.Getenv("AGENT_CLIENT_ID"),
    ClientSecret: os.Getenv("AGENT_CLIENT_SECRET"),
})
if err != nil {
    log.Fatal(err)
}

// Optional: authenticate now, so that a bad secret fails at startup.
if _, err := agent.Authenticate(ctx); err != nil {
    log.Fatal(err)
}
```

Ask before an action. Use this before an LLM calls a tool:

```go
result, err := agent.Ask(ctx, "tickets.read", map[string]any{"ticket": "T-1042"})
if err != nil {
    return err
}
if !result.Allowed {
    return fmt.Errorf("not allowed: %s", result.Reason)
}
```

`AgentAskResult` holds `Allowed`, `Reason`, `AuditID` and the `Context` that the server
evaluated. As with ABAC, the server sets `ip`, `userAgent`, `requestMethod` and `requestPath`
itself and moves your values under `pep`.

Check capabilities and the budget:

```go
// Returns an error that matches ErrPermissionDenied when the capability is missing.
if err := agent.RequireCapability(ctx, "tool:search_web"); err != nil {
    return err
}

// Returns an error that matches ErrBudgetExceeded when the daily token budget is used up.
if err := agent.CheckBudget(ctx); err != nil {
    return err
}

caps, err := agent.Capabilities(ctx)      // []string
budget, err := agent.Budget(ctx)          // MaxTokensPerDay, TokensUsedToday
me, err := agent.Identity(ctx, false)     // identity, capabilities, workspace (cached)
```

The `Agent` has the namespaces `Agents`, `Jit`, `Delegation`, `Approvals`, `Mcp` and
`Permissions`. `agent.Client()` returns the underlying `*Client` for the rest.
`agent.Register(ctx, params)` creates or updates the agent's record in the organization's
directory. When you call `client.Agents.Register` with a user access token, the token needs
`admin:agents:write` or `admin`. Organization API keys cannot register agents.

`Agents.Me` returns the agent's capability roles when an agent calls it. A user access token
without `authz:read` gets an empty `Capabilities` list.

### Ask a human to approve an action

Before an action that cannot be undone, ask a person. LumoAuth sends a push notification to
the user's phone. `Require` blocks until the user answers.

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
    return fmt.Errorf("the user declined the transfer")
case errors.Is(err, lumoauth.ErrApprovalTimeout):
    return fmt.Errorf("nobody answered in time")
case errors.Is(err, lumoauth.ErrApprovalNotDelivered):
    return fmt.Errorf("no phone got the request; ask the user to check their email")
case err != nil:
    return err
}
// approval.Token is the credential for the action that the user approved.
```

The impact levels are `ImpactLow`, `ImpactMedium` (the default), `ImpactHigh` and
`ImpactCritical`. `Require` polls every 1.5 seconds for up to 90 seconds. Change this with
`&lumoauth.WaitOptions{PollInterval: ..., Timeout: ...}`.

`Require` returns an error for any answer other than approval. To handle a denial without an
error, call `Create`, then `Wait` or `Status`:

```go
pending, err := agent.Approvals.Create(ctx, params)
// ... later, or from another process:
result, err := agent.Approvals.Wait(ctx, pending.Token, nil)
if result.Approved() { /* ... */ }
```

Some requests never reach a phone. The SDK reports them as follows:

- If the user has no enrolled push device, the server sends them an email notice. The email
  has no approval link, so nobody can approve the action in this call. `Create` returns a
  result with the status `lumoauth.ApprovalEmailFallbackSent` and an empty `Token`. There is
  nothing to poll. `Require` does not poll either. It returns an `*ApprovalError` with the
  code `APPROVAL_NOT_DELIVERED` and the reason `email_fallback_sent`. The server gives the
  same answer for an unknown user, so the endpoint does not reveal who has an account.
- If the user has no device and the email could not be sent, the server answers 428.
  `Create` and `Require` both return an `*ApprovalError` with the code
  `APPROVAL_NOT_DELIVERED` and the reason `no_enrolled_device`.

Neither case counts as approval. Tell the user to check their email or to enrol a device:

```go
var approvalErr *lumoauth.ApprovalError
if errors.As(err, &approvalErr) && approvalErr.Code == lumoauth.CodeApprovalNotDelivered {
    switch approvalErr.Reason {
    case lumoauth.ApprovalReasonEmailFallbackSent:
        // An email notice went out. Ask the user to enrol a device, then try again.
    case lumoauth.ApprovalReasonNoEnrolledDevice:
        // Nothing reached the user. Ask them to enrol a device.
    }
}
```

A portal test token cannot create approvals. The server answers 403
`test_token_not_accepted`.

### Just-in-Time permissions

JIT permissions give an agent narrow, short-lived access for one task. Closing the task
revokes every token that was issued for it.

```go
jit, err := lumoauth.NewJITContext(agent)
if err != nil {
    return err
}
defer jit.Close(ctx) // completes the task and revokes its tokens

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
    if err != nil {
        return err
    }
    resp, err := jit.Call(ctx, token, http.MethodGet, "https://files.example.com/report_q4.pdf", nil)
    // ... use resp, then close resp.Body
}
```

How a request is decided:

- LumoAuth approves low-risk requests at once.
- A higher-risk request stays pending until a person reviews it. `RequestPermission` polls every
  5 seconds for up to 5 minutes. Set `NoWait: true` to return at once and poll with `Status`.
- If the result is still pending after the wait, the wait timed out. It is not a denial.
- A JIT token lasts 300 seconds by default (`JitDefaultTTL`). Set `TTL` to ask for up to
  900 seconds (`JitMaxTTL`).

`CallWithEscalation` handles the request for you. When a resource answers 403 with an
`Insufficient-Authorization-Details` header, it requests exactly the permission that the
header names, gets a JIT token and retries once.

```go
resp, err := jit.CallWithEscalation(ctx, http.MethodGet, "https://api.example.com/reports/q4", nil, nil)
```

To act for a user, call `jit.DelegateOnBehalfOf(ctx, userToken)` before you create the task.
The JIT tokens then name both the user and the agent.

People who review JIT requests use `client.Jit.Pending(ctx)`. This needs a user access token
with the `jit:approve` scope. An agent's own token cannot call it.

### Act on behalf of a user (delegation)

With delegation, an agent can call APIs as "agent X acting for user Y". It uses OAuth token
exchange (RFC 8693). `DelegationChain` manages the whole flow for one session ID per user.

```go
chain := lumoauth.NewDelegationChain(agent, "https://agent.example.com/callback")

// 1. Send the user to the consent page.
consentURL, err := chain.ConsentURL("session-1", []string{"read:documents"}, "")

// 2. Your callback receives ?code=...
err = chain.HandleConsentCallback(ctx, "session-1", code)

// 3. Call an API as the agent acting for the user. The exchange happens when needed.
var out map[string]any
err = chain.Do(ctx, "session-1", http.MethodGet, "/orgs/acme-corp/api/v1/documents", nil, &out)

// Hand the delegation to a sub-agent. A chain is at most 3 agents deep.
subToken, err := chain.DelegateToSubAgent(ctx, "session-1", subAgentToken, "read:documents")

// End the delegation. This revokes the refresh token and every token made from it.
err = chain.Revoke(ctx, "session-1")
```

If you already hold the user's access token, call `chain.SetUserToken(sessionID, token)` and
skip the consent step. Without a refresh token, the delegation lasts only as long as that
token does.

**Bind the token to an API.** Pass the URL of the API that will receive the token as an
RFC 8707 resource indicator. It becomes the token's `aud` claim. Without it, the delegated
token is bound to the acting agent's own ID.

```go
token, err := chain.ExchangeForResource(ctx, "session-1", "https://api.example.com", "read:documents")
```

LumoAuth does not set `aud` from the `audience` parameter. Send one resource URL per exchange.

**Low-level token exchange.** `client.Auth.TokenExchange` sends the request directly:

```go
resp, err := client.Auth.TokenExchange(ctx, lumoauth.TokenExchangeParams{
    SubjectToken:     userIDToken,
    SubjectTokenType: lumoauth.TokenTypeIDToken,
    ActorToken:       agentToken,
    Resource:         "https://api.example.com",
    Scopes:           []string{"read:documents"},
})
```

Declare what kind of token you send. The server rejects a token that does not match its
declared type.

| Constant | Use it for |
| --- | --- |
| `TokenTypeAccessToken` (default) | An access token issued by LumoAuth |
| `TokenTypeJWT` | An `at+jwt` access token, or a JWT for a workload identity from outside LumoAuth |
| `TokenTypeIDToken` | An OpenID Connect ID token |
| `TokenTypeRefreshToken` | A refresh token. It is not accepted as the subject when an agent acts for a user. |

The subject of an exchange must still be active. A deactivated or blocked user, or a
suspended agent, gets `invalid_grant`. A JIT task token is never accepted as the subject.

Delegated tokens carry an `act` claim that records the chain. `lumoauth.ParseActorChain(token)`
reads it for logs and audit. It does not verify the signature, so never use it to decide
access.

### Get a token for an MCP server

An MCP server that is secured by LumoAuth accepts only tokens issued for it. Exchange the
agent's token for one:

```go
token, err := agent.MCPToken(ctx, "https://mcp.example.com/mcp")
```

Pass the Resource URI that the MCP server is registered with. It is the server's https
URL. The SDK sends it as the RFC 8707 `resource` parameter, and LumoAuth sets the token's
`aud` to it. A plain `http` URL works only for localhost and private hosts. An ID such as
`urn:mcp:financial-data` cannot be bound to a server, so the SDK returns a
`ValidationError` before it sends the request.

The token names exactly one MCP server, and it works only at that server. LumoAuth's own
API refuses it. An MCP server that is registered with "Require DPoP" accepts only tokens
that are bound to a key. Give the agent a DPoP signer and the same call returns one; see
[Bind tokens to a key with DPoP](#bind-tokens-to-a-key-with-dpop).

With a plain `Client`, call `client.Mcp.Token(ctx, serverID, subjectToken)`. Pass an empty
`subjectToken` to exchange the client's own bearer token. `TokenDetailed` returns the full
response, including `TokenType` (`Bearer` or `DPoP`).

### Bind tokens to a key with DPoP

DPoP (RFC 9449) binds a token to a private key that only the agent holds. A stolen token is
then useless without the key. Generate a signer and pass it to the agent:

```go
signer, err := lumoauth.NewDPoPSigner() // a fresh P-256 key, ES256 proofs
agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{DPoP: signer})

mcpToken, err := agent.MCPToken(ctx, "https://mcp.example.com/mcp") // bound to the key

req, _ := http.NewRequestWithContext(ctx, "POST", "https://mcp.example.com/mcp", body)
if err := signer.AuthorizeRequest(req, mcpToken); err != nil {
    return err
}
// Authorization: DPoP <token>  and  DPoP: <proof with ath>
```

With a signer in place, the SDK:

- sends a `DPoP` proof with every token request: the client-credentials grant, the MCP and
  delegation exchanges. The tokens come back with `token_type: "DPoP"`; `agent.TokenType()`
  reports it.
- retries a token request once when the server answers `use_dpop_nonce`, and remembers the
  latest `DPoP-Nonce` of each origin for the following proofs.
- presents a bound token with the `DPoP` authorization scheme and a proof that carries `ath`,
  on LumoAuth's own API as well as through `AuthorizeRequest`. An unbound token keeps the
  `Bearer` scheme.

`NewDPoPSignerEd25519` signs `EdDSA` proofs instead. `GenerateDPoPKeyPEM` and
`LoadDPoPSigner` keep one key across restarts; `NewDPoPSignerFromKey` wraps an existing
`*ecdsa.PrivateKey` (P-256) or `ed25519.PrivateKey`. `signer.Proof(method, url, opts...)`
signs a proof by hand, and `signer.Thumbprint()` is the value that appears in a bound token's
`cnf.jkt`. If a resource server answers 401 with a `DPoP-Nonce` header, call
`signer.RememberNonce(resp)` and send the request again. `WithDPoP(signer)` does the same
for a plain `Client`. `APIConfig` refuses a bound token: the generated client cannot sign
proofs.

### Verify LumoAuth tokens in your MCP server

An MCP server, or any API, that receives LumoAuth access tokens verifies them locally. Three
lines protect a `net/http` handler:

```go
protect := lumoauth.RequireAccessToken(lumoauth.AccessTokenVerifyOptions{
    Issuer:   "https://app.lumoauth.dev/orgs/acme-corp/api/v1",
    Resource: "https://mcp.example.com/mcp", // the Resource URI the server is registered with
})
mux.Handle("/mcp", protect(mcpHandler))
```

Inside the handler, `claims, _ := lumoauth.AccessTokenFromContext(r.Context())` gives the
verified claims: `Subject` (`agent_agt_…` for an agent, a user id otherwise), `IsAgent`,
`Scopes()` and `HasScope`, `Capabilities`, the delegation chain in `Act` (`ActorChain()`
lists it), and `Confirmation.JKT` for a bound token. A missing or invalid token gets a 401
with a `WWW-Authenticate` challenge and a JSON body.

To verify a token yourself, call `VerifyAccessToken`:

```go
claims, err := lumoauth.VerifyAccessToken(ctx, token, lumoauth.AccessTokenVerifyOptions{
    Issuer:   issuer,
    Resource: resource,
    DPoP:     lumoauth.DPoPRequestFromHTTP(r), // needed for DPoP-bound tokens
})
```

It checks the `at+jwt` type, the algorithm (RSA and EC only; `none` and HMAC are refused),
the issuer, the signature against the organization's keys, `exp` and `nbf` with 60 seconds
of tolerance (`ClockSkew`; a negative value means none), that `aud` contains `Resource`,
and that the token is not a test token (`token_use: "test"`). For a token with `cnf.jkt` it
also checks the DPoP proof: the `DPoP` scheme, the proof signature, `htm` and `htu`, the
`iat` window, `ath`, the key thumbprint, and that the proof's `jti` was not seen before.
`RequireDPoP: true` refuses tokens that are not bound. A rejection is a `ValidationError`
whose `Reason` is one of the `TokenRejected*` constants; `RejectionReason(err)` reads it.

The keys come from `{issuer}/.well-known/openid-configuration` and are cached per issuer,
with one refetch when a token names an unknown `kid`. Pass `JWKS` to supply them yourself,
or `KeyCache` (`NewAccessTokenKeyCache`) to control the cache. Replayed proofs are caught by
an in-memory `ReplayCache`; a server with several replicas should pass a shared
implementation. Local verification does not check revocation.

`VerifyAuthToken` is the separate verifier for AAuth `auth+jwt` tokens.

### Check access to an MCP tool

LumoAuth can decide whether a caller may run one tool on a registered MCP server. Two
methods ask this question. Both take the registered server ID, such as
`mcp_0123456789abcdef01234567`. Do not pass the Resource URI here.

**From the MCP server.** The MCP server first verifies the caller's token. Then it asks
LumoAuth about that caller with its own token. It must never forward the caller's token,
because the MCP specification forbids token passthrough. The server's OAuth client needs
the `mcp:authorize` scope, and it must be one of the server's tool authorizers.

`NewAgent` runs the client credentials grant and refreshes the token, so the MCP server
can use it for its own client:

```go
mcpAuth, err := lumoauth.NewAgent(lumoauth.AgentConfig{
    OrgID:        "acme-corp",
    ClientID:     os.Getenv("MCP_CLIENT_ID"),
    ClientSecret: os.Getenv("MCP_CLIENT_SECRET"),
    Scopes:       []string{"mcp:authorize"},
})
if err != nil {
    log.Fatal(err)
}

// claims holds the verified MCP token of the caller.
decision, err := mcpAuth.Mcp.AuthorizeTool(ctx, lumoauth.McpToolAuthorizeParams{
    ServerID:    "mcp_0123456789abcdef01234567",
    SubjectType: "user", // "agent" when the caller is an agent
    SubjectID:   claims.Subject,
    Tool:        "send_invoice",
})
if err != nil {
    return err
}
if !decision.Allowed {
    return errors.New("tool not allowed")
}
```

Pass the `sub` claim of the verified token as `SubjectID`. For an agent, you can pass the
claim as it is (`agent_agt_…`) or the bare agent ID (`agt_…`).

**From the agent.** An agent can ask about itself before it calls a tool. The request
uses the agent's own credential:

```go
decision, err := agent.AuthorizeMcpTool(ctx, "mcp_0123456789abcdef01234567", "send_invoice")
```

With a plain `Client`, call `client.Agents.AuthorizeMcpTool(ctx, serverID, tool)`.

A deny is not an error. Both methods return a decision with `Allowed` set to false and a
nil error. Other failures are errors as usual. A missing scope, or a client that is not a
tool authorizer, gives `ErrPermissionDenied`. An unknown server gives `ErrNotFound`. The
SDK checks the arguments before it sends the request. A tool name or server ID must not
contain `/`, `:`, `#` or `*`, and a tool name has at most 80 characters.

### AAuth: cryptographic agent identity

AAuth extends OAuth 2.1 for agents that hold their own signing key. Tokens are bound to the
key (proof of possession), and every request is signed with RFC 9421 HTTP message signatures.
Use AAuth instead of `Agent` when the agent must prove its identity with a key.

**1. Create a key once.** Store the private key in a secret manager. Register the JWKS with
LumoAuth, or serve it at `/.well-known/jwks.json`.

```go
keypair, err := lumoauth.GenerateKeypair("") // Ed25519; the kid defaults to "key-1"
// keypair.PrivateKeyPEM: keep it secret
// keypair.JWKS:          register it, or publish it
```

**2. Build the client.**

```go
aauth, err := lumoauth.NewAAuthClient(lumoauth.AAuthConfig{
    AgentIdentifier: "https://my-agent.example.com",
    PrivateKeyPEM:   os.Getenv("AGENT_PRIVATE_KEY"),
    OrgID:           "acme-corp",
})
```

| `AAuthConfig` field | Meaning | Default |
| --- | --- | --- |
| `AgentIdentifier` | The HTTPS URL that identifies the agent (required) | none |
| `PrivateKeyPEM` | An Ed25519 (PKCS#8) or RSA private key (required) | none |
| `BaseURL`, `OrgID` | As for `New` | the environment variables |
| `Kid` | The key ID in the registered JWKS | `key-1` |
| `Timeout`, `HTTPClient`, `SkipCertValidation` | As for `New` | 30 seconds, a new client, off |

**3. Get an auth token for a resource.** The resource gives the agent a resource token. The
agent trades it for an auth token.

```go
result, err := aauth.RequestAuthToken(ctx, lumoauth.AuthTokenParams{
    ResourceToken: resourceToken,
    Scope:         "read write",
    AgentToken:    agentToken,
})
if err != nil {
    return err
}
if result.AuthorizationRequired {
    // A person must consent first. Redirect them to result.AuthorizationURI,
    // then exchange the code that comes back:
    // result, err = aauth.ExchangeCode(ctx, code, redirectURI, agentToken)
}
```

**4. Call the resource with a signed request.**

```go
resp, err := aauth.SignedRequest(ctx, http.MethodGet,
    "https://api.example.com/v1/data", result.AuthToken, nil)
if err != nil {
    return err
}
defer resp.Body.Close()
```

The request carries the auth token as a bearer token and an RFC 9421 signature that covers it.
A stolen token is useless without the private key.

Other `AAuthClient` methods:

| Method | What it does |
| --- | --- |
| `ExchangeToken(ctx, authToken, resourceToken, agentToken)` | Gets a token for a further hop. The new token records the chain in `act`. |
| `Refresh(ctx, params)` | Renews an auth token with a refresh token |
| `Revoke(ctx, token, tokenType, agentToken)` | Revokes an auth token (by its `jti`, with `AAuthTokenTypeAuth`) or a refresh token (with `AAuthTokenTypeRefresh`) |
| `DiscoverIssuer`, `DiscoverAgents`, `DiscoverResource`, `JWKS` | Read the metadata documents |
| `SignRequest(method, url, opts)` | Builds the signature headers without sending the request |
| `PublicJWK`, `PublicJWKThumbprint` | Return the agent's public key and its RFC 7638 thumbprint |

If you sign your own agent tokens (`agent+jwt`) on your agent's server, LumoAuth checks them
strictly. It rejects a token that lacks `iat` or `jti`, or that is valid for more than 24
hours. The agent's JWKS document must be served as JSON and must not be larger than 256 KB.

### Verify AAuth tokens on a resource server

When your API receives AAuth tokens, verify each token and its proof of possession:

```go
claims, err := lumoauth.VerifyAuthToken(ctx, bearerToken, lumoauth.VerifyOptions{
    Issuer:   "https://app.lumoauth.dev/orgs/acme-corp/api/v1",
    Resource: "https://api.example.com",
})
if err != nil {
    return err
}

// The token is bound to the agent's key. Check that the request was signed with that key,
// or a stolen token would pass.
if err := claims.VerifyProofOfPossession(req, body); err != nil {
    return err
}

if !claims.HasScope("read") {
    return errors.New("insufficient scope")
}
```

`VerifyAuthToken` checks the following:

- the `typ` header and the `iss` claim;
- the JWS signature, against the issuer's JWKS;
- the `exp` and `aud` claims;
- the presence of `cnf.jwk`.

It always rejects HMAC and `none` algorithms. The algorithm must also match the type of the
published key.

For a busy server, cache the issuer's keys:

```go
cache := lumoauth.NewJWKSCache(issuer, time.Hour, nil)
keys, err := cache.Get(ctx)
claims, err := lumoauth.VerifyAuthToken(ctx, token, lumoauth.VerifyOptions{
    Issuer: issuer, Resource: resource, JWKS: keys,
})
```

`VerifyOptions.ClockSkew` adds tolerance to the expiry check. It defaults to zero, like the
server. Local verification does not check revocation. For checks that must detect revoked
tokens, use the server's introspection endpoint.

### Call any other endpoint

The namespaces cover what most applications need. For other endpoints, such as the admin API,
SCIM or audit logs, use `Do`:

```go
path, err := client.OrgPath("/admin/users")
if err != nil {
    return err
}
var page struct {
    Data []map[string]any `json:"data"`
}
err = client.Do(ctx, http.MethodGet, path, nil, &page)
```

`DoRaw` returns the `*http.Response` instead. You must close its body.

You can also use the generated OpenAPI client, which covers the full REST API. This SDK does
not depend on it, so that your build stays small. `APIConfig` gives you its settings:

```go
import lumoauthclient "github.com/lumoauth/api-clients/go"

apiCfg, err := client.APIConfig(ctx)

cfg := lumoauthclient.NewConfiguration()
cfg.Servers = lumoauthclient.ServerConfigurations{{URL: apiCfg.BaseURL}}
cfg.DefaultHeader = apiCfg.DefaultHeader
cfg.HTTPClient = apiCfg.HTTPClient

api := lumoauthclient.NewAPIClient(cfg)
```

`APIConfig` sets exactly one credential header, the one that matches the client's credential.
It reads the current bearer token, so call it again after the token changes.

## Errors

Every error from this SDK matches `lumoauth.ErrLumoAuth`. Use `errors.Is` with the sentinel
errors, and `errors.As` to read the details:

```go
_, err := client.Permissions.List(ctx)

switch {
case errors.Is(err, lumoauth.ErrPermissionDenied):
    var apiErr *lumoauth.APIError
    if errors.As(err, &apiErr) && len(apiErr.RequiredScopes) > 0 {
        // The token lacks a scope. Ask the user to sign in again with these scopes.
        log.Printf("missing scopes: %v", apiErr.RequiredScopes)
    }
case errors.Is(err, lumoauth.ErrRateLimited):
    var apiErr *lumoauth.APIError
    if errors.As(err, &apiErr) {
        time.Sleep(apiErr.RetryAfter)
    }
case errors.Is(err, lumoauth.ErrNetwork):
    // No HTTP response: DNS, connection, TLS or timeout.
case err != nil:
    return err
}
```

| Sentinel | Meaning | `ErrorCode(err)` |
| --- | --- | --- |
| `ErrLumoAuth` | Any error from this SDK | the code below |
| `ErrAPI` | Any response with a status that is not 2xx | `API_ERROR` |
| `ErrAuthentication` | 401: the credential is missing, invalid or expired | `AUTHENTICATION_ERROR` |
| `ErrPermissionDenied` | 403: the caller may not do this | `PERMISSION_DENIED`, or the code in the body |
| `ErrNotFound` | 404 | `NOT_FOUND` |
| `ErrRateLimited` | 429: too many requests | `RATE_LIMITED` |
| `ErrValidation` | Bad input, or a response that the SDK cannot use | `VALIDATION_ERROR` |
| `ErrConfig` | A required option is missing or invalid | `CONFIG_ERROR` |
| `ErrNetwork` | The request failed before a response arrived | `NETWORK_ERROR` |
| `ErrApprovalDenied` | A person declined an approval | `APPROVAL_DENIED` |
| `ErrApprovalTimeout` | An approval expired before anyone answered | `APPROVAL_TIMEOUT` |
| `ErrApprovalNotDelivered` | No push device got the approval request; see `ApprovalError.Reason` | `APPROVAL_NOT_DELIVERED` |
| `ErrBudgetExceeded` | The agent's daily budget is used up | `BUDGET_EXCEEDED` |

`*APIError` has these fields:

- `StatusCode`: the HTTP status.
- `Code` and `Message`: taken from the response body when it has them.
- `Body`: the decoded body (`map[string]any` for JSON).
- `RetryAfter`: the `Retry-After` hint on a 429 response.
- `RequiredScopes`: the scopes that the server named when a token lacked one. It is empty for
  other errors.

When a token lacks a scope, the server's error code is `forbidden`, so `ErrorCode(err)` returns
`forbidden`. `errors.Is(err, lumoauth.ErrPermissionDenied)` still matches.

The helpers `AsAPIError(err)`, `StatusCode(err)` and `ErrorCode(err)` read these values
without `errors.As`. Errors wrap their causes, so `errors.Is(err, context.DeadlineExceeded)`
works through a `NetworkError`.

## API reference

The tables list the scope that a **user access token** needs. Agent credentials use the
agent's capabilities instead. An organization API key works only where the table says so.

### `client.Permissions`

| Method | What it does | Needs |
| --- | --- | --- |
| `Check(ctx, permission, opts)` | One permission, as a bool | any credential |
| `CheckDetailed` | The same, with the full response | any credential |
| `CheckBulk(ctx, permissions, opts)` | Several permissions; a map of results | any credential |
| `CheckAny`, `CheckAnyDetailed` | True when at least one is granted | any credential |
| `CheckAll`, `CheckAllDetailed` | True when all of them are granted | any credential |
| `List(ctx)`, `ListSlugs(ctx)` | Every permission of the caller | user token with `authz:read` |

Checking another user or agent (`CheckOptions.UserID` or `AgentID`) needs the `authz:check`
scope or the `authz.check` permission.

### `client.Zanzibar`

| Method | What it does | Needs |
| --- | --- | --- |
| `Check(ctx, object, relation, subject)` | Does the subject hold the relation? | any credential |
| `CheckDetailed` | The same, with the full response | any credential |
| `IsViewer`, `IsEditor`, `IsOwner`, `IsMember`, `IsAdmin` | `Check` with a fixed relation | any credential |
| `Expand(ctx, object, relation)` | The tree of everyone who holds the relation | `authz.check` permission or `authz:check` |

### `client.Abac`

| Method | What it does | Needs |
| --- | --- | --- |
| `Check(ctx, params)` | Evaluate the policies for one resource and action | `abac:read` |
| `CheckBulk(ctx, checks)` | Up to 100 checks in one request, with one shared environment | `abac:read` |
| `IsAllowed(ctx, params)` | `Check` as a bool | `abac:read` |
| `MyAttributes(ctx)` | The caller's attributes | `abac:read` |
| `ResourceAttributes(ctx, type, id)` | The attributes of one resource | `abac:read` |
| `AttributeDefinitions(ctx, attributeType)` | The organization's attribute definitions | `abac:read` |
| `SetUserAttribute(ctx, userID, slug, value)` | Set a user's attribute | `abac:write` and `abac.manage` |
| `SetResourceAttribute(ctx, type, id, slug, value)` | Set a resource's attribute | `abac:write` and `abac.manage` |

API keys are not accepted on ABAC routes.

### `client.Auth`

| Method | What it does |
| --- | --- |
| `AuthorizationURL(params)` | Builds the URL that starts sign-in |
| `ExchangeCode(ctx, params)` | Trades an authorization code for tokens |
| `RefreshToken(ctx, params)` | Gets a new access token with a refresh token |
| `ClientCredentials(ctx, id, secret, scopes...)` | The machine-to-machine grant |
| `TokenExchange(ctx, params)` | RFC 8693 token exchange |
| `Revoke(ctx, params)` | Revokes an access or refresh token |
| `UserInfo(ctx, accessToken)` | The OpenID Connect UserInfo claims |

### `client.Agents` and `Agent`

| Method | What it does | Needs |
| --- | --- | --- |
| `Ask(ctx, action, context)`, `IsAllowed` | May the agent do this action? | agent credential |
| `Me(ctx)` | Identity, capabilities and workspace | any bearer credential; a user token without `authz:read` gets no capabilities |
| `Capabilities(ctx)`, `Budget(ctx)`, `Info(ctx)` | Capability slugs, budget policy, UserInfo claims | agent credential |
| `Register(ctx, params)` | Create or update an agent record | `admin:agents:write` on a user token; not an API key |
| `Agent.RequireCapability`, `HasCapability`, `CheckBudget` | Guards that return errors | agent credential |
| `Agent.MCPToken(ctx, serverID)` | A token for an MCP server | agent credential |
| `AuthorizeMcpTool(ctx, serverID, tool)`, `Agent.AuthorizeMcpTool` | May the agent run this MCP tool? A deny returns `Allowed` false | agent credential |

### `client.Approvals`

| Method | What it does |
| --- | --- |
| `Require(ctx, params, opts)` | Create an approval and wait for the answer; any answer other than approval is an error |
| `Create(ctx, params)` | Create an approval and return at once; the status is `email_fallback_sent` with no token when no device got it |
| `Status(ctx, token)` | Read the current state |
| `Wait(ctx, token, opts)` | Poll until the approval is answered or expires |

All of them need an agent credential. Portal test tokens are refused.

### `client.Jit` and `JITContext`

| Method | What it does | Needs |
| --- | --- | --- |
| `CreateTask`, `CompleteTask`, `EvaluateTask` | Manage a task | agent credential |
| `Request(ctx, params)`, `Status`, `Token` | Request a permission, read it, get its token | agent credential |
| `Pending(ctx)` | Requests that are pending review by a person | user token with `jit:approve` |
| `JITContext.RequestPermission`, `Token`, `Call`, `CallWithEscalation`, `Close` | The managed task lifecycle | agent credential |

### `client.Delegation` and `DelegationChain`

| Method | What it does |
| --- | --- |
| `Delegation.Exchange(ctx, subject, actor, scopes...)` | One RFC 8693 exchange |
| `Delegation.ExchangeForResource(...)` | The same, bound to one resource URL |
| `DelegationChain.ConsentURL`, `HandleConsentCallback`, `SetUserToken` | Get the user's token |
| `DelegationChain.Exchange`, `ExchangeForResource`, `DelegatedToken`, `Do`, `DoRaw` | Use the delegation |
| `DelegationChain.DelegateToSubAgent`, `DelegateToSubAgentForResource` | Extend the chain to a sub-agent |
| `DelegationChain.Revoke`, `RevokeAll` | End delegations |
| `ParseActorChain(token)`, `TokenSubject(token)` | Read claims for audit, without verification |

### `client.Mcp`

| Method | What it does |
| --- | --- |
| `Token(ctx, serverID, subjectToken)` | A token for one MCP server; `serverID` is the server's registered Resource URI |
| `TokenDetailed(...)` | The same, with the full response |
| `AuthorizeTool(ctx, McpToolAuthorizeParams)` | May a user or agent run this tool? Called by the MCP server with its own token (`mcp:authorize`); a deny returns `Allowed` false |

### `DPoPSigner`

| Method | What it does |
| --- | --- |
| `Proof(method, url, opts...)` | Signs a DPoP proof; `WithProofAccessToken` adds `ath`, `WithProofNonce` overrides the nonce |
| `AuthorizeRequest(req, token)` | Sets `Authorization` (`DPoP` scheme for a bound token, `Bearer` otherwise) and the `DPoP` header |
| `PublicJWK()`, `Thumbprint()`, `Algorithm()` | The public key, its RFC 7638 thumbprint, `ES256` or `EdDSA` |
| `SetNonce(url, nonce)`, `Nonce(url)`, `RememberNonce(resp)` | Nonce memory per origin |

### Package functions

| Function | What it does |
| --- | --- |
| `New`, `NewAgent`, `NewWebAuth`, `NewAAuthClient` | Constructors |
| `NewJITContext(source, opts...)` | A JIT context over an `Agent` or any `TokenSource` |
| `NewDelegationChain(agent, redirectURI)` | A delegation manager |
| `VerifyAuthToken`, `NewJWKSCache`, `FetchIssuerJWKS` | Verify AAuth tokens |
| `VerifyAccessToken`, `RequireAccessToken`, `AccessTokenFromContext`, `DPoPRequestFromHTTP`, `NewAccessTokenKeyCache`, `FetchAccessTokenJWKS`, `NewMemoryReplayCache`, `RejectionReason` | Verify LumoAuth access tokens in an MCP server |
| `NewDPoPSigner`, `NewDPoPSignerEd25519`, `NewDPoPSignerFromKey`, `LoadDPoPSigner`, `GenerateDPoPKeyPEM`, `DPoPBound`, `DPoPAccessTokenHash` | DPoP keys and helpers |
| `GenerateKeypair`, `LoadPrivateKey`, `PublicJWK`, `SignRequest` | AAuth key and signing helpers |
| `UserFromContext`, `TokensFromContext` | Read the session in a handler |
| `AsAPIError`, `StatusCode`, `ErrorCode` | Error helpers |
| `RoutePath`, `RouteNames`, `BuildPath` | The route registry |

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| 401 from an ABAC, agent or JIT call that uses an organization API key | API keys work only on the admin API, client registration and the permission checks | Call these routes with a user access token or an agent credential |
| 403 from `Permissions.List` with `RequiredScopes` `["authz:read"]` | The token lacks `authz:read`, or the call uses an API key, which cannot hold it | Add `authz:read` to the scopes that the app requests, and sign the user in again |
| 403 `INSUFFICIENT_PERMISSIONS` from a check with `CheckOptions.UserID` | The caller may only ask about itself | Give the API key the `authz:check` scope, or grant the caller the `authz.check` permission |
| 404 `SUBJECT_NOT_FOUND` from a check with `CheckOptions.UserID` | The ID is not a LumoAuth user ID in your organization | Pass the user's LumoAuth ID (the `sub` claim), not an email or a local ID |
| `ValidationError` from `Abac.CheckBulk` about one environment | The entries carry different `Context` values | Split the call, or give every entry the same `Context` |
| 403 from an ABAC call with `RequiredScopes` `["abac:read"]` | The user token lacks the ABAC scope | Request `abac:read`, or `abac:write` for writes |
| `Agents.Me` returns an empty `Capabilities` list | A user token without `authz:read` called it | Request `authz:read`, or call it with the agent's credential |
| `invalid_grant` from a token exchange | The declared token type does not match the token, the subject is no longer active, or the subject is a JIT token | Set `SubjectTokenType` correctly (for example `TokenTypeIDToken` for an ID token), and exchange an active user's token |
| 400 `invalid_request` when an agent exchanges a refresh token for a user | A refresh token cannot be the subject of an on-behalf-of exchange | Exchange the user's access token or ID token |
| 403 `test_token_not_accepted` from `Approvals.Create` | The agent uses a test token from the portal | Use the agent's real credential |
| `ErrApprovalNotDelivered` from `Approvals.Require` | The user has no enrolled push device | Ask the user to enrol a device in the LumoAuth app, then try again |
| `ValidationError` from `Mcp.Token` about the server ID | The ID is not an http(s) URL, for example `urn:mcp:…` | Pass the MCP server's https URL, for example `https://mcp.example.com/mcp` |
| `ValidationError` from `AuthorizeTool` or `AuthorizeMcpTool` about the server ID | The ID is a URL | Pass the registered server ID, for example `mcp_0123456789abcdef01234567` |
| 403 `insufficient_scope` or `forbidden` from `Mcp.AuthorizeTool` | The token lacks `mcp:authorize`, or its client is not a tool authorizer of the server | Request `mcp:authorize` with the MCP server's own client, and list that client as a tool authorizer |
| 400 `invalid_target` from `Mcp.Token` | The server URL uses plain `http` on a public host, or has a fragment | Use an `https` URL with no `#` part |
| `ErrRateLimited` | Too many requests | Wait for `APIError.RetryAfter`, then retry |
| `ErrConfig` mentioning the organization | The call needs an org ID | Set `WithOrgID` or `LUMOAUTH_ORG_ID` |
| The session is lost after every restart | `SessionSecret` changes at each start | Load a fixed secret from your configuration |
| The session cookie is not set during local development | The cookie is `Secure` and the app uses plain HTTP | Set `CookieSecure: lumoauth.Bool(false)` in development only |

## Versioning and compatibility

The SDK reports itself as `lumoauth-go/1.0.0` in the `User-Agent` header (`lumoauth.Version`).
The module has no release tag yet. It needs a LumoAuth server whose API is version 1.0.0 or later.

Every endpoint that this SDK calls is listed in `routes.go`. A test compares that list with
the server's OpenAPI spec and with the shared SDK contract (`../sdk-contract`). A route that is
renamed on the server therefore fails the build instead of returning 404 in production.

## Development

```bash
go test ./...          # unit tests, contract tests and route checks
go test -race ./...    # the concurrent paths (token refresh, delegation)
go vet ./...
gofmt -l .
```

The contract tests read `../sdk-contract`, or the directory in `LUMO_SDK_CONTRACT`. They are
skipped when neither exists.

## Licence

MIT. See [LICENSE](./LICENSE).
