# Changelog

Release notes of published versions are in [release-notes/](release-notes/).

## Unreleased

- **New:** a delegation's consent goes through an application of your organization:
  `NewDelegationChainForApplication(agent, DelegationApplication{ClientID, ClientSecret,
  RedirectURI, OfflineAccess})`. `ConsentURL` builds the sign-in of that application with PKCE
  (S256), `openid`, the scopes and optional `offline_access`, and a random state
  (`ConsentState`). `HandleConsentCallback` redeems the code as the application, never with the
  agent's credentials. `SetUserTokens` registers tokens that the application got itself.
  `Delegation.ApplicationConsentURL` builds the same URL from explicit parameters.
- **Deprecated:** `NewDelegationChain` and `Delegation.ConsentURL`. They built the sign-in with the
  agent's ID, which LumoAuth answers with "Unknown Application". With an agent's `agt_…` ID they
  now return an error that says so instead of a URL that cannot work.
- **Changed:** `DelegationChain.Revoke` revokes the person's refresh token as the application, which
  ends every delegated token of that grant. When it can only forget the session (no refresh token,
  or no application credentials), it says so: the error matches `ErrDelegationNotRevoked` and
  `ErrConfig`. New `Forget` drops a session without a request.
- **Fixed:** the web sign-in (`WebAuth`) completes with the default scopes. The session cookie is
  encrypted (AES-256) and signed, with keys derived from `SessionSecret`. It is split over
  `lumo_session`, `lumo_session.1`, … when it is larger than one cookie. Sessions of earlier
  versions are still read. New `WebConfig.Store` takes any gorilla `sessions.Store`.
- **Changed:** `/auth/logout` also ends the LumoAuth session (RP-initiated logout with
  `id_token_hint`; register the absolute `PostLogoutRedirect` as a post-logout redirect URI).
  `WebConfig.LocalLogout` keeps the local-only sign-out. New `Auth.EndSessionURL`.
- **Fixed:** `Abac.Check` and `Abac.AttributeDefinitions` decode the numeric IDs that the server
  sends (`AbacMatchedPolicy.ID` and `AbacAttributeDefinition.ID` stay strings).
  `AbacAttributeDefinition` has `DefaultValue`, `IsRequired`, `IsSystem`, `BuiltIn`, `CreatedAt`
  and `UpdatedAt`; `IsActive` is deprecated (the server never sends it).
- **New:** `AgentAskResult.DecidedBy` with the constants `DecidedByCapability`, `DecidedByPDP` and
  `DecidedByDenyOverride`. `AgentBudget` types every limit and usage counter of `budget_policy`,
  plus `MaxSteps` and `TimeoutSeconds`; `Exhausted()` without the server's verdict checks every
  limit.
- **Fixed:** a response with the body code `budget_exceeded` (a spent agent budget, 429) matches
  `ErrBudgetExceeded` as well as `ErrRateLimited`. It is still an `*APIError`, and `errors.As`
  finds a `*BudgetError` in it. `BudgetError` has `RetryAfter`.
- **New:** workload attestation: `client.Agents.Attest(ctx, AttestParams)` and
  `AttestWorkload(ctx, AttestWorkloadOptions)` for a workload without a LumoAuth credential.
  The route `agents.attest` is in `Routes`.
- **New:** `Auth.ClientCredentialsWithParams` with a `Resource` (RFC 8707, the token's `aud`), a
  secret or a client assertion, and `ClientAuthMethod` (`ClientSecretPost` or
  `ClientSecretBasic`).
- **New:** client authentication for the token exchange of a confidential application:
  `TokenExchangeParams.ClientID` with `ClientSecret` (Basic by default, or `ClientSecretPost`) or
  `ClientAssertion`.
- **New:** `WithoutCredential()` builds a client without a credential, for addresses and the calls
  that authenticate themselves (token endpoint, revocation, attestation), for example an
  application that holds only a private key.
- **New:** DPoP nonces on a resource server: `DPoPRequest.Nonce`, `TokenRejectedDPoPNonce`, and
  `AccessTokenVerifyOptions.DPoPNonce`, with which `RequireAccessToken` answers
  `use_dpop_nonce` and a `DPoP-Nonce` header.
- **Fixed:** `MaxDelegationDepth` is 5, the number of actors that LumoAuth allows (it said 3).
  `DelegationChain` recognises the server's answer for a chain that is too deep (400
  `invalid_request`, "Delegation chain too deep: …").
- **Changed:** `client.Poppy.Middleware` without `OnError` answers a failed verification call with
  503 `temporarily_unavailable` instead of 500.
