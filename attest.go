package lumoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

// Workload attestation: POST /agents/{agentId}/attest.
//
// The agent's runtime presents an OIDC token that its platform issued
// (GitHub Actions, Kubernetes, AWS, GCP, Azure, SPIFFE, …) and gets a
// short-lived LumoAuth access token for the agent, with no client secret in
// the environment. LumoAuth verifies the token's signature against the
// issuer's keys and its subject against the agent's registered workload
// identity binding.

// AttestParams describes a workload attestation.
type AttestParams struct {
	// AgentID is the agent's ID, for example "agt_7f3c2a19b84e5d60". Required.
	AgentID string
	// AttestationToken is the workload's OIDC token (a JWT). Required.
	AttestationToken string
	// Scopes optionally narrows the token to some of the agent's
	// capabilities. Empty means every capability. A scope outside the
	// capabilities is refused with invalid_scope.
	Scopes []string
}

// AttestResult is the answer to an accepted attestation.
type AttestResult struct {
	// AccessToken is the agent's access token; it lives 15 minutes.
	AccessToken string `json:"access_token"`
	// TokenType is "DPoP" when the token is bound to the client's DPoP key
	// (WithDPoP), "Bearer" otherwise.
	TokenType string `json:"token_type"`
	// ExpiresIn is the token's lifetime in seconds.
	ExpiresIn int `json:"expires_in"`
	// Scope holds the issued scope values, separated by spaces; "" when
	// none was issued.
	Scope string `json:"scope,omitempty"`
	// Identity is the workload identity that LumoAuth verified.
	Identity WorkloadIdentity `json:"identity"`

	// Raw is the complete decoded answer.
	Raw map[string]any `json:"-"`
}

// WorkloadIdentity is the verified identity of an attested workload.
type WorkloadIdentity struct {
	// Provider names the platform, for example "github" or "k8s".
	Provider string `json:"provider"`
	// Subject is the token's subject, for example
	// "repo:acme/app:ref:refs/heads/main".
	Subject string `json:"subject"`
	// Issuer is the token's issuer.
	Issuer string `json:"issuer"`
	// AudienceGeneric is true when the agent's registered audience is not
	// specific to LumoAuth (for example sts.amazonaws.com), so any token
	// that the provider mints for it satisfies the agent. Move the binding
	// to the agent-specific audience that the portal shows.
	AudienceGeneric bool `json:"audience_generic"`
}

// UnmarshalJSON decodes the typed fields and retains the whole object.
func (r *AttestResult) UnmarshalJSON(data []byte) error {
	type alias AttestResult
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*r = AttestResult(a)
	return json.Unmarshal(data, &r.Raw)
}

// Scopes splits the space-separated Scope field.
func (r *AttestResult) Scopes() []string { return splitScopes(r.Scope) }

// Attest exchanges a workload's OIDC token for an access token of the agent
// (workload attestation). The endpoint is public: the attestation token is
// the credential, so no API key or bearer token of the client is sent. With
// WithDPoP the request carries a proof, the token comes back bound to the
// key (TokenType "DPoP"), and a use_dpop_nonce answer is retried once with
// the server's nonce.
//
// A rejected attestation (unknown agent, inactive agent, a token that
// failed verification) is a 401 attestation_rejected that matches
// ErrAuthentication. A spent budget matches ErrBudgetExceeded.
//
//	result, err := client.Agents.Attest(ctx, lumoauth.AttestParams{
//	    AgentID:          "agt_7f3c2a19b84e5d60",
//	    AttestationToken: workloadToken,
//	})
//
// A runtime without any LumoAuth credential uses AttestWorkload, or a
// client built with WithoutCredential.
func (r *AgentsResource) Attest(ctx context.Context, params AttestParams) (*AttestResult, error) {
	if params.AgentID == "" {
		return nil, NewValidationError("AgentID is required for a workload attestation")
	}
	if params.AttestationToken == "" {
		return nil, NewValidationError("AttestationToken is required for a workload attestation")
	}
	for _, scope := range params.Scopes {
		if !isScopeToken(scope) {
			return nil, validationErrorf("scope %q is not a scope value (RFC 6749 §3.3)", scope)
		}
	}
	body := map[string]any{"attestation_token": params.AttestationToken}
	if len(params.Scopes) > 0 {
		body["scope"] = joinScopes(params.Scopes)
	}
	routeParams := map[string]string{"agentId": params.AgentID}

	var result AttestResult
	if r.http.dpop == nil {
		if err := r.http.call(ctx, RouteAgentsAttest, routeParams, &request{JSON: body, NoAuth: true}, &result); err != nil {
			return nil, err
		}
		return checkAttestResult(&result)
	}

	// With DPoP: a proof over this very address, retried once when the
	// server asks for its nonce (as at the token endpoint).
	attestURL, err := r.http.routeURL(RouteAgentsAttest, routeParams)
	if err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		proof, err := r.http.dpop.Proof(http.MethodPost, attestURL)
		if err != nil {
			return nil, err
		}
		req := &request{JSON: body, NoAuth: true, Headers: map[string]string{DPoPHeader: proof}}
		headers, err := r.http.doHeaders(ctx, http.MethodPost, attestURL, req, &result)
		if err == nil {
			return checkAttestResult(&result)
		}
		if attempt == 0 && isUseDPoPNonce(err) && headers.Get(DPoPNonceHeader) != "" {
			continue
		}
		return nil, err
	}
}

// checkAttestResult rejects a 2xx answer without an access token.
func checkAttestResult(result *AttestResult) (*AttestResult, error) {
	if result.AccessToken == "" {
		return nil, NewValidationError("the attestation endpoint returned no access_token")
	}
	return result, nil
}

// AttestWorkloadOptions configures AttestWorkload.
type AttestWorkloadOptions struct {
	// BaseURL is the LumoAuth instance. Defaults to $LUMOAUTH_URL, then
	// DefaultBaseURL.
	BaseURL string
	// OrgID is the organization slug. Defaults to $LUMOAUTH_ORG_ID. Not
	// needed with CustomDomain.
	OrgID string
	// CustomDomain is the organization's own domain. Defaults to
	// $LUMOAUTH_CUSTOM_DOMAIN. It wins over BaseURL.
	CustomDomain string
	// AgentID, AttestationToken and Scopes are those of AttestParams.
	AgentID          string
	AttestationToken string
	Scopes           []string
	// DPoP binds the issued token to this signer's key.
	DPoP *DPoPSigner
	// HTTPClient overrides the client used for the request.
	HTTPClient *http.Client
	// Timeout is the request timeout. Default: 30s.
	Timeout time.Duration
	// SkipCertValidation disables TLS verification. Local development only.
	SkipCertValidation bool
}

// AttestWorkload performs a workload attestation without a LumoAuth client:
// the workload has no credential of its own, only its platform's OIDC token.
// It reads the address from the options, then from $LUMOAUTH_URL,
// $LUMOAUTH_ORG_ID and $LUMOAUTH_CUSTOM_DOMAIN, and never sends an API key.
//
//	token, _ := os.ReadFile("/var/run/secrets/tokens/lumoauth")
//	result, err := lumoauth.AttestWorkload(ctx, lumoauth.AttestWorkloadOptions{
//	    AgentID:          os.Getenv("LUMOAUTH_AGENT_ID"),
//	    AttestationToken: strings.TrimSpace(string(token)),
//	})
func AttestWorkload(ctx context.Context, opts AttestWorkloadOptions) (*AttestResult, error) {
	customDomain, err := customDomainFrom(opts.CustomDomain)
	if err != nil {
		return nil, err
	}
	cfg := &clientConfig{
		baseURL:            strings.TrimRight(firstNonEmpty(opts.BaseURL, os.Getenv(EnvBaseURL), DefaultBaseURL), "/"),
		customDomain:       customDomain,
		orgID:              firstNonEmpty(opts.OrgID, os.Getenv(EnvOrgID)),
		timeout:            opts.Timeout,
		httpClient:         opts.HTTPClient,
		skipCertValidation: opts.SkipCertValidation,
		userAgent:          userAgent(),
		dpop:               opts.DPoP,
	}
	if cfg.timeout <= 0 {
		cfg.timeout = defaultTimeout
	}
	if cfg.orgID == "" && customDomain == "" {
		return nil, NewConfigError("AttestWorkload needs the organization: set OrgID (or LUMOAUTH_ORG_ID), or CustomDomain")
	}
	return newClient(cfg).Agents.Attest(ctx, AttestParams{
		AgentID:          opts.AgentID,
		AttestationToken: opts.AttestationToken,
		Scopes:           opts.Scopes,
	})
}
