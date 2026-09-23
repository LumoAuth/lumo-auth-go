package lumoauth

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// ID is an identifier the API may send as either a JSON string or a JSON
// number (user IDs in particular). It decodes both into a string.
type ID string

// UnmarshalJSON accepts a string, a number, or null.
func (id *ID) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*id = ""
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*id = ID(s)
		return nil
	}
	*id = ID(string(data))
	return nil
}

// MarshalJSON emits the ID as a JSON string, or as a number when it is one.
func (id ID) MarshalJSON() ([]byte, error) {
	if _, err := strconv.ParseInt(string(id), 10, 64); err == nil {
		return []byte(id), nil
	}
	return json.Marshal(string(id))
}

// String returns the identifier as text.
func (id ID) String() string { return string(id) }

// Response shapes shared across the resource namespaces.
//
// The LumoAuth API is still growing response fields, so the open-ended
// payloads (agent identity, JIT results, ABAC decisions) keep a Raw map
// alongside their typed fields. Raw always holds the complete decoded
// object, so a field this SDK does not know about yet is still reachable
// without dropping to the escape hatch.

// ── Permissions (RBAC) ────────────────────────────────────────────────

// Permission is one permission granted to a principal.
type Permission struct {
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source,omitempty"`
}

// PermissionCheck is the result of a single permission check.
type PermissionCheck struct {
	Allowed    bool           `json:"allowed"`
	Permission string         `json:"permission,omitempty"`
	UserID     ID             `json:"user_id,omitempty"`
	Context    map[string]any `json:"context,omitempty"`
}

// PermissionBulkCheck is the result of a bulk permission check: Results maps
// each requested slug to its decision.
type PermissionBulkCheck struct {
	Results map[string]bool `json:"results"`
	UserID  ID              `json:"user_id,omitempty"`
	Context map[string]any  `json:"context,omitempty"`
}

// PermissionMultiCheck is the result of a check-any / check-all call.
type PermissionMultiCheck struct {
	Allowed     bool           `json:"allowed"`
	Permissions []string       `json:"permissions,omitempty"`
	UserID      ID             `json:"user_id,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
}

// PermissionList is the full set of permissions granted to a principal.
type PermissionList struct {
	UserID      ID           `json:"user_id,omitempty"`
	Permissions []Permission `json:"permissions"`
	Count       int          `json:"count,omitempty"`
}

// ── Zanzibar (ReBAC) ──────────────────────────────────────────────────

// ZanzibarCheck is the result of a relationship check.
type ZanzibarCheck struct {
	Allowed  bool   `json:"allowed"`
	Object   string `json:"object,omitempty"`
	Relation string `json:"relation,omitempty"`
	Subject  string `json:"subject,omitempty"`
	User     string `json:"user,omitempty"`
}

// ZanzibarUsersetNode is a node in an expansion tree. Leaves carry Subjects;
// union/intersection nodes carry Children of the same shape.
type ZanzibarUsersetNode struct {
	Type     string                `json:"type"` // "union", "intersection" or "leaf"
	Object   string                `json:"object,omitempty"`
	Relation string                `json:"relation,omitempty"`
	Children []ZanzibarUsersetNode `json:"children,omitempty"`
	Subjects []string              `json:"subjects,omitempty"`
}

// zanzibarExpandResponse is the wire envelope; callers get the tree itself.
type zanzibarExpandResponse struct {
	Tree *ZanzibarUsersetNode `json:"tree"`
}

// ── ABAC ──────────────────────────────────────────────────────────────

// AbacMatchedPolicy is a policy that contributed to an ABAC decision.
type AbacMatchedPolicy struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Effect   string `json:"effect"` // "allow" or "deny"
	Priority int    `json:"priority"`
}

// AbacDecision is the outcome of evaluating ABAC policies for one
// resource/action pair.
type AbacDecision struct {
	Allowed         bool                `json:"allowed"`
	Reason          string              `json:"reason,omitempty"`
	MatchedPolicies []AbacMatchedPolicy `json:"matchedPolicies,omitempty"`

	// Raw is the complete decoded decision, including the evaluation
	// context the server echoed back.
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON decodes the typed fields and retains the whole object.
func (d *AbacDecision) UnmarshalJSON(data []byte) error {
	type alias AbacDecision
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*d = AbacDecision(a)
	return json.Unmarshal(data, &d.Raw)
}

// AbacBulkDecision is the result of a bulk ABAC check, in request order.
type AbacBulkDecision struct {
	Results []AbacDecision `json:"results"`
}

// AbacAttributeDefinition describes an attribute the org has defined.
type AbacAttributeDefinition struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Slug            string         `json:"slug"`
	Description     string         `json:"description,omitempty"`
	AttributeType   string         `json:"attributeType,omitempty"` // user | resource | environment
	DataType        string         `json:"dataType,omitempty"`      // string | number | boolean | array | date
	ValidationRules map[string]any `json:"validationRules,omitempty"`
	IsActive        bool           `json:"isActive,omitempty"`
}

// ── OAuth ─────────────────────────────────────────────────────────────

// TokenResponse is an OAuth 2.1 token endpoint response.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IDToken         string `json:"id_token,omitempty"`
	TokenType       string `json:"token_type,omitempty"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// Scopes splits the space-separated Scope field.
func (t *TokenResponse) Scopes() []string { return splitScopes(t.Scope) }

// UserInfo is an OIDC UserInfo response. Agent principals additionally
// carry Capabilities and BudgetPolicy.
type UserInfo struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	GivenName     string   `json:"given_name,omitempty"`
	FamilyName    string   `json:"family_name,omitempty"`
	Picture       string   `json:"picture,omitempty"`
	AgentID       string   `json:"agent_id,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`

	// BudgetPolicy is the agent's budget, when one is set.
	BudgetPolicy *AgentBudget `json:"budget_policy,omitempty"`

	// Raw is the complete decoded response, including any claims not
	// modelled above.
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON decodes the typed claims and retains the whole object.
func (u *UserInfo) UnmarshalJSON(data []byte) error {
	type alias UserInfo
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*u = UserInfo(a)
	return json.Unmarshal(data, &u.Raw)
}

// ── Agents ────────────────────────────────────────────────────────────

// AgentAskResult is the decision returned by the Ask API.
type AgentAskResult struct {
	Allowed bool           `json:"allowed"`
	Action  string         `json:"action,omitempty"`
	Reason  string         `json:"reason,omitempty"`
	AuditID string         `json:"audit_id,omitempty"`
	Context map[string]any `json:"context,omitempty"`

	// Raw is the complete decoded decision.
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON decodes the typed fields and retains the whole object.
func (r *AgentAskResult) UnmarshalJSON(data []byte) error {
	type alias AgentAskResult
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*r = AgentAskResult(a)
	return json.Unmarshal(data, &r.Raw)
}

// AgentIdentity is the agent's own identity, capabilities, and workspace.
type AgentIdentity struct {
	Identity     map[string]any `json:"identity,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Workspace    map[string]any `json:"workspace,omitempty"`

	// Raw is the complete decoded response.
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON decodes the typed fields and retains the whole object.
func (i *AgentIdentity) UnmarshalJSON(data []byte) error {
	type alias AgentIdentity
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*i = AgentIdentity(a)
	return json.Unmarshal(data, &i.Raw)
}

// ID returns the agent's identity ID, or "" when the server did not send one.
func (i *AgentIdentity) ID() string {
	if id, ok := i.Identity["id"].(string); ok {
		return id
	}
	return ""
}

// AgentBudget is the budget policy attached to an agent.
type AgentBudget struct {
	MaxTokensPerDay int `json:"max_tokens_per_day,omitempty"`
	TokensUsedToday int `json:"tokens_used_today,omitempty"`

	// Raw is the complete decoded policy.
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON decodes the typed fields and retains the whole object.
func (b *AgentBudget) UnmarshalJSON(data []byte) error {
	type alias AgentBudget
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*b = AgentBudget(a)
	return json.Unmarshal(data, &b.Raw)
}

// Exhausted reports whether the daily token budget has been reached. A
// policy without a daily cap is never exhausted.
func (b *AgentBudget) Exhausted() bool {
	if b == nil || b.MaxTokensPerDay <= 0 {
		return false
	}
	return b.TokensUsedToday >= b.MaxTokensPerDay
}

// AgentRegistration is the response to registering an agent.
type AgentRegistration struct {
	AgentID  string `json:"agent_id,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Name     string `json:"name,omitempty"`
	Status   string `json:"status,omitempty"`

	// Raw is the complete decoded response.
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON decodes the typed fields and retains the whole object.
func (r *AgentRegistration) UnmarshalJSON(data []byte) error {
	type alias AgentRegistration
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*r = AgentRegistration(a)
	return json.Unmarshal(data, &r.Raw)
}

// ── JIT ───────────────────────────────────────────────────────────────

// JitTask is an ephemeral task (an isolated agent sub-identity).
type JitTask struct {
	TaskID        string `json:"task_id"`
	CaepSessionID string `json:"caep_session_id,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`

	// Raw is the complete decoded response.
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON decodes the typed fields and retains the whole object.
func (t *JitTask) UnmarshalJSON(data []byte) error {
	type alias JitTask
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*t = JitTask(a)
	return json.Unmarshal(data, &t.Raw)
}

// JitRequest is the state of a Just-in-Time permission request.
type JitRequest struct {
	RequestID string `json:"request_id"`
	// Status is "approved", "pending", "denied", or a newer server value.
	Status    string `json:"status"`
	RiskLevel string `json:"risk_level,omitempty"`
	TokenURL  string `json:"token_url,omitempty"`
	StatusURL string `json:"status_url,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`

	// AuthorizationDetails is the RFC 9396 object the request covers.
	AuthorizationDetails map[string]any `json:"authorization_details,omitempty"`

	// Raw is the complete decoded response.
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON decodes the typed fields and retains the whole object.
func (r *JitRequest) UnmarshalJSON(data []byte) error {
	type alias JitRequest
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*r = JitRequest(a)
	return json.Unmarshal(data, &r.Raw)
}

// Approved reports whether the request has been granted.
func (r *JitRequest) Approved() bool { return r.Status == JitStatusApproved }

// Pending reports whether the request is still awaiting a decision.
func (r *JitRequest) Pending() bool { return r.Status == JitStatusPending }

// JIT request statuses.
const (
	JitStatusApproved = "approved"
	JitStatusPending  = "pending"
	JitStatusDenied   = "denied"
)

// Task outcomes accepted by JitResource.EvaluateTask.
const (
	TaskResultCompleted = "completed"
	TaskResultFailed    = "failed"
	TaskResultCancelled = "cancelled"
)

// ── Approvals ─────────────────────────────────────────────────────────

// ApprovalImpact is the severity tier of an approval request; it drives the
// visual treatment on the approver's phone.
type ApprovalImpact string

// Approval impact tiers.
const (
	ImpactLow      ApprovalImpact = "low"
	ImpactMedium   ApprovalImpact = "medium"
	ImpactHigh     ApprovalImpact = "high"
	ImpactCritical ApprovalImpact = "critical"
)

// Valid reports whether the impact is one the server accepts.
func (i ApprovalImpact) Valid() bool {
	switch i {
	case ImpactLow, ImpactMedium, ImpactHigh, ImpactCritical:
		return true
	}
	return false
}

// Approval statuses.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalExpired  = "expired"
)

// Approver identifies the human who responded to an approval request.
type Approver struct {
	UserID ID     `json:"user_id,omitempty"`
	Email  string `json:"email,omitempty"`
}

// ApprovalResult is the state of a push-approval request.
type ApprovalResult struct {
	// Status is "pending", "approved", "denied", or "expired".
	Status string `json:"status"`
	// Token is the approval token; present it as the credential for the
	// side-effecting call the approval authorises.
	Token       string         `json:"approval_token,omitempty"`
	TaskID      string         `json:"task_id,omitempty"`
	Impact      ApprovalImpact `json:"impact,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	ExpiresAt   string         `json:"expires_at,omitempty"`
	RespondedAt string         `json:"responded_at,omitempty"`
	ApprovedBy  *Approver      `json:"approved_by,omitempty"`
}

// Approved reports whether a human approved the action.
func (r *ApprovalResult) Approved() bool { return r != nil && r.Status == ApprovalApproved }

// ── MCP ───────────────────────────────────────────────────────────────

// McpToken is an audience-scoped token for a secured MCP server.
type McpToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`
}
