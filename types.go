package lumoauth

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"strings"
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
	// ID is the policy's ID as text. The server sends a number ({"id": 81}
	// gives "81"); a string is accepted too, and null gives "".
	ID       string `json:"id"`
	Name     string `json:"name"`
	Effect   string `json:"effect"` // "allow" or "deny"
	Priority int    `json:"priority"`
}

// UnmarshalJSON decodes the policy and accepts its ID as a number or a
// string.
func (p *AbacMatchedPolicy) UnmarshalJSON(data []byte) error {
	type alias AbacMatchedPolicy
	aux := struct {
		*alias
		ID ID `json:"id"`
	}{alias: (*alias)(p)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	p.ID = aux.ID.String()
	return nil
}

// AbacDecision is the outcome of evaluating ABAC policies for one
// resource/action pair.
type AbacDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
	// MatchedPolicies lists the policies that applied. A caller without the
	// policies.view permission receives only each policy's ID and Name.
	MatchedPolicies []AbacMatchedPolicy `json:"matchedPolicies,omitempty"`
	// ResourceType, Action and ResourceID echo the evaluated target.
	ResourceType string `json:"resourceType,omitempty"`
	Action       string `json:"action,omitempty"`
	ResourceID   string `json:"resourceId,omitempty"`
	// Index is the position of this result in a bulk request (0 for a
	// single check).
	Index int `json:"index,omitempty"`
	// Error is set on a bulk result whose entry the server could not
	// evaluate; Allowed is then false.
	Error string `json:"error,omitempty"`

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
	// ID is the definition's ID as text. The server sends a number; a
	// string is accepted too.
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Slug            string         `json:"slug"`
	Description     string         `json:"description,omitempty"`
	AttributeType   string         `json:"attributeType,omitempty"` // user | resource | environment
	DataType        string         `json:"dataType,omitempty"`      // string | number | boolean | array | date
	ValidationRules map[string]any `json:"validationRules,omitempty"`
	// DefaultValue is the value an entity has when none is set; nil when the
	// definition has none.
	DefaultValue any `json:"defaultValue,omitempty"`
	// IsRequired reports whether every entity must have a value.
	IsRequired bool `json:"isRequired,omitempty"`
	// IsSystem marks a definition that LumoAuth manages.
	IsSystem bool `json:"isSystem,omitempty"`
	// BuiltIn marks a definition that LumoAuth provides to every
	// organization: readable, never writable by one.
	BuiltIn bool `json:"builtIn,omitempty"`
	// CreatedAt and UpdatedAt are RFC 3339 times; UpdatedAt is "" for a
	// definition that was never changed.
	CreatedAt string `json:"createdAt,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
	// IsActive is not sent by the server and is always false.
	//
	// Deprecated: the server has no such flag; every listed definition
	// applies.
	IsActive bool `json:"isActive,omitempty"`
}

// UnmarshalJSON decodes the definition and accepts its ID as a number or a
// string.
func (d *AbacAttributeDefinition) UnmarshalJSON(data []byte) error {
	type alias AbacAttributeDefinition
	aux := struct {
		*alias
		ID ID `json:"id"`
	}{alias: (*alias)(d)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	d.ID = aux.ID.String()
	return nil
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

// RecordedUsage is the usage that LumoAuth added to the agent's budget windows.
type RecordedUsage struct {
	Tokens  int     `json:"tokens"`
	CostUSD float64 `json:"cost_usd"`
}

// UsageReportResult is the answer to AgentsResource.ReportUsage: what was
// recorded, and the agent's budget after it (the same shape as BudgetPolicy in
// UserInfo; Budget.Exhausted() means that the next metered call gets 429).
type UsageReportResult struct {
	Recorded RecordedUsage `json:"recorded"`
	Budget   *AgentBudget  `json:"budget,omitempty"`
}

// Values of AgentAskResult.DecidedBy.
const (
	// DecidedByCapability: the agent's capabilities decided (no policy or
	// relationship data applied).
	DecidedByCapability = "capability"
	// DecidedByPDP: the organization's policies and relationships decided.
	DecidedByPDP = "pdp"
	// DecidedByDenyOverride: an explicit ABAC deny overrode a capability that
	// would have allowed the action.
	DecidedByDenyOverride = "deny_override"
)

// AgentAskResult is the decision returned by the Ask API.
type AgentAskResult struct {
	Allowed bool   `json:"allowed"`
	Action  string `json:"action,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// DecidedBy names the check that produced the answer: DecidedByCapability,
	// DecidedByPDP or DecidedByDenyOverride. "" when the server did not say.
	DecidedBy string         `json:"decided_by,omitempty"`
	AuditID   string         `json:"audit_id,omitempty"`
	Context   map[string]any `json:"context,omitempty"`

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

// AgentBudget is the budget of an agent as UserInfo (budget_policy) and the
// usage report return it: the limits that are set, the usage in the current
// UTC windows, and the server's verdict. A limit that is not set is 0.
type AgentBudget struct {
	// Limits on API calls and model tokens.
	MaxAPICallsPerHour int `json:"max_api_calls_per_hour,omitempty"`
	MaxAPICallsPerDay  int `json:"max_api_calls_per_day,omitempty"`
	MaxTokensPerHour   int `json:"max_tokens_per_hour,omitempty"`
	MaxTokensPerDay    int `json:"max_tokens_per_day,omitempty"`
	// Limits on cost, in USD. HardLimitUSD (`hard_limit`) and
	// MaxCostPerDayUSD are both daily limits; the lower one applies.
	MaxCostPerDayUSD   float64 `json:"max_cost_per_day_usd,omitempty"`
	MaxCostPerMonthUSD float64 `json:"max_cost_per_month_usd,omitempty"`
	HardLimitUSD       float64 `json:"hard_limit,omitempty"`

	// Usage in the current UTC hour, day and month. Tokens and cost count
	// only reported usage (Agent.ReportUsage).
	APICallsThisHour   int     `json:"api_calls_this_hour,omitempty"`
	APICallsToday      int     `json:"api_calls_today,omitempty"`
	TokensUsedThisHour int     `json:"tokens_used_this_hour,omitempty"`
	TokensUsedToday    int     `json:"tokens_used_today,omitempty"`
	CostTodayUSD       float64 `json:"cost_today_usd,omitempty"`
	CostThisMonthUSD   float64 `json:"cost_this_month_usd,omitempty"`

	// MaxSteps and TimeoutSeconds are settings that LumoAuth stores and
	// returns but does not enforce: your agent applies them. They are 0
	// when unset or when the stored value is not a number.
	MaxSteps       int `json:"-"`
	TimeoutSeconds int `json:"-"`

	// ReportedExhausted is the server's own verdict (`exhausted`): true when
	// any limit (calls, tokens or cost, per hour, day or month) is reached.
	// Nil when the server did not report it.
	ReportedExhausted *bool `json:"exhausted,omitempty"`

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
	if err := json.Unmarshal(data, &b.Raw); err != nil {
		return err
	}
	// The runtime settings come back as stored, so read them leniently: a
	// value of another type must not make the whole UserInfo unreadable.
	b.MaxSteps = wholeNumber(b.Raw["max_steps"])
	b.TimeoutSeconds = wholeNumber(b.Raw["timeout_seconds"])
	return nil
}

// wholeNumber reads a JSON number or a numeric string as an int, and gives 0
// for anything else.
func wholeNumber(value any) int {
	switch v := value.(type) {
	case float64:
		if v > 0 && v < math.MaxInt32 {
			return int(v)
		}
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f > 0 && f < math.MaxInt32 {
			return int(f)
		}
	}
	return 0
}

// Exhausted reports whether the agent's budget is spent, so the next metered
// call would get 429. It uses the server's verdict when reported (any limit,
// any window); otherwise it compares every limit that is set with the usage
// of its window, and a policy without limits is never exhausted.
func (b *AgentBudget) Exhausted() bool {
	if b == nil {
		return false
	}
	if b.ReportedExhausted != nil {
		return *b.ReportedExhausted
	}
	reached := func(limit, used float64) bool { return limit > 0 && used >= limit }
	return reached(float64(b.MaxAPICallsPerHour), float64(b.APICallsThisHour)) ||
		reached(float64(b.MaxAPICallsPerDay), float64(b.APICallsToday)) ||
		reached(float64(b.MaxTokensPerHour), float64(b.TokensUsedThisHour)) ||
		reached(float64(b.MaxTokensPerDay), float64(b.TokensUsedToday)) ||
		reached(b.MaxCostPerDayUSD, b.CostTodayUSD) ||
		reached(b.HardLimitUSD, b.CostTodayUSD) ||
		reached(b.MaxCostPerMonthUSD, b.CostThisMonthUSD)
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
	// ApprovalEmailFallbackSent is the status Create returns when the user
	// has no enrolled push device. The server sent an email notice with no
	// approval link instead. The result has no Token and nothing to poll.
	ApprovalEmailFallbackSent = "email_fallback_sent"
)

// Approver identifies the human who responded to an approval request. The
// server sends it as {"user_id": …} on an approved request and null
// otherwise.
type Approver struct {
	UserID ID `json:"user_id,omitempty"`
	// Email is set only if the server includes it; the current server
	// sends user_id alone.
	Email string `json:"email,omitempty"`
}

// ApprovalResult is the state of a push-approval request.
type ApprovalResult struct {
	// Status is "pending", "approved", "denied", or "expired". Create can
	// also return ApprovalEmailFallbackSent, with an empty Token.
	Status string `json:"status"`
	// Message is the server's explanation, when it sends one.
	Message string `json:"message,omitempty"`
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

// McpToolSubject names the caller of an MCP tool: a user or an agent.
type McpToolSubject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// McpToolResource names the tool that a decision covers. Type is
// "mcp_tool" and ID is "<serverId>/<tool>".
type McpToolResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// McpToolDecision is the answer to McpResource.AuthorizeTool. A deny comes
// back with Allowed set to false and a nil error.
type McpToolDecision struct {
	Allowed  bool            `json:"allowed"`
	Subject  McpToolSubject  `json:"subject"`
	Resource McpToolResource `json:"resource"`
}

// AgentMcpToolDecision is the answer to AgentsResource.AuthorizeMcpTool. A
// deny comes back with Allowed set to false and a nil error.
type AgentMcpToolDecision struct {
	Allowed  bool            `json:"allowed"`
	AgentID  string          `json:"agent_id,omitempty"`
	Resource McpToolResource `json:"resource"`
}

// ── Personal Agent Protocol ───────────────────────────────────────────

// PoppyVerification is the answer to PoppyResource.VerifyRequest: who a
// request from a personal agent is from, or the refusal to send back.
//
// Active tells the two apart. A verified result (Active true) carries
// ClientID, UserID, Session and, for a signed-in request, Account. A
// refusal (Active false) carries Error and Response; send Response to the
// personal agent unchanged with WritePoppyRefusal.
type PoppyVerification struct {
	// Active is true when LumoAuth verified the request.
	Active bool `json:"active"`

	// ClientID is the personal agent: the URL of its metadata document.
	// LumoAuth checked this value.
	ClientID string `json:"client_id,omitempty"`
	// ClientName is the name that the personal agent gives itself.
	ClientName string `json:"client_name,omitempty"`
	// UserID is the personal agent's stable name for its user at your
	// organization. It is not an account: never look an account up by it.
	UserID string `json:"user_id,omitempty"`
	// AgentID is set when the personal agent runs several agents for one
	// user and says which one this is. Empty otherwise.
	AgentID string `json:"agent_id,omitempty"`
	// Session is the Session of the request. Nil in a refusal.
	Session *PoppySession `json:"session,omitempty"`
	// SignedIn is true when the request carried a valid access token.
	SignedIn bool `json:"signed_in"`
	// Account says whose access token the request carried. Nil when the
	// request is signed out.
	Account *PoppyAccount `json:"account,omitempty"`
	// Version is the Poppy-Version of the request.
	Version string `json:"version,omitempty"`
	// Extensions are the extensions that the request declares, as name and
	// version.
	Extensions map[string]string `json:"extensions,omitempty"`

	// Error is the protocol's error code of a refusal, such as
	// "invalid_session" or "insufficient_scope".
	Error string `json:"error,omitempty"`
	// ErrorDescription explains a refusal.
	ErrorDescription string `json:"error_description,omitempty"`
	// Scope holds the scopes that a refusal asks for, space-separated.
	// Empty when the refusal names none.
	Scope string `json:"scope,omitempty"`
	// Response is the HTTP response that the personal agent must get. Nil
	// in a verified result.
	Response *PoppyRelayResponse `json:"response,omitempty"`

	// Raw is the complete decoded answer.
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON decodes a verification answer and fails closed: an answer
// that is neither a complete verified result nor a well-formed refusal is
// an error, and is never decoded as verified.
func (v *PoppyVerification) UnmarshalJSON(data []byte) error {
	parsed, err := parsePoppyVerification(data)
	if err != nil {
		return err
	}
	*v = *parsed
	return nil
}

// PoppySession is the Session of a verified request.
type PoppySession struct {
	// ID is LumoAuth's id of the Session. Store your own Session state
	// under it, such as a cart.
	ID int64 `json:"id"`
	// SID is the Session ID that the personal agent chose. GetSessionStatus
	// and EndSession take it.
	SID string `json:"sid"`
	// IsNew is true when this request started the Session.
	IsNew bool `json:"new"`
	// StartedAt is the start of the Session, as an RFC 3339 time.
	StartedAt string `json:"started_at,omitempty"`
}

// PoppyAccount describes the access token of a signed-in request.
type PoppyAccount struct {
	// Subject is the id of the user in your LumoAuth organization. Use it
	// to find the account's data.
	Subject string `json:"sub"`
	// Scope is the space-separated scope string of the access token; see
	// Scopes and HasScope.
	Scope string `json:"scope"`
	// Audience lists the services that the access token is for.
	Audience []string `json:"aud"`
	// Expires is the expiry of the access token in Unix seconds, or 0 when
	// LumoAuth sent none.
	Expires int64 `json:"exp"`
	// TokenType is "DPoP" for a token bound to a DPoP key, "Bearer"
	// otherwise.
	TokenType string `json:"token_type,omitempty"`
}

// Scopes returns the access token's scopes as a slice.
func (a *PoppyAccount) Scopes() []string {
	if a == nil {
		return nil
	}
	return splitScopes(a.Scope)
}

// HasScope reports whether the access token carries the scope.
func (a *PoppyAccount) HasScope(scope string) bool {
	for _, s := range a.Scopes() {
		if s == scope {
			return true
		}
	}
	return false
}

// PoppyRelayResponse is the HTTP response that a refused personal agent
// must get: the status, the headers and the body, exactly as LumoAuth
// worded them.
type PoppyRelayResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	// Body is the JSON object to send, or nil when the response has no
	// body. Access token errors travel in WWW-Authenticate and have none.
	Body map[string]any `json:"body"`
}

// Session states that PoppySessionStatus.Status reports.
const (
	PoppyStatusActive = "active"
	PoppyStatusEnded  = "ended"
	// PoppyStatusUnknown means that no Session has the sid: it never
	// started, or nothing used it for the idle period.
	PoppyStatusUnknown = "unknown"
)

// PoppySessionStatus is the answer to PoppyResource.GetSessionStatus.
type PoppySessionStatus struct {
	// Status is PoppyStatusActive, PoppyStatusEnded or PoppyStatusUnknown.
	Status string `json:"status"`
	// UserID is the personal agent's name for its user. Empty for an
	// unknown Session.
	UserID string `json:"user_id,omitempty"`
	// AgentID is set when the personal agent named one of several agents.
	AgentID string `json:"agent_id,omitempty"`
	// Account is the id of the account that the Session used, or "".
	Account string `json:"account,omitempty"`
	// SignedIn is true while the Session is active, it used an account,
	// and the personal agent still holds a valid refresh token for it.
	SignedIn bool `json:"signed_in"`
	// LastSeenAt is the time of the Session's last request, as an RFC 3339
	// time. Empty for an unknown Session.
	LastSeenAt string `json:"last_seen_at,omitempty"`

	// Raw is the complete decoded answer.
	Raw map[string]any `json:"-"`
}

// Active reports whether the Session still stands.
func (s *PoppySessionStatus) Active() bool { return s != nil && s.Status == PoppyStatusActive }

// UnmarshalJSON decodes a Session status and refuses an answer without a
// status or with a member of the wrong type.
func (s *PoppySessionStatus) UnmarshalJSON(data []byte) error {
	parsed, err := parsePoppySessionStatus(data)
	if err != nil {
		return err
	}
	*s = *parsed
	return nil
}
