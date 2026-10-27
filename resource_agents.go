package lumoauth

import "context"

// AgentsResource covers agent identity: the Ask API for preflight
// authorization, self-inspection, and registration.
type AgentsResource struct {
	http *httpClient
}

// Ask asks whether the agent may perform an action. It is the preflight
// check to run before an LLM tool call, and it writes an audit record
// whichever way the decision goes.
//
// The keys ip, userAgent, requestMethod and requestPath in actionContext
// always describe the request LumoAuth received. A value you pass under one
// of those names is kept under pep instead, as in ABAC.
//
//	decision, err := client.Agents.Ask(ctx, "document.read", map[string]any{"id": "doc_99"})
//	if err != nil {
//	    return err
//	}
//	if !decision.Allowed {
//	    return fmt.Errorf("refused: %s", decision.Reason)
//	}
func (r *AgentsResource) Ask(ctx context.Context, action string, actionContext map[string]any) (*AgentAskResult, error) {
	if action == "" {
		return nil, NewValidationError("an action is required")
	}
	body := map[string]any{"action": action}
	if context := copyStringMap(actionContext); context != nil {
		body["context"] = context
	}

	var result AgentAskResult
	if err := r.http.call(ctx, RouteAgentsAsk, nil, &request{JSON: body}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// IsAllowed is Ask reduced to a boolean.
func (r *AgentsResource) IsAllowed(ctx context.Context, action string, actionContext map[string]any) (bool, error) {
	result, err := r.Ask(ctx, action, actionContext)
	if err != nil {
		return false, err
	}
	return result.Allowed, nil
}

// Me returns the calling agent's own identity, capabilities, and workspace.
//
// For an agent credential, Capabilities lists the agent's capability roles.
// A user access token without the authz:read scope gets an empty list.
func (r *AgentsResource) Me(ctx context.Context) (*AgentIdentity, error) {
	var identity AgentIdentity
	if err := r.http.call(ctx, RouteAgentsMe, nil, nil, &identity); err != nil {
		return nil, err
	}
	return &identity, nil
}

// AuthorizeMcpTool asks whether the calling agent may run one tool on an
// MCP server. It uses the agent's own credential, so it suits an agent that
// checks a tool before it calls it. An MCP server must not use it, because
// it would have to forward the agent's token; the server calls
// Mcp.AuthorizeTool with its own token instead.
//
// serverID is the registered MCP server ID, for example
// "mcp_0123456789abcdef01234567". It is not the Resource URI.
//
//	decision, err := agent.Agents.AuthorizeMcpTool(ctx, "mcp_0123456789abcdef01234567", "send_invoice")
//	if err != nil {
//	    return err
//	}
//	if !decision.Allowed {
//	    return errors.New("tool refused")
//	}
//
// A deny is not an error. It comes back with Allowed set to false and a nil
// error. An unknown server is an error that matches ErrNotFound.
func (r *AgentsResource) AuthorizeMcpTool(ctx context.Context, serverID, tool string) (*AgentMcpToolDecision, error) {
	if err := validateMcpToolTarget(serverID, tool); err != nil {
		return nil, err
	}
	body := map[string]any{"server_id": serverID, "tool": tool}
	var decision AgentMcpToolDecision
	if err := callMcpDecision(ctx, r.http, RouteAgentsAuthorizeMcpTool, nil, body, &decision); err != nil {
		return nil, err
	}
	return &decision, nil
}

// RegisterParams describes an agent registration.
type RegisterParams struct {
	// Name is the human-readable agent name ("Document Analyser"). Required.
	Name string
	// ClientID is the OAuth client identifying the agent. Required.
	ClientID string
	// Description explains what the agent is for.
	Description string
	// Capabilities are the slugs the agent declares
	// (e.g. "read:documents", "tool:search_web").
	Capabilities []string
	// JWKSURI points at the agent's public JWKS. Required for AAuth and
	// other proof-of-possession flows.
	JWKSURI string
}

// Register creates or updates the agent's record in the organization
// directory.
func (r *AgentsResource) Register(ctx context.Context, params RegisterParams) (*AgentRegistration, error) {
	if params.Name == "" {
		return nil, NewValidationError("Name is required to register an agent")
	}
	if params.ClientID == "" {
		return nil, NewValidationError("ClientID is required to register an agent")
	}
	body := map[string]any{"name": params.Name, "client_id": params.ClientID}
	if params.Description != "" {
		body["description"] = params.Description
	}
	if len(params.Capabilities) > 0 {
		body["capabilities"] = params.Capabilities
	}
	if params.JWKSURI != "" {
		body["jwks_uri"] = params.JWKSURI
	}

	var registration AgentRegistration
	if err := r.http.call(ctx, RouteAgentsRegister, nil, &request{JSON: body}, &registration); err != nil {
		return nil, err
	}
	return &registration, nil
}

// Info returns the agent's claims from the UserInfo endpoint, which carries
// capabilities and the budget policy for agent principals.
func (r *AgentsResource) Info(ctx context.Context) (*UserInfo, error) {
	var info UserInfo
	if err := r.http.call(ctx, RouteOAuthUserInfo, nil, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Capabilities returns the capability slugs granted to the agent.
func (r *AgentsResource) Capabilities(ctx context.Context) ([]string, error) {
	info, err := r.Info(ctx)
	if err != nil {
		return nil, err
	}
	return info.Capabilities, nil
}

// Budget returns the agent's budget policy. The result is never nil: an
// agent with no policy gets an empty one, which reports Exhausted() false.
func (r *AgentsResource) Budget(ctx context.Context) (*AgentBudget, error) {
	info, err := r.Info(ctx)
	if err != nil {
		return nil, err
	}
	if info.BudgetPolicy == nil {
		return &AgentBudget{}, nil
	}
	return info.BudgetPolicy, nil
}
