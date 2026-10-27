package lumoauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// McpResource covers secured MCP servers. Token exchanges the caller's
// token for one bound to a single MCP server (RFC 8693 token exchange).
// AuthorizeTool lets an MCP server ask whether a caller may run one tool.
type McpResource struct {
	http *httpClient
	auth *AuthResource
}

// Token returns an access token bound to one MCP server.
//
//	token, err := client.Mcp.Token(ctx, "https://mcp.example.com/mcp", "")
//
// serverID is the Resource URI that the MCP server is registered with in
// LumoAuth. It is an https URL, and the SDK sends it as the RFC 8707
// `resource` parameter. The token names exactly one MCP server, and LumoAuth
// sets the token's `aud` from this value. A plain-http URL is accepted only
// for localhost and private hosts. Pass an empty subjectToken to exchange
// the client's own bearer token.
//
// The token works only at that MCP server. LumoAuth's own API refuses it.
// This method does not send a DPoP proof, so an MCP server that requires
// DPoP needs a DPoP-bound exchange instead.
func (r *McpResource) Token(ctx context.Context, serverID, subjectToken string) (string, error) {
	result, err := r.TokenDetailed(ctx, serverID, subjectToken)
	if err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

// TokenDetailed is Token with the full token response — lifetime, type,
// and granted scope.
func (r *McpResource) TokenDetailed(ctx context.Context, serverID, subjectToken string) (*McpToken, error) {
	if err := validateMcpServerID(serverID); err != nil {
		return nil, err
	}

	token := subjectToken
	if token == "" {
		resolved, err := r.http.bearerToken(ctx)
		if err != nil {
			return nil, err
		}
		token = resolved
	}
	if token == "" {
		return nil, NewConfigError(
			"MCP token exchange needs a subject token — authenticate first, or pass one explicitly")
	}

	response, err := r.auth.TokenExchange(ctx, TokenExchangeParams{
		SubjectToken: token,
		Resource:     serverID,
		Audience:     serverID,
	})
	if err != nil {
		return nil, err
	}
	return &McpToken{
		AccessToken: response.AccessToken,
		TokenType:   response.TokenType,
		ExpiresIn:   response.ExpiresIn,
		Scope:       response.Scope,
	}, nil
}

// validateMcpServerID checks that serverID can serve as an RFC 8707
// resource: an absolute http(s) URI with a host and no fragment. The server
// enforces the stricter rule (https, or http only for localhost and
// private hosts) and answers 400 invalid_target otherwise.
func validateMcpServerID(serverID string) error {
	const hint = `the MCP server ID must be the server's https URL (its RFC 8707 resource identifier), e.g. "https://mcp.example.com/mcp"`
	if serverID == "" {
		return NewValidationError("a server ID is required: " + hint)
	}
	u, err := url.Parse(serverID)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Fragment != "" || u.RawFragment != "" {
		return validationErrorf("invalid MCP server ID %q: %s", serverID, hint)
	}
	return nil
}

// McpToolAuthorizeParams describes one per-tool question that an MCP server
// asks about a caller it has already verified.
type McpToolAuthorizeParams struct {
	// ServerID is the registered MCP server ID, for example
	// "mcp_0123456789abcdef01234567". It is not the Resource URI. Required.
	ServerID string
	// SubjectType is "user" or "agent". Required.
	SubjectType string
	// SubjectID is the `sub` claim of the verified MCP token. For a user it
	// is the user ID. For an agent it may be the agent ID ("agt_…") or the
	// `sub` claim as is ("agent_agt_…"). Required.
	SubjectID string
	// Tool is the name of the MCP tool. Required.
	Tool string
}

// AuthorizeTool asks whether a user or an agent may run one tool on an MCP
// server. The MCP server calls it after it has verified the caller's token.
//
// The client must authenticate with the MCP server's own client-credentials
// token, which needs the mcp:authorize scope. The server's OAuth client must
// also be one of the MCP server's tool authorizers. Never pass the caller's
// token here: the MCP specification forbids token passthrough.
//
// NewAgent runs the client-credentials grant and keeps the token fresh, so
// it works for the MCP server's own client too:
//
//	mcpAuth, err := lumoauth.NewAgent(lumoauth.AgentConfig{
//	    OrgID: "acme-corp", ClientID: mcpClientID, ClientSecret: mcpClientSecret,
//	    Scopes: []string{"mcp:authorize"},
//	})
//	// handle err
//	decision, err := mcpAuth.Mcp.AuthorizeTool(ctx, lumoauth.McpToolAuthorizeParams{
//	    ServerID:    "mcp_0123456789abcdef01234567",
//	    SubjectType: "user",
//	    SubjectID:   verifiedSub, // the `sub` claim of the verified MCP token
//	    Tool:        "send_invoice",
//	})
//
// A deny is not an error. It comes back with Allowed set to false and a nil
// error. A 403 without an `allowed` key, such as insufficient_scope, is an
// error that matches ErrPermissionDenied.
func (r *McpResource) AuthorizeTool(ctx context.Context, params McpToolAuthorizeParams) (*McpToolDecision, error) {
	if params.SubjectType != "user" && params.SubjectType != "agent" {
		return nil, validationErrorf("the subject type must be \"user\" or \"agent\", got %q", params.SubjectType)
	}
	if params.SubjectID == "" {
		return nil, NewValidationError("a subject ID is required")
	}
	if err := validateMcpToolTarget(params.ServerID, params.Tool); err != nil {
		return nil, err
	}

	body := map[string]any{
		"subject": map[string]any{"type": params.SubjectType, "id": params.SubjectID},
		"tool":    params.Tool,
	}
	var decision McpToolDecision
	err := callMcpDecision(ctx, r.http, RouteMcpAuthorizeTool,
		map[string]string{"serverId": params.ServerID}, body, &decision)
	if err != nil {
		return nil, err
	}
	return &decision, nil
}

// validateMcpToolTarget checks a registered MCP server ID and a tool name
// before they reach the wire.
func validateMcpToolTarget(serverID, tool string) error {
	if serverID == "" {
		return NewValidationError(`a server ID is required: pass the registered MCP server ID, e.g. "mcp_0123456789abcdef01234567"`)
	}
	if tool == "" {
		return NewValidationError("a tool name is required")
	}
	if strings.ContainsAny(serverID, "/:#*") {
		return validationErrorf(
			"invalid MCP server ID %q: pass the registered server ID (e.g. \"mcp_0123456789abcdef01234567\"), not its URL", serverID)
	}
	if strings.ContainsAny(tool, "/:#*") {
		return validationErrorf("invalid tool name %q: it must not contain '/', ':', '#' or '*'", tool)
	}
	if len([]rune(tool)) > 80 {
		return validationErrorf("the tool name is %d characters long; the limit is 80", len([]rune(tool)))
	}
	return nil
}

// callMcpDecision sends a per-tool question. A 403 whose JSON body has
// "allowed": false is a deny decision: it is decoded into out and no error
// is returned. Every other failure keeps the usual error mapping.
func callMcpDecision(ctx context.Context, h *httpClient, route string, params map[string]string, body map[string]any, out any) error {
	err := h.call(ctx, route, params, &request{JSON: body}, out)
	if err == nil {
		return nil
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		return err
	}
	decoded, ok := apiErr.Body.(map[string]any)
	if !ok {
		return err
	}
	if allowed, present := decoded["allowed"].(bool); !present || allowed {
		return err
	}
	raw, marshalErr := json.Marshal(decoded)
	if marshalErr != nil {
		return err
	}
	if json.Unmarshal(raw, out) != nil {
		return err
	}
	return nil
}
