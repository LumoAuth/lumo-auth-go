package lumoauth

import (
	"context"
	"net/url"
)

// McpResource exchanges the caller's token for one bound to a secured MCP
// server (RFC 8693 token exchange). The server's URL goes in the RFC 8707
// `resource` parameter, which sets the issued token's `aud`.
type McpResource struct {
	http *httpClient
	auth *AuthResource
}

// Token returns an access token bound to one MCP server.
//
//	token, err := client.Mcp.Token(ctx, "https://mcp.example.com/mcp", "")
//
// serverID is the MCP server's https URL, which is its RFC 8707 resource
// identifier. LumoAuth sets the token's `aud` from it. A plain-http URL is
// accepted only for localhost and private hosts. Pass an empty
// subjectToken to exchange the client's own bearer token.
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
