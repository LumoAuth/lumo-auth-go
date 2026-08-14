package lumoauth

import "context"

// McpResource exchanges the caller's token for one scoped to a secured MCP
// server (RFC 8693, with the server id as the audience).
type McpResource struct {
	http *httpClient
	auth *AuthResource
}

// Token returns an access token scoped to one MCP server.
//
//	token, err := client.Mcp.Token(ctx, "urn:mcp:financial-data", "")
//
// serverID is the audience identifier of the target server. Pass an empty
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
	if serverID == "" {
		return nil, NewValidationError(
			`a server ID is required (the MCP server's audience, e.g. "urn:mcp:financial-data")`)
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
