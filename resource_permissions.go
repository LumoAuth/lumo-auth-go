package lumoauth

import "context"

// PermissionsResource covers RBAC permission checks for the authenticated
// principal: single checks, bulk checks, logical combinations, and listing.
//
// The endpoints infer the organization from the credential, so this
// namespace works without an org ID.
type PermissionsResource struct {
	http *httpClient
}

// CheckOptions carries the optional arguments shared by every check.
type CheckOptions struct {
	// Context supplies attributes for ABAC evaluation alongside the RBAC
	// decision.
	Context map[string]any
	// UserID asks about another user instead of the caller. It must be the
	// user's LumoAuth ID (a UUID) in the caller's organization. The SDK sends
	// it as the request's subject, {"type": "user", "id": UserID}.
	//
	// Asking about someone other than yourself needs the authz:check scope
	// (on the API key or the access token) or the authz.check permission.
	// Without it the server answers 403 INSUFFICIENT_PERMISSIONS; an unknown
	// ID gets 404 SUBJECT_NOT_FOUND. Leave it empty to check the caller.
	UserID string
	// AgentID asks about an agent (its agt_… ID) instead of the caller, with
	// the same authz:check rule as UserID. Set at most one of the two.
	AgentID string
}

// Check reports whether the principal holds a permission.
//
//	ok, err := client.Permissions.Check(ctx, "document.edit", nil)
func (r *PermissionsResource) Check(ctx context.Context, permission string, opts *CheckOptions) (bool, error) {
	result, err := r.CheckDetailed(ctx, permission, opts)
	if err != nil {
		return false, err
	}
	return result.Allowed, nil
}

// CheckDetailed is Check with the full response — the permission slug, the
// principal it was evaluated for, and the context echoed back.
func (r *PermissionsResource) CheckDetailed(ctx context.Context, permission string, opts *CheckOptions) (*PermissionCheck, error) {
	if permission == "" {
		return nil, NewValidationError("a permission slug is required")
	}
	body, err := checkBody(opts)
	if err != nil {
		return nil, err
	}
	body["permission"] = permission

	var result PermissionCheck
	if err := r.http.call(ctx, RoutePermissionsCheck, nil, &request{JSON: body}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckBulk evaluates many permissions in one round trip; the Results map
// holds one decision per requested slug.
func (r *PermissionsResource) CheckBulk(ctx context.Context, permissions []string, opts *CheckOptions) (*PermissionBulkCheck, error) {
	if len(permissions) == 0 {
		return nil, NewValidationError("at least one permission is required")
	}
	body, err := checkBody(opts)
	if err != nil {
		return nil, err
	}
	body["permissions"] = permissions

	var result PermissionBulkCheck
	if err := r.http.call(ctx, RoutePermissionsCheckBulk, nil, &request{JSON: body}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckAny reports whether the principal holds at least one of the
// permissions (logical OR).
func (r *PermissionsResource) CheckAny(ctx context.Context, permissions []string, opts *CheckOptions) (bool, error) {
	result, err := r.CheckAnyDetailed(ctx, permissions, opts)
	if err != nil {
		return false, err
	}
	return result.Allowed, nil
}

// CheckAnyDetailed is CheckAny with the full response.
func (r *PermissionsResource) CheckAnyDetailed(ctx context.Context, permissions []string, opts *CheckOptions) (*PermissionMultiCheck, error) {
	return r.multiCheck(ctx, RoutePermissionsCheckAny, permissions, opts)
}

// CheckAll reports whether the principal holds every one of the
// permissions (logical AND).
func (r *PermissionsResource) CheckAll(ctx context.Context, permissions []string, opts *CheckOptions) (bool, error) {
	result, err := r.CheckAllDetailed(ctx, permissions, opts)
	if err != nil {
		return false, err
	}
	return result.Allowed, nil
}

// CheckAllDetailed is CheckAll with the full response.
func (r *PermissionsResource) CheckAllDetailed(ctx context.Context, permissions []string, opts *CheckOptions) (*PermissionMultiCheck, error) {
	return r.multiCheck(ctx, RoutePermissionsCheckAll, permissions, opts)
}

// List returns every permission granted to the authenticated principal.
//
// A user access token needs the authz:read scope (or the blanket admin
// scope). Organization API keys cannot hold that scope, so with an API key
// List fails with an *APIError whose RequiredScopes is ["authz:read"].
func (r *PermissionsResource) List(ctx context.Context) (*PermissionList, error) {
	var result PermissionList
	if err := r.http.call(ctx, RoutePermissionsList, nil, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListSlugs returns just the permission slugs granted to the principal.
func (r *PermissionsResource) ListSlugs(ctx context.Context) ([]string, error) {
	result, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	slugs := make([]string, 0, len(result.Permissions))
	for _, permission := range result.Permissions {
		if permission.Slug != "" {
			slugs = append(slugs, permission.Slug)
		}
	}
	return slugs, nil
}

func (r *PermissionsResource) multiCheck(ctx context.Context, route string, permissions []string, opts *CheckOptions) (*PermissionMultiCheck, error) {
	if len(permissions) == 0 {
		return nil, NewValidationError("at least one permission is required")
	}
	body, err := checkBody(opts)
	if err != nil {
		return nil, err
	}
	body["permissions"] = permissions

	var result PermissionMultiCheck
	if err := r.http.call(ctx, route, nil, &request{JSON: body}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// checkBody seeds a request body with the shared optional fields. The
// checked subject goes in "subject": the server ignores a top-level
// "user_id" and would answer for the caller instead.
func checkBody(opts *CheckOptions) (map[string]any, error) {
	body := map[string]any{}
	if opts == nil {
		return body, nil
	}
	if context := copyStringMap(opts.Context); context != nil {
		body["context"] = context
	}
	switch {
	case opts.UserID != "" && opts.AgentID != "":
		return nil, NewValidationError("set CheckOptions.UserID or CheckOptions.AgentID, not both")
	case opts.UserID != "":
		body["subject"] = map[string]any{"type": "user", "id": opts.UserID}
	case opts.AgentID != "":
		body["subject"] = map[string]any{"type": "agent", "id": opts.AgentID}
	}
	return body, nil
}
