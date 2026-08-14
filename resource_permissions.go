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
	// UserID checks on behalf of another user. Backend credentials only —
	// the endpoint otherwise defaults to the authenticated principal.
	UserID string
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
	body := checkBody(opts)
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
	body := checkBody(opts)
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
	body := checkBody(opts)
	body["permissions"] = permissions

	var result PermissionMultiCheck
	if err := r.http.call(ctx, route, nil, &request{JSON: body}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// checkBody seeds a request body with the shared optional fields.
func checkBody(opts *CheckOptions) map[string]any {
	body := map[string]any{}
	if opts == nil {
		return body
	}
	if context := copyStringMap(opts.Context); context != nil {
		body["context"] = context
	}
	if opts.UserID != "" {
		body["user_id"] = opts.UserID
	}
	return body
}
