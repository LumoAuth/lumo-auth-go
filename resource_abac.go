package lumoauth

import (
	"context"
	"encoding/json"
	"net/url"
)

// AbacResource covers attribute-based access control: policy evaluation
// from user, resource, and environment attributes, plus attribute
// management.
//
// ABAC is org-scoped, so the client needs an org ID.
//
// Note the wire format uses camelCase keys (resourceType, resourceId);
// this resource takes Go-shaped params and translates.
type AbacResource struct {
	http *httpClient
}

// AbacCheckParams describes one ABAC evaluation.
type AbacCheckParams struct {
	// ResourceType is the kind of thing being accessed ("document"). Required.
	ResourceType string
	// Action is the operation ("read", "delete"). Required.
	Action string
	// ResourceID identifies the specific instance, when there is one.
	ResourceID string
	// Context supplies resource and environment attributes for the
	// evaluation, e.g. {"environment": {"ip": "10.0.0.1"}}.
	Context map[string]any
}

func (p AbacCheckParams) body() (map[string]any, error) {
	if p.ResourceType == "" {
		return nil, NewValidationError("ResourceType is required for an ABAC check")
	}
	if p.Action == "" {
		return nil, NewValidationError("Action is required for an ABAC check")
	}
	body := map[string]any{"resourceType": p.ResourceType, "action": p.Action}
	if p.ResourceID != "" {
		body["resourceId"] = p.ResourceID
	}
	if context := copyStringMap(p.Context); context != nil {
		body["context"] = context
	}
	return body, nil
}

// Check evaluates the policies for one resource/action pair and returns the
// full decision, including the policies that matched.
func (r *AbacResource) Check(ctx context.Context, params AbacCheckParams) (*AbacDecision, error) {
	body, err := params.body()
	if err != nil {
		return nil, err
	}
	var decision AbacDecision
	if err := r.http.call(ctx, RouteAbacCheck, nil, &request{JSON: body}, &decision); err != nil {
		return nil, err
	}
	return &decision, nil
}

// IsAllowed is Check reduced to a boolean.
func (r *AbacResource) IsAllowed(ctx context.Context, params AbacCheckParams) (bool, error) {
	decision, err := r.Check(ctx, params)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// AbacMaxBulkRequests is the server's cap on one bulk check.
const AbacMaxBulkRequests = 100

// CheckBulk evaluates up to AbacMaxBulkRequests pairs in one round trip.
// Results come back in request order.
func (r *AbacResource) CheckBulk(ctx context.Context, checks []AbacCheckParams) ([]AbacDecision, error) {
	if len(checks) == 0 {
		return nil, NewValidationError("at least one check request is required")
	}
	if len(checks) > AbacMaxBulkRequests {
		return nil, validationErrorf("a bulk check accepts at most %d requests (got %d)",
			AbacMaxBulkRequests, len(checks))
	}

	requests := make([]map[string]any, 0, len(checks))
	for i, check := range checks {
		body, err := check.body()
		if err != nil {
			return nil, validationErrorf("check %d: %s", i, err.Error())
		}
		requests = append(requests, body)
	}

	var result AbacBulkDecision
	if err := r.http.call(ctx, RouteAbacCheckBulk, nil,
		&request{JSON: map[string]any{"requests": requests}}, &result); err != nil {
		return nil, err
	}
	return result.Results, nil
}

// MyAttributes returns every ABAC attribute for the authenticated user,
// built-in and custom.
func (r *AbacResource) MyAttributes(ctx context.Context) (map[string]any, error) {
	var attributes map[string]any
	if err := r.http.call(ctx, RouteAbacMyAttributes, nil, nil, &attributes); err != nil {
		return nil, err
	}
	return attributes, nil
}

// SetUserAttribute sets one attribute value on a user.
func (r *AbacResource) SetUserAttribute(ctx context.Context, userID, attributeSlug string, value any) error {
	if userID == "" || attributeSlug == "" {
		return NewValidationError("userID and attributeSlug are both required")
	}
	params := map[string]string{"userId": userID, "attributeSlug": attributeSlug}
	return r.http.call(ctx, RouteAbacSetUserAttribute, params,
		&request{JSON: map[string]any{"value": value}}, nil)
}

// ResourceAttributes returns the ABAC attributes attached to one resource.
func (r *AbacResource) ResourceAttributes(ctx context.Context, resourceType, resourceID string) (map[string]any, error) {
	if resourceType == "" || resourceID == "" {
		return nil, NewValidationError("resourceType and resourceID are both required")
	}
	params := map[string]string{"resourceType": resourceType, "resourceId": resourceID}
	var attributes map[string]any
	if err := r.http.call(ctx, RouteAbacResourceAttributes, params, nil, &attributes); err != nil {
		return nil, err
	}
	return attributes, nil
}

// SetResourceAttribute sets one attribute value on a resource.
func (r *AbacResource) SetResourceAttribute(ctx context.Context, resourceType, resourceID, attributeSlug string, value any) error {
	if resourceType == "" || resourceID == "" || attributeSlug == "" {
		return NewValidationError("resourceType, resourceID and attributeSlug are all required")
	}
	params := map[string]string{
		"resourceType":  resourceType,
		"resourceId":    resourceID,
		"attributeSlug": attributeSlug,
	}
	return r.http.call(ctx, RouteAbacSetResourceAttribute, params,
		&request{JSON: map[string]any{"value": value}}, nil)
}

// Attribute definition types accepted by AttributeDefinitions.
const (
	AttributeTypeUser        = "user"
	AttributeTypeResource    = "resource"
	AttributeTypeEnvironment = "environment"
)

// AttributeDefinitions lists the org's attribute definitions. Pass an empty
// attributeType for all of them.
func (r *AbacResource) AttributeDefinitions(ctx context.Context, attributeType string) ([]AbacAttributeDefinition, error) {
	req := &request{}
	if attributeType != "" {
		req.Query = url.Values{"type": []string{attributeType}}
	}

	// The endpoint returns either a bare array or an envelope with `data`.
	var raw json.RawMessage
	if err := r.http.call(ctx, RouteAbacAttributeDefinitions, nil, req, &raw); err != nil {
		return nil, err
	}

	var definitions []AbacAttributeDefinition
	if err := json.Unmarshal(raw, &definitions); err == nil {
		return definitions, nil
	}
	var envelope struct {
		Data []AbacAttributeDefinition `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, NewValidationError(
			"could not decode the attribute definitions response: " + err.Error())
	}
	return envelope.Data, nil
}
