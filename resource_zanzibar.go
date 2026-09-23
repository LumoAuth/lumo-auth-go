package lumoauth

import (
	"context"
	"strings"
)

// ZanzibarResource covers Google-Zanzibar-style relationship-based access
// control: does a subject have a relation to an object?
//
// Objects and subjects are "namespace:id" tuples — "document:readme",
// "user:alice" — and subjects may name a relation ("group:eng#member").
type ZanzibarResource struct {
	http *httpClient
}

// Common relation names, provided so the helpers below and hand-written
// checks agree on spelling.
const (
	RelationViewer = "viewer"
	RelationEditor = "editor"
	RelationOwner  = "owner"
	RelationMember = "member"
	RelationAdmin  = "admin"
)

// Check reports whether the relationship holds, directly or by inheritance.
//
//	ok, err := client.Zanzibar.Check(ctx, "document:readme", "viewer", "user:bob")
func (r *ZanzibarResource) Check(ctx context.Context, object, relation, subject string) (bool, error) {
	result, err := r.CheckDetailed(ctx, object, relation, subject)
	if err != nil {
		return false, err
	}
	return result.Allowed, nil
}

// CheckDetailed is Check with the full response.
func (r *ZanzibarResource) CheckDetailed(ctx context.Context, object, relation, subject string) (*ZanzibarCheck, error) {
	if err := validateTuple(object, relation, subject); err != nil {
		return nil, err
	}
	body := map[string]any{"object": object, "relation": relation, "subject": subject}

	var result ZanzibarCheck
	if err := r.http.call(ctx, RouteZanzibarCheck, nil, &request{JSON: body}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Expand returns the full userset tree for object#relation — every subject
// that satisfies the relation, including those reached through namespace
// rewrites.
//
// It is the inverse of Check: Check answers "does this subject have the
// relation", Expand answers "who has it at all".
//
// Expansion always reveals other subjects, so the server requires the oracle
// privilege (the authz.check permission or the authz:check scope). There is
// no self-service variant — a token that can only check itself gets a 403.
//
//	tree, err := client.Zanzibar.Expand(ctx, "document:readme", "viewer")
func (r *ZanzibarResource) Expand(ctx context.Context, object, relation string) (*ZanzibarUsersetNode, error) {
	if err := validateObjectRelation(object, relation); err != nil {
		return nil, err
	}
	body := map[string]any{"object": object, "relation": relation}

	var result zanzibarExpandResponse
	if err := r.http.call(ctx, RouteZanzibarExpand, nil, &request{JSON: body}, &result); err != nil {
		return nil, err
	}
	if result.Tree == nil {
		return nil, NewValidationError("unexpected response from LumoAuth API: missing \"tree\"")
	}
	return result.Tree, nil
}

// IsViewer reports whether the subject can view the object.
func (r *ZanzibarResource) IsViewer(ctx context.Context, object, subject string) (bool, error) {
	return r.Check(ctx, object, RelationViewer, subject)
}

// IsEditor reports whether the subject can edit the object.
func (r *ZanzibarResource) IsEditor(ctx context.Context, object, subject string) (bool, error) {
	return r.Check(ctx, object, RelationEditor, subject)
}

// IsOwner reports whether the subject owns the object.
func (r *ZanzibarResource) IsOwner(ctx context.Context, object, subject string) (bool, error) {
	return r.Check(ctx, object, RelationOwner, subject)
}

// IsMember reports whether the subject is a member of the object.
func (r *ZanzibarResource) IsMember(ctx context.Context, object, subject string) (bool, error) {
	return r.Check(ctx, object, RelationMember, subject)
}

// IsAdmin reports whether the subject administers the object.
func (r *ZanzibarResource) IsAdmin(ctx context.Context, object, subject string) (bool, error) {
	return r.Check(ctx, object, RelationAdmin, subject)
}

// validateTuple catches malformed tuples client-side, where the error can
// name the argument, rather than as an opaque 400.
func validateTuple(object, relation, subject string) error {
	if err := validateObjectRelation(object, relation); err != nil {
		return err
	}
	if subject == "" || !strings.Contains(subject, ":") {
		return NewValidationError(`subject must be in "namespace:id" or "namespace:id#relation" format`)
	}
	return nil
}

// validateObjectRelation is the half of validateTuple that Expand needs —
// it takes no subject.
func validateObjectRelation(object, relation string) error {
	if object == "" || !strings.Contains(object, ":") {
		return NewValidationError(`object must be in "namespace:id" format (e.g. "document:123")`)
	}
	if relation == "" {
		return NewValidationError(`relation is required (e.g. "viewer", "editor", "owner")`)
	}
	return nil
}
