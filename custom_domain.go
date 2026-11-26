package lumoauth

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Custom domains.
//
// An organization can serve LumoAuth on its own domain, for example
// https://auth.acme.com. On that domain:
//
//   - every route of the organization is served without the /orgs/{orgId}
//     segment: /orgs/acme-corp/api/v1/oauth/token is /api/v1/oauth/token;
//   - a route without that segment (/api/v1/authz/check) keeps its path;
//   - the prefixed paths answer 404;
//   - the issuer is the bare domain.
//
// One function holds the path rule: httpClient.resolve, which every route
// call, every built URL (authorization URL, DPoP htu, AAuth request URL)
// and the issuer go through. The rule itself is pathOnCustomDomain in
// routes.go. The behaviour is fixed by
// sdk-contract/vectors/custom-domain.json.

// EnvCustomDomain is read when the custom domain option is not passed, by
// every constructor that reads EnvBaseURL.
const EnvCustomDomain = "LUMOAUTH_CUSTOM_DOMAIN"

// normalizeCustomDomain turns the value of the custom domain option into
// an origin: "https://<lower-case host>[:port]" without a trailing slash.
//
// The value is a host name or an https:// origin. http:// is accepted only
// for localhost, 127.0.0.1 and [::1]. An empty or blank value means "not
// set" and gives "". A value with a path, a query, a fragment or
// credentials is a *ConfigError.
func normalizeCustomDomain(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	const hint = `the custom domain must be a host name or an https:// origin, for example "auth.acme.com" or "https://auth.acme.com"`

	candidate := trimmed
	if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" {
		return "", configErrorf("invalid custom domain %q: %s", trimmed, hint)
	}
	if parsed.User != nil {
		return "", configErrorf("invalid custom domain %q: it must not carry credentials", trimmed)
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", configErrorf(
			"invalid custom domain %q: it must not carry a path. On a custom domain no path has an /orgs/… segment, and the SDK adds /api/v1 itself",
			trimmed)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.ContainsAny(trimmed, "?#") {
		return "", configErrorf("invalid custom domain %q: it must not carry a query or a fragment", trimmed)
	}

	host := strings.ToLower(parsed.Host)
	hostname := strings.ToLower(parsed.Hostname())
	if strings.ContainsAny(hostname, " \t/\\@") {
		return "", configErrorf("invalid custom domain %q: %s", trimmed, hint)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if hostname != "localhost" && hostname != "127.0.0.1" && hostname != "::1" {
			return "", configErrorf(
				"invalid custom domain %q: http:// is accepted only for localhost, 127.0.0.1 and [::1]", trimmed)
		}
	default:
		return "", configErrorf("invalid custom domain %q: %s", trimmed, hint)
	}
	return strings.ToLower(parsed.Scheme) + "://" + host, nil
}

// customDomainFrom resolves the custom domain of a constructor: the option
// value, or $LUMOAUTH_CUSTOM_DOMAIN when the option is empty or blank. It
// returns "" when neither is set.
func customDomainFrom(option string) (string, error) {
	if strings.TrimSpace(option) == "" {
		option = os.Getenv(EnvCustomDomain)
	}
	return normalizeCustomDomain(option)
}

// customDomainSource is implemented by a TokenSource or a
// ConfidentialClient that addresses its organization on a custom domain.
// *Agent implements it. NewJITContext and NewDelegationChain ask for it,
// so the clients that they build follow the same rule as their source.
type customDomainSource interface {
	// CustomDomain returns the custom domain, or "" when none is set.
	CustomDomain() string
}

// customDomainOf returns the normalized custom domain of a source that has
// one, or "".
func customDomainOf(source any) (string, error) {
	if withDomain, ok := source.(customDomainSource); ok {
		return normalizeCustomDomain(withDomain.CustomDomain())
	}
	return "", nil
}

// ownOrgTransport removes the /orgs/{orgId} segment of the client's own
// organization from requests to the custom domain. APIConfig installs it
// for the generated OpenAPI client, whose paths always carry the segment.
type ownOrgTransport struct {
	base   http.RoundTripper
	origin *url.URL
	client *httpClient
}

func (t *ownOrgTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.URL == nil || !strings.EqualFold(req.URL.Scheme, t.origin.Scheme) || !strings.EqualFold(req.URL.Host, t.origin.Host) {
		return base.RoundTrip(req)
	}
	stripped := t.client.ownPath(req.URL.EscapedPath())
	if stripped == req.URL.EscapedPath() {
		return base.RoundTrip(req)
	}
	// A RoundTripper must not change the request that it was given.
	clone := req.Clone(req.Context())
	unescaped, err := url.PathUnescape(stripped)
	if err != nil {
		return base.RoundTrip(req)
	}
	clone.URL.Path, clone.URL.RawPath = unescaped, stripped
	return base.RoundTrip(clone)
}

// generatedClientHTTP is the *http.Client that APIConfig hands to the
// generated OpenAPI client. On a custom domain with a known organization
// ID it is a copy whose transport removes that organization's /orgs/…
// segment; otherwise it is the client's own.
func (c *httpClient) generatedClientHTTP() *http.Client {
	if c.customDomain == "" || c.orgID == "" {
		return c.doer
	}
	origin, err := url.Parse(c.customDomain)
	if err != nil {
		return c.doer
	}
	wrapped := *c.doer
	wrapped.Transport = &ownOrgTransport{base: c.doer.Transport, origin: origin, client: c}
	return &wrapped
}
