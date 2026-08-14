package lumoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Auth-token verification for resource servers.
//
// VerifyAuthToken checks an `auth+jwt` against the issuing organization's
// JWKS plus typ, iss, aud, and exp — the same checks the LumoAuth server
// performs, revocation excepted.
//
// AAuth auth tokens are proof-of-possession tokens. Verifying the JWT is
// only half the job: the resource MUST also verify the request's RFC 9421
// signature against the key in cnf.jwk. Claims.VerifyProofOfPossession
// does that second half.

// AAuthClaims are the claims carried by an `auth+jwt`.
type AAuthClaims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	JTI      string `json:"jti"`
	Subject  string `json:"sub,omitempty"`
	// Agent identifies the agent the token was issued to.
	Agent string `json:"agent,omitempty"`
	// AgentDelegate is set when the agent acts for another agent.
	AgentDelegate string `json:"agent_delegate,omitempty"`
	Scope         string `json:"scope,omitempty"`
	// Confirmation binds the token to the holder's key (RFC 7800).
	Confirmation struct {
		JWK JWK `json:"jwk"`
	} `json:"cnf"`
	// Act records the delegation chain, when there is one.
	Act map[string]any `json:"act,omitempty"`

	// Raw is every claim in the token, including ones not modelled above.
	Raw map[string]any `json:"-"`
}

// Scopes splits the space-separated scope claim.
func (c *AAuthClaims) Scopes() []string { return splitScopes(c.Scope) }

// HasScope reports whether the token carries a scope.
func (c *AAuthClaims) HasScope(scope string) bool {
	for _, granted := range c.Scopes() {
		if granted == scope {
			return true
		}
	}
	return false
}

// VerifyOptions configures VerifyAuthToken.
type VerifyOptions struct {
	// Issuer is the trusted issuer URL, e.g.
	// "https://app.lumoauth.dev/orgs/acme-corp/api/v1". Required.
	Issuer string
	// Resource is your resource identifier; it must equal the token's
	// audience. Required.
	Resource string
	// JWKS supplies the issuer's keys directly, skipping the fetch. Use
	// it with a cache in front of a hot path.
	JWKS *JWKS
	// HTTPClient fetches the JWKS. Defaults to a 30s-timeout client.
	HTTPClient *http.Client
	// ClockSkew tolerated on the expiry check. Default: 0, like the server.
	ClockSkew time.Duration
}

// VerifyAuthToken verifies an AAuth auth token against the issuing
// organization's JWKS and returns its claims.
//
//	claims, err := lumoauth.VerifyAuthToken(ctx, bearer, lumoauth.VerifyOptions{
//	    Issuer:   "https://app.lumoauth.dev/orgs/acme-corp/api/v1",
//	    Resource: "https://api.example.com",
//	})
//	if err != nil {
//	    return err
//	}
//	// Then enforce proof-of-possession over the incoming request:
//	if err := claims.VerifyProofOfPossession(r, body); err != nil {
//	    return err
//	}
//
// HMAC and "none" algorithms are always rejected, and the algorithm must
// match the key type published in the JWKS.
func VerifyAuthToken(ctx context.Context, token string, opts VerifyOptions) (*AAuthClaims, error) {
	if opts.Issuer == "" {
		return nil, NewConfigError("Issuer is required to verify an auth token")
	}
	if opts.Resource == "" {
		return nil, NewConfigError("Resource is required to verify an auth token")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, NewValidationError("invalid JWT: expected three dot-separated segments")
	}

	header, err := decodeJWTSegment(parts[0])
	if err != nil {
		return nil, err
	}
	if typ, _ := header["typ"].(string); typ != "auth+jwt" {
		return nil, validationErrorf("unexpected token type %q: expected auth+jwt", header["typ"])
	}
	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)
	if alg == "" || kid == "" {
		return nil, NewValidationError("the JOSE header is missing alg or kid")
	}

	claimsMap, err := decodeJWTSegment(parts[1])
	if err != nil {
		return nil, err
	}
	// Check the issuer before fetching anything from it.
	if issuer, _ := claimsMap["iss"].(string); issuer != opts.Issuer {
		return nil, validationErrorf("untrusted issuer %q", claimsMap["iss"])
	}

	jwks := opts.JWKS
	if jwks == nil {
		if jwks, err = FetchIssuerJWKS(ctx, opts.Issuer, opts.HTTPClient); err != nil {
			return nil, err
		}
	}
	jwk, found := jwks.Find(kid)
	if !found {
		return nil, validationErrorf("no key with kid %q in the issuer JWKS", kid)
	}
	if !algMatchesKeyType(alg, jwk.Kty) {
		return nil, validationErrorf("algorithm %s is incompatible with key type %s", alg, jwk.Kty)
	}
	if jwk.Alg != "" && jwk.Alg != alg {
		return nil, validationErrorf("algorithm %s does not match the key's declared alg %s", alg, jwk.Alg)
	}

	publicKey, err := jwk.PublicKey()
	if err != nil {
		return nil, err
	}
	signature, err := b64urlDecode(parts[2])
	if err != nil {
		return nil, NewValidationError("could not decode the JWT signature: " + err.Error())
	}
	if !verifyJWS(alg, []byte(parts[0]+"."+parts[1]), signature, publicKey) {
		return nil, NewValidationError("signature verification failed")
	}

	// Temporal and audience checks come after the signature, as on the
	// server: never trust claim values from an unverified token.
	var claims AAuthClaims
	if err := json.Unmarshal([]byte(mustJSON(claimsMap)), &claims); err != nil {
		return nil, NewValidationError("could not decode the token claims: " + err.Error())
	}
	claims.Raw = claimsMap

	if claims.Expires == 0 {
		return nil, NewValidationError("the token has no exp claim")
	}
	if time.Now().Add(-opts.ClockSkew).Unix() > claims.Expires {
		return nil, NewValidationError("the auth token has expired")
	}
	if claims.Audience != opts.Resource {
		return nil, validationErrorf("invalid audience %q: this resource is %q",
			claims.Audience, opts.Resource)
	}
	if claims.Confirmation.JWK.Kty == "" {
		return nil, NewValidationError("the token has no cnf.jwk claim, so it cannot be bound to a key")
	}
	return &claims, nil
}

// VerifyProofOfPossession checks that an incoming request was signed by the
// key the token is bound to (cnf.jwk) — the second half of AAuth
// verification, without which a stolen token would be replayable.
//
// body must be the exact bytes the request carried, since Content-Digest
// is computed over them.
func (c *AAuthClaims) VerifyProofOfPossession(r *http.Request, body []byte) error {
	if c.Confirmation.JWK.Kty == "" {
		return NewValidationError("the token has no cnf.jwk claim to verify against")
	}

	signatureInput := r.Header.Get("Signature-Input")
	signatureHeader := r.Header.Get("Signature")
	if signatureInput == "" || signatureHeader == "" {
		return NewValidationError("the request carries no RFC 9421 signature")
	}

	components, created, nonce, err := parseSignatureInput(signatureInput)
	if err != nil {
		return err
	}
	signature, err := parseSignatureHeader(signatureHeader)
	if err != nil {
		return err
	}

	// Content-Digest must match the body actually received, or an
	// attacker could replay a signature over different content.
	if digest := r.Header.Get("Content-Digest"); digest != "" {
		if digest != ContentDigestSHA256(body) {
			return NewValidationError("Content-Digest does not match the request body")
		}
	}

	// The AAuth profile covers @authority and @path, never the scheme.
	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}

	values := map[string]string{
		"@method":        strings.ToUpper(r.Method),
		"@authority":     strings.ToLower(r.Host),
		"@path":          path,
		"@query":         query,
		"signature-key":  r.Header.Get("Signature-Key"),
		"content-digest": r.Header.Get("Content-Digest"),
		"content-type":   r.Header.Get("Content-Type"),
		"authorization":  r.Header.Get("Authorization"),
	}

	publicKey, err := c.Confirmation.JWK.PublicKey()
	if err != nil {
		return err
	}
	base := BuildSignatureBase(components, values, created, nonce)
	if !VerifySignatureBase(base, signature, publicKey) {
		return NewValidationError("proof-of-possession signature verification failed")
	}
	return nil
}

// FetchIssuerJWKS retrieves an AAuth issuer's signing keys from
// {issuer}/aauth/jwks.json.
func FetchIssuerJWKS(ctx context.Context, issuer string, httpClient *http.Client) (*JWKS, error) {
	transport := newHTTPClient(strings.TrimRight(issuer, "/"))
	transport.userAgent = userAgent()
	if httpClient != nil {
		transport.doer = httpClient
	}

	var jwks JWKS
	if err := transport.do(ctx, http.MethodGet, "/aauth/jwks.json", &request{NoAuth: true}, &jwks); err != nil {
		return nil, err
	}
	if len(jwks.Keys) == 0 {
		return nil, NewValidationError("the issuer JWKS contains no keys")
	}
	return &jwks, nil
}

// JWKSCache caches an issuer's JWKS for a TTL, so a busy resource server
// verifies tokens without fetching keys on every request. The zero value
// is not usable — build one with NewJWKSCache.
type JWKSCache struct {
	issuer     string
	ttl        time.Duration
	httpClient *http.Client

	mu        sync.Mutex
	keys      *JWKS
	expiresAt time.Time
}

// NewJWKSCache builds a cache for one issuer. A ttl of 0 means one hour.
func NewJWKSCache(issuer string, ttl time.Duration, httpClient *http.Client) *JWKSCache {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &JWKSCache{issuer: issuer, ttl: ttl, httpClient: httpClient}
}

// Get returns the cached key set, fetching it when absent or stale.
func (c *JWKSCache) Get(ctx context.Context) (*JWKS, error) {
	c.mu.Lock()
	if c.keys != nil && time.Now().Before(c.expiresAt) {
		keys := c.keys
		c.mu.Unlock()
		return keys, nil
	}
	c.mu.Unlock()

	keys, err := FetchIssuerJWKS(ctx, c.issuer, c.httpClient)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.keys = keys
	c.expiresAt = time.Now().Add(c.ttl)
	c.mu.Unlock()
	return keys, nil
}

// Invalidate drops the cached keys, forcing the next Get to refetch. Call
// it when verification fails on an unknown kid — the issuer may have
// rotated keys mid-TTL.
func (c *JWKSCache) Invalidate() {
	c.mu.Lock()
	c.keys = nil
	c.expiresAt = time.Time{}
	c.mu.Unlock()
}

// ── Internal ──────────────────────────────────────────────────────────

// decodeJWTSegment base64url-decodes one JWT segment as a JSON object.
func decodeJWTSegment(segment string) (map[string]any, error) {
	decoded, err := b64urlDecode(segment)
	if err != nil {
		return nil, NewValidationError("could not base64url-decode the JWT segment: " + err.Error())
	}
	var parsed map[string]any
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		return nil, NewValidationError("could not decode the JWT segment as JSON: " + err.Error())
	}
	return parsed, nil
}

// mustJSON re-encodes a decoded claim map. The input came from
// json.Unmarshal, so it always round-trips.
func mustJSON(value map[string]any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

// parseSignatureInput reads a Signature-Input header value of the form
//
//	sig1=("@method" "@authority" …);created=1700000000;nonce="…"
func parseSignatureInput(header string) (components []string, created int64, nonce string, err error) {
	open := strings.Index(header, "(")
	close := strings.Index(header, ")")
	if open < 0 || close < open {
		return nil, 0, "", NewValidationError("malformed Signature-Input: no covered component list")
	}

	for _, field := range strings.Fields(header[open+1 : close]) {
		components = append(components, strings.Trim(field, `"`))
	}

	for _, param := range strings.Split(header[close+1:], ";") {
		name, value, found := strings.Cut(strings.TrimSpace(param), "=")
		if !found {
			continue
		}
		value = strings.Trim(value, `"`)
		switch name {
		case "created":
			var seconds int64
			for _, char := range value {
				if char < '0' || char > '9' {
					return nil, 0, "", NewValidationError("malformed Signature-Input: non-numeric created")
				}
				seconds = seconds*10 + int64(char-'0')
			}
			created = seconds
		case "nonce":
			nonce = value
		}
	}
	if created == 0 || nonce == "" {
		return nil, 0, "", NewValidationError("malformed Signature-Input: created and nonce are both required")
	}
	return components, created, nonce, nil
}

// parseSignatureHeader reads a Signature header value of the form
// `sig1=:<base64url>:`.
func parseSignatureHeader(header string) (string, error) {
	_, value, found := strings.Cut(header, "=")
	if !found {
		return "", NewValidationError("malformed Signature header")
	}
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, ":") || !strings.HasSuffix(value, ":") || len(value) < 2 {
		return "", NewValidationError("malformed Signature header: expected a :…: byte sequence")
	}
	return value[1 : len(value)-1], nil
}
