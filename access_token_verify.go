package lumoauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Access-token verification for resource servers — MCP servers in
// particular.
//
// VerifyAccessToken checks a LumoAuth core access token (`at+jwt`, RFC
// 9068) the way the LumoAuth server itself does, revocation excepted: the
// JWS signature against the organization's JWKS, the issuer, the audience
// (your resource URI), the time window, the token_use marker, and — for a
// sender-constrained token — the DPoP proof that accompanies it (RFC
// 9449). VerifyAuthToken is the AAuth (`auth+jwt`) counterpart and stays
// separate: the two token formats share no claims beyond iss/aud/exp.

// AccessTokenClaims are the claims of a verified LumoAuth access token.
type AccessTokenClaims struct {
	Issuer string `json:"iss"`
	// Subject is "agent_agt_…" for an agent, a user id for a user token or a
	// delegated token.
	Subject   string        `json:"sub"`
	Audience  AudienceClaim `json:"aud"`
	Expires   int64         `json:"exp"`
	NotBefore int64         `json:"nbf,omitempty"`
	IssuedAt  int64         `json:"iat,omitempty"`
	JTI       string        `json:"jti"`
	// ClientID is the OAuth client that obtained the token.
	ClientID string `json:"client_id,omitempty"`
	// Scope is the space-separated scope string; see Scopes and HasScope.
	Scope string `json:"scope,omitempty"`
	// IsAgent is true for tokens issued to an agent identity.
	IsAgent bool `json:"is_agent,omitempty"`
	// Capabilities are the agent's capability slugs, when IsAgent.
	Capabilities []string `json:"capabilities,omitempty"`
	// Act is the RFC 8693 actor claim of a delegated token: the agent acting
	// for Subject, with any deeper sub-agents nested in Act.Act.
	Act *ActorClaim `json:"act,omitempty"`
	// Confirmation is the RFC 7800 key binding; JKT is set for a DPoP-bound
	// token.
	Confirmation *TokenConfirmation `json:"cnf,omitempty"`
	// TokenUse marks special-purpose tokens. "test" tokens are refused.
	TokenUse string `json:"token_use,omitempty"`

	// Raw is every claim in the token, including ones not modelled above.
	Raw map[string]any `json:"-"`
}

// ActorClaim is one link of a delegation chain (`act`).
type ActorClaim struct {
	Subject        string `json:"sub"`
	Issuer         string `json:"iss,omitempty"`
	SubjectProfile string `json:"sub_profile,omitempty"`
	Name           string `json:"name,omitempty"`
	// Act is the next actor down the chain, when there is one.
	Act *ActorClaim `json:"act,omitempty"`
}

// TokenConfirmation is the `cnf` claim.
type TokenConfirmation struct {
	// JKT is the RFC 7638 thumbprint of the DPoP key the token is bound to.
	JKT string `json:"jkt,omitempty"`
}

// AudienceClaim is a JWT `aud` claim, which may be a string or an array.
type AudienceClaim []string

// UnmarshalJSON accepts a single string or an array of strings.
func (a *AudienceClaim) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = AudienceClaim{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("aud must be a string or an array of strings")
	}
	*a = AudienceClaim(many)
	return nil
}

// Contains reports whether the audience names value.
func (a AudienceClaim) Contains(value string) bool {
	for _, aud := range a {
		if aud == value {
			return true
		}
	}
	return false
}

// Scopes splits the space-separated scope claim.
func (c *AccessTokenClaims) Scopes() []string { return splitScopes(c.Scope) }

// HasScope reports whether the token carries a scope.
func (c *AccessTokenClaims) HasScope(scope string) bool {
	for _, granted := range c.Scopes() {
		if granted == scope {
			return true
		}
	}
	return false
}

// HasCapability reports whether an agent token carries a capability.
func (c *AccessTokenClaims) HasCapability(capability string) bool {
	for _, held := range c.Capabilities {
		if held == capability {
			return true
		}
	}
	return false
}

// IsDPoPBound reports whether the token is sender-constrained (cnf.jkt).
func (c *AccessTokenClaims) IsDPoPBound() bool {
	return c.Confirmation != nil && c.Confirmation.JKT != ""
}

// ActorChain returns the `sub` of each actor in the delegation chain,
// outermost first: the agent acting for Subject, then its sub-agents. It
// is empty for a token with no `act` claim.
func (c *AccessTokenClaims) ActorChain() []string {
	var chain []string
	for act := c.Act; act != nil; act = act.Act {
		if act.Subject != "" {
			chain = append(chain, act.Subject)
		}
	}
	return chain
}

// Rejection reasons carried by the *ValidationError that VerifyAccessToken
// returns, in ValidationError.Reason. They are stable; match on them rather
// than on the message.
const (
	TokenRejectedMalformed    = "malformed"
	TokenRejectedType         = "wrong_type"
	TokenRejectedAlgorithm    = "bad_algorithm"
	TokenRejectedIssuer       = "wrong_issuer"
	TokenRejectedUnknownKey   = "unknown_key"
	TokenRejectedSignature    = "bad_signature"
	TokenRejectedExpired      = "expired"
	TokenRejectedNotYetValid  = "not_yet_valid"
	TokenRejectedAudience     = "wrong_audience"
	TokenRejectedTestToken    = "test_token"
	TokenRejectedDPoPRequired = "dpop_required"
	TokenRejectedDPoPScheme   = "dpop_scheme"
	TokenRejectedDPoPProof    = "dpop_proof"
	TokenRejectedDPoPBinding  = "dpop_binding"
	TokenRejectedDPoPReplay   = "dpop_replay"
)

// RejectionReason returns the TokenRejected* reason carried by err, or ""
// when err is not a token rejection.
func RejectionReason(err error) string {
	var verr *ValidationError
	if errors.As(err, &verr) {
		return verr.Reason
	}
	return ""
}

// rejectToken builds the *ValidationError for a failed verification.
func rejectToken(reason, message string) *ValidationError {
	err := NewValidationError(message)
	err.Reason = reason
	return err
}

// DPoPRequest describes the incoming request a DPoP-bound token arrived
// with, so the proof can be checked against it. Build one with
// DPoPRequestFromHTTP.
type DPoPRequest struct {
	// Method is the HTTP method of the request.
	Method string
	// URL is the absolute request URL. Query and fragment are ignored.
	URL string
	// Proof is the value of the DPoP header ("" when absent).
	Proof string
	// Scheme is the Authorization scheme the token came with: "DPoP" or
	// "Bearer".
	Scheme string
}

// DPoPRequestFromHTTP reads the DPoP-relevant parts of an incoming request.
// The scheme of the URL is https when the connection is TLS or an
// X-Forwarded-Proto header says so, http otherwise; the host is r.Host.
// Behind a proxy that rewrites the host, set DPoPRequest.URL yourself.
func DPoPRequestFromHTTP(r *http.Request) *DPoPRequest {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = strings.ToLower(strings.TrimSpace(strings.Split(forwarded, ",")[0]))
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	authScheme, _, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	return &DPoPRequest{
		Method: r.Method,
		URL:    scheme + "://" + r.Host + path,
		Proof:  r.Header.Get(DPoPHeader),
		Scheme: authScheme,
	}
}

// ReplayCache remembers DPoP proof identifiers so a captured proof cannot
// be presented twice. Seen records jti and reports whether it was already
// present; entries may be forgotten after ttl. Implementations must be
// safe for concurrent use. A shared store (Redis, say) is the right choice
// for a resource server with several replicas.
type ReplayCache interface {
	Seen(jti string, ttl time.Duration) bool
}

// MemoryReplayCache is an in-process ReplayCache. The zero value is ready
// to use.
type MemoryReplayCache struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	nextGC  time.Time
	now     func() time.Time
	maxSize int
}

// NewMemoryReplayCache returns an empty in-process replay cache.
func NewMemoryReplayCache() *MemoryReplayCache { return &MemoryReplayCache{} }

// Seen implements ReplayCache.
func (c *MemoryReplayCache) Seen(jti string, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	current := now()
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	if current.After(c.nextGC) || (c.maxSize > 0 && len(c.seen) >= c.maxSize) {
		for key, expires := range c.seen {
			if current.After(expires) {
				delete(c.seen, key)
			}
		}
		c.nextGC = current.Add(ttl)
	}
	if expires, ok := c.seen[jti]; ok && current.Before(expires) {
		return true
	}
	if c.maxSize > 0 && len(c.seen) >= c.maxSize {
		// Fail closed: a flooded cache must not turn into a replay window.
		return true
	}
	c.seen[jti] = current.Add(ttl)
	return false
}

// defaultReplayCache backs VerifyAccessToken when no ReplayCache is given.
var defaultReplayCache = &MemoryReplayCache{maxSize: 100_000}

// AccessTokenVerifyOptions configures VerifyAccessToken.
type AccessTokenVerifyOptions struct {
	// Issuer is the organization's issuer URL, e.g.
	// "https://app.lumoauth.dev/orgs/acme-corp/api/v1". Required.
	Issuer string
	// Resource is this server's resource URI — the value the MCP server is
	// registered with and the token's `aud` must name. Required.
	Resource string
	// JWKS supplies the issuer's keys directly. When nil, the keys are
	// fetched through the issuer's discovery document and cached (KeyCache,
	// or a process-wide cache per issuer), with one refetch on an unknown
	// kid.
	JWKS *JWKS
	// KeyCache is the cache to fetch keys through when JWKS is nil.
	KeyCache *AccessTokenKeyCache
	// HTTPClient fetches discovery and keys. Defaults to a 30s-timeout
	// client.
	HTTPClient *http.Client
	// ClockSkew tolerated on exp, nbf and the proof's iat. The default (0)
	// means 60 seconds; a negative value means no tolerance.
	ClockSkew time.Duration
	// RequireDPoP rejects tokens that are not sender-constrained. Set it
	// when the MCP server is registered with "Require DPoP".
	RequireDPoP bool
	// DPoP describes the request the token arrived with. Required for a
	// DPoP-bound token; RequireAccessToken fills it from the request.
	DPoP *DPoPRequest
	// ReplayCache stores proof identifiers. Defaults to a process-wide
	// in-memory cache.
	ReplayCache ReplayCache
}

// Verification windows shared with the server.
const (
	defaultTokenClockSkew = 60 * time.Second
	// dpopProofMaxAge is how far in the past a proof's iat may lie.
	dpopProofMaxAge = 300 * time.Second
	// dpopProofMaxFuture is how far in the future a proof's iat may lie.
	dpopProofMaxFuture = 60 * time.Second
	// dpopReplayTTL is how long a proof jti is remembered.
	dpopReplayTTL = 300 * time.Second
)

// VerifyAccessToken verifies a LumoAuth access token for this resource and
// returns its claims.
//
//	claims, err := lumoauth.VerifyAccessToken(ctx, token, lumoauth.AccessTokenVerifyOptions{
//	    Issuer:   "https://app.lumoauth.dev/orgs/acme-corp/api/v1",
//	    Resource: "https://mcp.example.com/mcp",
//	    DPoP:     lumoauth.DPoPRequestFromHTTP(r),
//	})
//
// It checks, in order: the compact JWS shape; the `typ` header (at+jwt);
// the algorithm (RSA and EC families only — HMAC and none are refused, and
// the algorithm must match the published key); `iss`; the signature; `exp`
// and `nbf`; `aud` contains Resource; `token_use` is not "test"; and, for a
// token with cnf.jkt, the DPoP proof: scheme, signature, htm/htu, iat
// window, ath, key thumbprint and jti replay.
//
// Failures are a *ValidationError whose Reason is a TokenRejected*
// constant. Fetch failures are *NetworkError or *APIError.
func VerifyAccessToken(ctx context.Context, token string, opts AccessTokenVerifyOptions) (*AccessTokenClaims, error) {
	if opts.Issuer == "" {
		return nil, NewConfigError("Issuer is required to verify an access token")
	}
	if opts.Resource == "" {
		return nil, NewConfigError("Resource is required to verify an access token")
	}
	skew := opts.ClockSkew
	if skew == 0 {
		skew = defaultTokenClockSkew
	} else if skew < 0 {
		skew = 0
	}
	issuer := strings.TrimRight(opts.Issuer, "/")

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, rejectToken(TokenRejectedMalformed, "invalid JWT: expected three dot-separated segments")
	}
	header, err := decodeJWTSegment(parts[0])
	if err != nil {
		return nil, rejectToken(TokenRejectedMalformed, err.Error())
	}
	typ, _ := header["typ"].(string)
	if typ != "at+jwt" && typ != "application/at+jwt" {
		return nil, rejectToken(TokenRejectedType,
			fmt.Sprintf("unexpected token type %q: expected at+jwt", typ))
	}
	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)
	if alg == "" || kid == "" {
		return nil, rejectToken(TokenRejectedMalformed, "the JOSE header is missing alg or kid")
	}
	if !accessTokenAlgAllowed(alg) {
		return nil, rejectToken(TokenRejectedAlgorithm,
			fmt.Sprintf("algorithm %q is not accepted for access tokens", alg))
	}

	claimsMap, err := decodeJWTSegment(parts[1])
	if err != nil {
		return nil, rejectToken(TokenRejectedMalformed, err.Error())
	}
	// Check the issuer before fetching anything from it.
	if iss, _ := claimsMap["iss"].(string); strings.TrimRight(iss, "/") != issuer {
		return nil, rejectToken(TokenRejectedIssuer, fmt.Sprintf("untrusted issuer %q", claimsMap["iss"]))
	}

	jwk, err := accessTokenKey(ctx, kid, issuer, opts)
	if err != nil {
		return nil, err
	}
	if !algMatchesKeyType(alg, jwk.Kty) {
		return nil, rejectToken(TokenRejectedAlgorithm,
			fmt.Sprintf("algorithm %s is incompatible with key type %s", alg, jwk.Kty))
	}
	if jwk.Alg != "" && jwk.Alg != alg {
		return nil, rejectToken(TokenRejectedAlgorithm,
			fmt.Sprintf("algorithm %s does not match the key's declared alg %s", alg, jwk.Alg))
	}
	publicKey, err := jwk.PublicKey()
	if err != nil {
		return nil, rejectToken(TokenRejectedUnknownKey, err.Error())
	}
	signature, err := b64urlDecode(parts[2])
	if err != nil {
		return nil, rejectToken(TokenRejectedMalformed, "could not decode the JWT signature: "+err.Error())
	}
	if !verifyJWS(alg, []byte(parts[0]+"."+parts[1]), signature, publicKey) {
		return nil, rejectToken(TokenRejectedSignature, "signature verification failed")
	}

	// Claim checks come after the signature, as on the server: never act
	// on claim values from an unverified token.
	var claims AccessTokenClaims
	if err := json.Unmarshal([]byte(mustJSON(claimsMap)), &claims); err != nil {
		return nil, rejectToken(TokenRejectedMalformed, "could not decode the token claims: "+err.Error())
	}
	claims.Raw = claimsMap

	now := time.Now()
	if claims.Expires == 0 {
		return nil, rejectToken(TokenRejectedExpired, "the token has no exp claim")
	}
	if now.Add(-skew).Unix() >= claims.Expires {
		return nil, rejectToken(TokenRejectedExpired, "the access token has expired")
	}
	if claims.NotBefore != 0 && now.Add(skew).Unix() < claims.NotBefore {
		return nil, rejectToken(TokenRejectedNotYetValid, "the access token is not valid yet (nbf)")
	}
	if !claims.Audience.Contains(opts.Resource) {
		return nil, rejectToken(TokenRejectedAudience,
			fmt.Sprintf("invalid audience %v: this resource is %q", []string(claims.Audience), opts.Resource))
	}
	if claims.TokenUse == "test" {
		return nil, rejectToken(TokenRejectedTestToken,
			"this is a test token (token_use=test); resource servers must refuse it")
	}
	if claims.Subject == "" {
		return nil, rejectToken(TokenRejectedMalformed, "the token has no sub claim")
	}

	if !claims.IsDPoPBound() {
		if opts.RequireDPoP {
			return nil, rejectToken(TokenRejectedDPoPRequired,
				"this resource requires DPoP-bound tokens, and the token has no cnf.jkt")
		}
		return &claims, nil
	}
	if err := verifyDPoPBinding(token, claims.Confirmation.JKT, opts, skew, now); err != nil {
		return nil, err
	}
	return &claims, nil
}

// accessTokenAlgAllowed lists the JWS algorithms a LumoAuth access token
// may be signed with.
func accessTokenAlgAllowed(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
		return true
	default:
		return false
	}
}

// accessTokenKey finds the signing key for kid: in the supplied JWKS, or
// through a cache with one refetch on an unknown kid.
func accessTokenKey(ctx context.Context, kid, issuer string, opts AccessTokenVerifyOptions) (*JWK, error) {
	if opts.JWKS != nil {
		if jwk, found := opts.JWKS.Find(kid); found {
			return jwk, nil
		}
		return nil, rejectToken(TokenRejectedUnknownKey,
			fmt.Sprintf("no key with kid %q in the supplied JWKS", kid))
	}
	cache := opts.KeyCache
	if cache == nil {
		cache = sharedAccessTokenKeyCache(issuer, opts.HTTPClient)
	}
	keys, err := cache.Get(ctx)
	if err != nil {
		return nil, err
	}
	if jwk, found := keys.Find(kid); found {
		return jwk, nil
	}
	// The issuer may have rotated keys since the last fetch: refetch once.
	cache.Invalidate()
	if keys, err = cache.Get(ctx); err != nil {
		return nil, err
	}
	if jwk, found := keys.Find(kid); found {
		return jwk, nil
	}
	return nil, rejectToken(TokenRejectedUnknownKey,
		fmt.Sprintf("no key with kid %q in the issuer JWKS", kid))
}

// verifyDPoPBinding checks the proof that accompanies a bound token.
func verifyDPoPBinding(token, jkt string, opts AccessTokenVerifyOptions, skew time.Duration, now time.Time) error {
	req := opts.DPoP
	if req == nil {
		return rejectToken(TokenRejectedDPoPRequired,
			"the token is DPoP-bound (cnf.jkt), but no DPoP request details were given — pass AccessTokenVerifyOptions.DPoP")
	}
	if !strings.EqualFold(req.Scheme, DPoPTokenType) {
		return rejectToken(TokenRejectedDPoPScheme,
			fmt.Sprintf("a DPoP-bound token must be presented with the DPoP authorization scheme, not %q", req.Scheme))
	}
	if req.Proof == "" {
		return rejectToken(TokenRejectedDPoPProof, "the request carries no DPoP proof")
	}

	parts := strings.Split(req.Proof, ".")
	if len(parts) != 3 {
		return rejectToken(TokenRejectedDPoPProof, "invalid DPoP proof: expected three dot-separated segments")
	}
	header, err := decodeJWTSegment(parts[0])
	if err != nil {
		return rejectToken(TokenRejectedDPoPProof, "invalid DPoP proof header: "+err.Error())
	}
	if typ, _ := header["typ"].(string); typ != "dpop+jwt" {
		return rejectToken(TokenRejectedDPoPProof, fmt.Sprintf("unexpected DPoP proof type %q", typ))
	}
	alg, _ := header["alg"].(string)
	if !dpopAlgAllowed(alg) {
		return rejectToken(TokenRejectedDPoPProof, fmt.Sprintf("DPoP proof algorithm %q is not accepted", alg))
	}
	rawJWK, ok := header["jwk"].(map[string]any)
	if !ok {
		return rejectToken(TokenRejectedDPoPProof, "the DPoP proof header has no jwk")
	}
	if _, private := rawJWK["d"]; private {
		return rejectToken(TokenRejectedDPoPProof, "the DPoP proof jwk carries a private key")
	}
	var jwk JWK
	if err := json.Unmarshal([]byte(mustJSON(rawJWK)), &jwk); err != nil {
		return rejectToken(TokenRejectedDPoPProof, "invalid DPoP proof jwk: "+err.Error())
	}
	if !algMatchesKeyType(alg, jwk.Kty) || !dpopCurveMatches(alg, jwk) {
		return rejectToken(TokenRejectedDPoPProof,
			fmt.Sprintf("DPoP proof algorithm %s does not match the jwk (%s %s)", alg, jwk.Kty, jwk.Crv))
	}
	if jwk.Alg != "" && jwk.Alg != alg {
		return rejectToken(TokenRejectedDPoPProof, "the DPoP proof jwk declares a different alg")
	}
	publicKey, err := jwk.PublicKey()
	if err != nil {
		return rejectToken(TokenRejectedDPoPProof, "invalid DPoP proof jwk: "+err.Error())
	}
	signature, err := b64urlDecode(parts[2])
	if err != nil {
		return rejectToken(TokenRejectedDPoPProof, "could not decode the DPoP proof signature")
	}
	if !verifyJWS(alg, []byte(parts[0]+"."+parts[1]), signature, publicKey) {
		return rejectToken(TokenRejectedDPoPProof, "DPoP proof signature verification failed")
	}

	// The key in the proof must be the key the token is bound to. Checked
	// right after the signature so no later claim is read from a proof
	// signed by the wrong key.
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		return rejectToken(TokenRejectedDPoPProof, err.Error())
	}
	if subtle.ConstantTimeCompare([]byte(thumbprint), []byte(jkt)) != 1 {
		return rejectToken(TokenRejectedDPoPBinding, "the DPoP proof key does not match the token's cnf.jkt")
	}

	claims, err := decodeJWTSegment(parts[1])
	if err != nil {
		return rejectToken(TokenRejectedDPoPProof, "invalid DPoP proof claims: "+err.Error())
	}
	htm, _ := claims["htm"].(string)
	if !strings.EqualFold(htm, req.Method) || htm == "" {
		return rejectToken(TokenRejectedDPoPProof,
			fmt.Sprintf("DPoP proof htm %q does not match the request method %s", htm, req.Method))
	}
	htu, _ := claims["htu"].(string)
	expectedHTU, err := dpopHTU(req.URL)
	if err != nil {
		return err
	}
	if gotHTU, err := dpopHTU(htu); err != nil || gotHTU != expectedHTU {
		return rejectToken(TokenRejectedDPoPProof,
			fmt.Sprintf("DPoP proof htu %q does not match the request URL %s", htu, expectedHTU))
	}
	iat, ok := jsonInt64(claims["iat"])
	if !ok {
		return rejectToken(TokenRejectedDPoPProof, "the DPoP proof has no iat claim")
	}
	if iat > now.Add(dpopProofMaxFuture+skew).Unix() || iat < now.Add(-dpopProofMaxAge-skew).Unix() {
		return rejectToken(TokenRejectedDPoPProof, "the DPoP proof iat is outside the accepted window")
	}
	ath, _ := claims["ath"].(string)
	if ath == "" {
		return rejectToken(TokenRejectedDPoPProof, "the DPoP proof has no ath claim")
	}
	if subtle.ConstantTimeCompare([]byte(ath), []byte(DPoPAccessTokenHash(token))) != 1 {
		return rejectToken(TokenRejectedDPoPProof, "the DPoP proof ath does not match the presented token")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return rejectToken(TokenRejectedDPoPProof, "the DPoP proof has no jti claim")
	}
	cache := opts.ReplayCache
	if cache == nil {
		cache = defaultReplayCache
	}
	// Scope the identifier to the key: two clients may pick the same jti.
	if cache.Seen(thumbprint+":"+jti, dpopReplayTTL) {
		return rejectToken(TokenRejectedDPoPReplay, "the DPoP proof has already been used (jti replay)")
	}
	return nil
}

func dpopAlgAllowed(alg string) bool {
	for _, allowed := range dpopProofAlgorithms {
		if alg == allowed {
			return true
		}
	}
	return false
}

// dpopCurveMatches enforces the curve a proof algorithm requires.
func dpopCurveMatches(alg string, jwk JWK) bool {
	switch alg {
	case "ES256":
		return jwk.Crv == "P-256"
	case "ES384":
		return jwk.Crv == "P-384"
	case "ES512":
		return jwk.Crv == "P-521"
	case "EdDSA":
		return jwk.Crv == "Ed25519"
	default:
		return true
	}
}

// jsonInt64 reads an integer claim decoded as float64 by encoding/json.
func jsonInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

// ── Key discovery ─────────────────────────────────────────────────────

// FetchAccessTokenJWKS retrieves an organization's token-signing keys: it
// reads jwks_uri from {issuer}/.well-known/openid-configuration and fetches
// that document.
func FetchAccessTokenJWKS(ctx context.Context, issuer string, httpClient *http.Client) (*JWKS, error) {
	issuer = strings.TrimRight(issuer, "/")
	if _, err := url.ParseRequestURI(issuer); err != nil {
		return nil, configErrorf("invalid issuer URL %q", issuer)
	}
	transport := newHTTPClient(issuer)
	transport.userAgent = userAgent()
	if httpClient != nil {
		transport.doer = httpClient
	}

	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := transport.do(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", &request{NoAuth: true}, &discovery); err != nil {
		return nil, err
	}
	if discovery.JWKSURI == "" {
		return nil, NewValidationError("the discovery document has no jwks_uri")
	}
	// Only follow a jwks_uri that stays with the issuer: a discovery
	// document pointing elsewhere must not become a key-injection path.
	if !sameOrigin(discovery.JWKSURI, issuer) {
		return nil, validationErrorf("the discovery document's jwks_uri %q is not on the issuer's origin", discovery.JWKSURI)
	}

	var jwks JWKS
	if err := transport.do(ctx, http.MethodGet, discovery.JWKSURI, &request{NoAuth: true}, &jwks); err != nil {
		return nil, err
	}
	if len(jwks.Keys) == 0 {
		return nil, NewValidationError("the issuer JWKS contains no keys")
	}
	return &jwks, nil
}

func sameOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// AccessTokenKeyCache caches an organization's token-signing keys for a
// TTL. Build one with NewAccessTokenKeyCache and pass it as
// AccessTokenVerifyOptions.KeyCache, or let VerifyAccessToken use its
// process-wide cache.
type AccessTokenKeyCache struct {
	issuer     string
	ttl        time.Duration
	httpClient *http.Client

	mu        sync.Mutex
	keys      *JWKS
	expiresAt time.Time
}

// NewAccessTokenKeyCache builds a cache for one issuer. A ttl of 0 means
// one hour.
func NewAccessTokenKeyCache(issuer string, ttl time.Duration, httpClient *http.Client) *AccessTokenKeyCache {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &AccessTokenKeyCache{issuer: strings.TrimRight(issuer, "/"), ttl: ttl, httpClient: httpClient}
}

// Get returns the cached key set, fetching it when absent or stale.
func (c *AccessTokenKeyCache) Get(ctx context.Context) (*JWKS, error) {
	c.mu.Lock()
	if c.keys != nil && time.Now().Before(c.expiresAt) {
		keys := c.keys
		c.mu.Unlock()
		return keys, nil
	}
	c.mu.Unlock()

	keys, err := FetchAccessTokenJWKS(ctx, c.issuer, c.httpClient)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.keys = keys
	c.expiresAt = time.Now().Add(c.ttl)
	c.mu.Unlock()
	return keys, nil
}

// Invalidate drops the cached keys, forcing the next Get to refetch.
func (c *AccessTokenKeyCache) Invalidate() {
	c.mu.Lock()
	c.keys = nil
	c.expiresAt = time.Time{}
	c.mu.Unlock()
}

var (
	sharedKeyCachesMu sync.Mutex
	sharedKeyCaches   = map[string]*AccessTokenKeyCache{}
)

// sharedAccessTokenKeyCache returns the process-wide cache for an issuer.
func sharedAccessTokenKeyCache(issuer string, httpClient *http.Client) *AccessTokenKeyCache {
	sharedKeyCachesMu.Lock()
	defer sharedKeyCachesMu.Unlock()
	if cache, ok := sharedKeyCaches[issuer]; ok {
		return cache
	}
	cache := NewAccessTokenKeyCache(issuer, 0, httpClient)
	sharedKeyCaches[issuer] = cache
	return cache
}

// ── net/http middleware ───────────────────────────────────────────────

type accessTokenContextKey struct{}

// AccessTokenFromContext returns the claims RequireAccessToken stored for
// the request.
func AccessTokenFromContext(ctx context.Context) (*AccessTokenClaims, bool) {
	claims, ok := ctx.Value(accessTokenContextKey{}).(*AccessTokenClaims)
	return claims, ok
}

// ContextWithAccessToken stores verified claims in a context, for handlers
// that verify tokens themselves but share downstream code with
// RequireAccessToken.
func ContextWithAccessToken(ctx context.Context, claims *AccessTokenClaims) context.Context {
	return context.WithValue(ctx, accessTokenContextKey{}, claims)
}

// RequireAccessToken is net/http middleware that verifies the LumoAuth
// access token on every request and stores its claims in the context —
// the guard for an MCP server built on net/http:
//
//	protect := lumoauth.RequireAccessToken(lumoauth.AccessTokenVerifyOptions{
//	    Issuer:   "https://app.lumoauth.dev/orgs/acme-corp/api/v1",
//	    Resource: "https://mcp.example.com/mcp",
//	})
//	mux.Handle("/mcp", protect(mcpHandler))
//
//	// in mcpHandler:
//	claims, _ := lumoauth.AccessTokenFromContext(r.Context())
//
// The token is read from the Authorization header (Bearer or DPoP scheme)
// and, for a bound token, the DPoP header is checked against the request
// (opts.DPoP is filled from each request; DPoPRequestFromHTTP documents
// how the URL is derived). A missing or invalid token gets 401 with a
// WWW-Authenticate challenge (RFC 6750 and RFC 9449 §7.1) and a JSON body
// {"error": "invalid_token", "error_description": …}. When opts.JWKS is
// nil the middleware keeps one key cache for the issuer.
func RequireAccessToken(opts AccessTokenVerifyOptions) func(http.Handler) http.Handler {
	if opts.JWKS == nil && opts.KeyCache == nil {
		opts.KeyCache = NewAccessTokenKeyCache(opts.Issuer, 0, opts.HTTPClient)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
			token = strings.TrimSpace(token)
			if token == "" || (!strings.EqualFold(scheme, "Bearer") && !strings.EqualFold(scheme, DPoPTokenType)) {
				writeTokenChallenge(w, opts, "", "")
				return
			}
			perRequest := opts
			perRequest.DPoP = DPoPRequestFromHTTP(r)
			claims, err := VerifyAccessToken(r.Context(), token, perRequest)
			if err != nil {
				writeTokenChallenge(w, opts, "invalid_token", err.Error())
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithAccessToken(r.Context(), claims)))
		})
	}
}

// writeTokenChallenge answers 401 with the RFC 6750 / RFC 9449 challenges.
func writeTokenChallenge(w http.ResponseWriter, opts AccessTokenVerifyOptions, errorCode, description string) {
	realm := strings.ReplaceAll(opts.Resource, `"`, "")
	params := `realm="` + realm + `"`
	if errorCode != "" {
		params += `, error="` + errorCode + `", error_description="` + strings.ReplaceAll(description, `"`, "'") + `"`
	}
	algs := `algs="` + strings.Join(dpopProofAlgorithms, " ") + `"`
	if opts.RequireDPoP {
		w.Header().Add("WWW-Authenticate", "DPoP "+params+", "+algs)
	} else {
		w.Header().Add("WWW-Authenticate", "Bearer "+params)
		w.Header().Add("WWW-Authenticate", "DPoP "+algs)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	body := map[string]string{"error": "invalid_token"}
	if errorCode == "" {
		body["error_description"] = "an access token is required"
	} else {
		body["error_description"] = description
	}
	_ = json.NewEncoder(w).Encode(body)
}
