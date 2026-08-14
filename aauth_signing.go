package lumoauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// RFC 9421 HTTP Message Signing, profiled for AAuth.
//
// The LumoAuth agent token endpoint enforces a strict profile (AAuth 1.0 §4):
//
//   - Covered components: @method @authority @path signature-key
//     content-digest content-type authorization — plus @query if and only
//     if the target URI has a query string.
//   - Signature-Input parameters: exactly `created` (within ±60s of the
//     server clock) and a fresh `nonce` (≥12 bytes of entropy, base64url).
//   - Content-Digest per RFC 9530 using STANDARD base64 (sha-256=:…:).
//   - The Signature value is base64url-encoded (label=:…:).
//   - Algorithms are dispatched by key type — Ed25519 or RSA-PSS-SHA512
//     (MGF1-SHA512, 64-byte salt). No `alg` parameter is declared.
//
// The output is byte-compatible with the JS and Python SDKs.

// AAuthCoveredComponents are the components the agent token endpoint
// requires, in order. @query is inserted after @path when the target URI
// carries a query string.
var AAuthCoveredComponents = []string{
	"@method",
	"@authority",
	"@path",
	"signature-key",
	"content-digest",
	"content-type",
	"authorization",
}

// signatureLabel is the label under which the signature is published.
const signatureLabel = "sig1"

// SignOptions configures SignRequest.
type SignOptions struct {
	// Body is the exact request body being signed. Empty means no body.
	Body []byte
	// ContentType is the media type of the body.
	// Defaults to "application/json".
	ContentType string
	// AgentToken is the `agent+jwt` presented in the Agent-Auth header. It
	// travels outside the signature.
	AgentToken string
	// Authorization is the value of a covered Authorization header, when
	// the request carries one (proof-of-possession requests do).
	Authorization string
	// SignatureKey is the value of a covered Signature-Key header.
	SignatureKey string
	// Created overrides the signature timestamp. Testing only — the server
	// rejects timestamps more than 60s from its own clock.
	Created int64
	// Nonce overrides the generated nonce. Testing only — the server
	// treats nonces as single-use.
	Nonce string
}

// ContentDigestSHA256 computes an RFC 9530 Content-Digest header value over
// exact body bytes, using standard base64 (the server base64-decodes it).
func ContentDigestSHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// GenerateNonce returns a fresh signature nonce: base64url of 16 random
// bytes (128 bits), comfortably above the 12-byte floor the profile sets.
func GenerateNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", newError(ErrLumoAuth, CodeError, "could not generate a nonce: "+err.Error())
	}
	return b64url(buf), nil
}

// SignatureParams renders the `(…);created=…;nonce="…"` string shared by
// the signature base and the Signature-Input header.
func SignatureParams(components []string, created int64, nonce string) string {
	quoted := make([]string, len(components))
	for i, component := range components {
		quoted[i] = `"` + component + `"`
	}
	return fmt.Sprintf(`(%s);created=%d;nonce=%q`, strings.Join(quoted, " "), created, nonce)
}

// BuildSignatureBase assembles the RFC 9421 signature base: one
// `"<component>": <value>` line per covered component in order, then the
// "@signature-params" line carrying created and nonce.
func BuildSignatureBase(components []string, values map[string]string, created int64, nonce string) string {
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		lines = append(lines, `"`+component+`": `+values[component])
	}
	lines = append(lines, `"@signature-params": `+SignatureParams(components, created, nonce))
	return strings.Join(lines, "\n")
}

// SignSignatureBase signs a signature base and returns the base64url
// signature. Ed25519 keys sign directly; RSA keys use RSA-PSS with SHA-512
// and a digest-length salt, matching the server's dispatch.
func SignSignatureBase(signatureBase string, key crypto.Signer) (string, error) {
	data := []byte(signatureBase)

	switch typed := key.(type) {
	case ed25519.PrivateKey:
		return b64url(ed25519.Sign(typed, data)), nil

	case *rsa.PrivateKey:
		digest := sha512.Sum512(data)
		signature, err := rsa.SignPSS(rand.Reader, typed, crypto.SHA512, digest[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA512,
		})
		if err != nil {
			return "", newError(ErrLumoAuth, CodeError, "RSA-PSS signing failed: "+err.Error())
		}
		return b64url(signature), nil

	default:
		return "", NewValidationError("AAuth signing requires an Ed25519 or RSA private key")
	}
}

// VerifySignatureBase checks a base64url signature over a signature base.
// Resource servers use it to verify proof-of-possession against the key in
// a token's cnf.jwk.
func VerifySignatureBase(signatureBase, signatureB64URL string, key crypto.PublicKey) bool {
	signature, err := b64urlDecode(signatureB64URL)
	if err != nil {
		return false
	}
	data := []byte(signatureBase)

	switch typed := key.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(typed, data, signature)

	case *rsa.PublicKey:
		digest := sha512.Sum512(data)
		return rsa.VerifyPSS(typed, crypto.SHA512, digest[:], signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA512,
		}) == nil

	default:
		return false
	}
}

// SignRequest builds the RFC 9421 signature headers for a request under the
// AAuth profile: Content-Digest, Content-Type, Signature-Input, Signature,
// and — when an agent token is supplied — Agent-Auth.
//
//	headers, err := lumoauth.SignRequest(privateKeyPEM, "POST", url, lumoauth.SignOptions{
//	    Body:       body,
//	    AgentToken: agentToken,
//	})
func SignRequest(privateKeyPEM, method, targetURL string, opts SignOptions) (map[string]string, error) {
	key, err := LoadPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return signRequestWithKey(key, method, targetURL, opts)
}

func signRequestWithKey(key crypto.Signer, method, targetURL string, opts SignOptions) (map[string]string, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, validationErrorf("could not parse the target URL %q: %v", targetURL, err)
	}

	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	query := ""
	if parsed.RawQuery != "" {
		query = "?" + parsed.RawQuery
	}

	contentType := opts.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	contentDigest := ContentDigestSHA256(opts.Body)

	created := opts.Created
	if created == 0 {
		created = time.Now().Unix()
	}
	nonce := opts.Nonce
	if nonce == "" {
		if nonce, err = GenerateNonce(); err != nil {
			return nil, err
		}
	}

	// @query is covered if and only if the target URI has a query string.
	components := []string{"@method", "@authority", "@path"}
	if query != "" {
		components = append(components, "@query")
	}
	components = append(components,
		"signature-key", "content-digest", "content-type", "authorization")

	values := map[string]string{
		"@method":        strings.ToUpper(method),
		"@authority":     strings.ToLower(parsed.Host),
		"@path":          path,
		"@query":         query,
		"signature-key":  opts.SignatureKey,
		"content-digest": contentDigest,
		"content-type":   contentType,
		"authorization":  opts.Authorization,
	}

	signature, err := SignSignatureBase(
		BuildSignatureBase(components, values, created, nonce), key)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Content-Digest":  contentDigest,
		"Content-Type":    contentType,
		"Signature-Input": signatureLabel + "=" + SignatureParams(components, created, nonce),
		"Signature":       signatureLabel + "=:" + signature + ":",
	}
	if opts.AgentToken != "" {
		headers["Agent-Auth"] = "agent_token=" + opts.AgentToken
	}
	if opts.SignatureKey != "" {
		headers["Signature-Key"] = opts.SignatureKey
	}
	return headers, nil
}

// ── JWS verification primitives (used by VerifyAuthToken) ─────────────

// verifyJWS checks a JWS signature for one of the asymmetric algorithms
// AAuth permits. HMAC and "none" are always rejected.
func verifyJWS(alg string, signingInput, signature []byte, key crypto.PublicKey) bool {
	switch alg {
	case "EdDSA":
		edKey, ok := key.(ed25519.PublicKey)
		return ok && ed25519.Verify(edKey, signingInput, signature)

	case "RS256", "RS384", "RS512":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		hashID, digest := hashFor(alg, signingInput)
		return rsa.VerifyPKCS1v15(rsaKey, hashID, digest, signature) == nil

	case "PS256", "PS384", "PS512":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		hashID, digest := hashFor(alg, signingInput)
		return rsa.VerifyPSS(rsaKey, hashID, digest, signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashID,
		}) == nil

	case "ES256", "ES384", "ES512":
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		// JWS uses the fixed-width IEEE P-1363 encoding, not ASN.1.
		if len(signature)%2 != 0 {
			return false
		}
		half := len(signature) / 2
		r := new(big.Int).SetBytes(signature[:half])
		s := new(big.Int).SetBytes(signature[half:])
		_, digest := hashFor(alg, signingInput)
		return ecdsa.Verify(ecKey, digest, r, s)

	default:
		return false
	}
}

// hashFor returns the hash identifier and digest for a JWS algorithm.
func hashFor(alg string, data []byte) (crypto.Hash, []byte) {
	var hashID crypto.Hash
	var hasher hash.Hash

	switch alg[2:] {
	case "384":
		hashID, hasher = crypto.SHA384, sha512.New384()
	case "512":
		hashID, hasher = crypto.SHA512, sha512.New()
	default:
		hashID, hasher = crypto.SHA256, sha256.New()
	}
	hasher.Write(data)
	return hashID, hasher.Sum(nil)
}

// algMatchesKeyType reports whether a JWS algorithm is usable with a key
// type — the check that stops an attacker swapping an RSA key into an
// EdDSA slot.
func algMatchesKeyType(alg, kty string) bool {
	switch kty {
	case "RSA":
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case "EC":
		return strings.HasPrefix(alg, "ES")
	case "OKP":
		return alg == "EdDSA"
	default:
		return false
	}
}
