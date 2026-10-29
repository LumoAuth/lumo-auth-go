package lumoauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DPoP (RFC 9449): sender-constrained access tokens.
//
// A DPoPSigner holds the private key an agent proves possession of. With
// one configured (WithDPoP on a Client, AgentConfig.DPoP on an Agent), the
// SDK
//
//   - sends a `DPoP` proof with every token request, so the tokens the
//     server issues are bound to the key (token_type "DPoP"), and retries
//     once when the server demands a nonce (use_dpop_nonce);
//   - presents a bound token with the `DPoP` authorization scheme plus a
//     proof carrying `ath`, on LumoAuth's own API and — through
//     AuthorizeRequest — on any MCP or resource server.
//
// A DPoPSigner is safe for concurrent use.

// DPoP proof algorithms this SDK signs with. The server also accepts the
// RSA and larger EC families; ES256 is the RFC 9449 default.
const (
	DPoPAlgES256 = "ES256"
	DPoPAlgEdDSA = "EdDSA"
)

// DPoPHeader is the request header that carries a DPoP proof.
const DPoPHeader = "DPoP"

// DPoPNonceHeader is the response header a server uses to hand out a nonce.
const DPoPNonceHeader = "DPoP-Nonce"

// DPoPTokenType is the token_type of a DPoP-bound token.
const DPoPTokenType = "DPoP"

// dpopProofAlgorithms lists every proof algorithm the server accepts, in
// the order a resource server advertises them (WWW-Authenticate: DPoP algs).
var dpopProofAlgorithms = []string{
	"ES256", "ES384", "ES512",
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"EdDSA",
}

// DPoPSigner signs RFC 9449 proofs with one private key.
type DPoPSigner struct {
	key crypto.Signer
	alg string
	jwk JWK
	jkt string

	mu     sync.Mutex
	nonces map[string]string // origin → latest server-issued nonce
	now    func() time.Time
}

// NewDPoPSigner generates a fresh P-256 key and returns a signer for ES256
// proofs — the recommended default.
//
//	signer, err := lumoauth.NewDPoPSigner()
//	agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{DPoP: signer})
//
// The key lives only in memory; a new process gets a new key, which is
// fine because the tokens it binds are short-lived. To keep one key across
// restarts, generate it once (GenerateDPoPKeyPEM) and load it with
// LoadDPoPSigner.
func NewDPoPSigner() (*DPoPSigner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, newError(ErrLumoAuth, CodeError, "could not generate a P-256 key: "+err.Error())
	}
	return NewDPoPSignerFromKey(key)
}

// NewDPoPSignerEd25519 generates a fresh Ed25519 key and returns a signer
// for EdDSA proofs.
func NewDPoPSignerEd25519() (*DPoPSigner, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, newError(ErrLumoAuth, CodeError, "could not generate an Ed25519 key: "+err.Error())
	}
	return NewDPoPSignerFromKey(key)
}

// NewDPoPSignerFromKey wraps an existing private key: an *ecdsa.PrivateKey
// on P-256 (ES256) or an ed25519.PrivateKey (EdDSA). Other key types are a
// *ValidationError.
func NewDPoPSignerFromKey(key crypto.Signer) (*DPoPSigner, error) {
	var alg string
	switch typed := key.(type) {
	case *ecdsa.PrivateKey:
		if typed.Curve != elliptic.P256() {
			return nil, NewValidationError("DPoP ECDSA keys must be on the P-256 curve (ES256)")
		}
		alg = DPoPAlgES256
	case ed25519.PrivateKey:
		alg = DPoPAlgEdDSA
	default:
		return nil, NewValidationError("a DPoP key must be an *ecdsa.PrivateKey (P-256) or an ed25519.PrivateKey")
	}
	jwk, err := jwkFromPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	jkt, err := jwk.Thumbprint()
	if err != nil {
		return nil, err
	}
	return &DPoPSigner{
		key:    key,
		alg:    alg,
		jwk:    jwk,
		jkt:    jkt,
		nonces: map[string]string{},
		now:    time.Now,
	}, nil
}

// LoadDPoPSigner parses a PEM private key (PKCS#8 "PRIVATE KEY" or SEC 1
// "EC PRIVATE KEY") into a signer. The key must be P-256 or Ed25519.
func LoadDPoPSigner(pemData string) (*DPoPSigner, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, NewValidationError("could not parse the DPoP private key: no PEM block found")
	}
	var parsed any
	var err error
	if block.Type == "EC PRIVATE KEY" {
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	} else {
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, NewValidationError("could not parse the DPoP private key: " + err.Error())
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, NewValidationError("the DPoP private key is not a signing key")
	}
	return NewDPoPSignerFromKey(signer)
}

// GenerateDPoPKeyPEM generates a P-256 key and returns it as a PKCS#8 PEM
// block, for storing in a secret manager and loading with LoadDPoPSigner.
func GenerateDPoPKeyPEM() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", newError(ErrLumoAuth, CodeError, "could not generate a P-256 key: "+err.Error())
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", newError(ErrLumoAuth, CodeError, "could not encode the private key: "+err.Error())
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// Algorithm returns the JWS algorithm of the proofs: "ES256" or "EdDSA".
func (s *DPoPSigner) Algorithm() string { return s.alg }

// PublicJWK returns the public key as it appears in each proof's header.
// It never includes private members.
func (s *DPoPSigner) PublicJWK() JWK { return s.jwk }

// Thumbprint returns the RFC 7638 thumbprint of the public key — the value
// the server writes into a bound token's cnf.jkt.
func (s *DPoPSigner) Thumbprint() string { return s.jkt }

// DPoPProofOption customises one proof.
type DPoPProofOption func(*dpopProofConfig)

type dpopProofConfig struct {
	accessToken string
	nonce       string
	nonceSet    bool
}

// WithProofAccessToken adds the `ath` claim — the SHA-256 hash of the
// access token the proof accompanies. Required on every resource request.
func WithProofAccessToken(accessToken string) DPoPProofOption {
	return func(c *dpopProofConfig) { c.accessToken = accessToken }
}

// WithProofNonce sets the `nonce` claim explicitly, overriding the nonce
// the signer remembers for the target's origin. Pass "" to omit the claim.
func WithProofNonce(nonce string) DPoPProofOption {
	return func(c *dpopProofConfig) { c.nonce, c.nonceSet = nonce, true }
}

// Proof signs a DPoP proof for one HTTP request.
//
// method is the HTTP method; rawURL is the request URL. The proof carries
// `htm` (the method, upper-case), `htu` (the URL without query or
// fragment), `iat`, a random `jti`, the `nonce` the signer remembers for
// that origin unless WithProofNonce overrides it, and `ath` when
// WithProofAccessToken is given.
func (s *DPoPSigner) Proof(method, rawURL string, opts ...DPoPProofOption) (string, error) {
	cfg := &dpopProofConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	htu, err := dpopHTU(rawURL)
	if err != nil {
		return "", err
	}
	if method == "" {
		return "", NewValidationError("an HTTP method is required to sign a DPoP proof")
	}

	jti, err := randomJTI()
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"jti": jti,
		"htm": strings.ToUpper(method),
		"htu": htu,
		"iat": s.now().Unix(),
	}
	nonce := cfg.nonce
	if !cfg.nonceSet {
		nonce = s.Nonce(rawURL)
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if cfg.accessToken != "" {
		claims["ath"] = DPoPAccessTokenHash(cfg.accessToken)
	}

	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": s.alg,
		"jwk": s.jwk,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", NewValidationError("could not encode the DPoP proof header: " + err.Error())
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", NewValidationError("could not encode the DPoP proof claims: " + err.Error())
	}
	signingInput := b64url(headerJSON) + "." + b64url(claimsJSON)
	signature, err := s.sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64url(signature), nil
}

// sign produces the JWS signature for the signer's algorithm: raw r||s for
// ES256, the Ed25519 signature for EdDSA.
func (s *DPoPSigner) sign(signingInput []byte) ([]byte, error) {
	switch key := s.key.(type) {
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(signingInput)
		r, sv, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return nil, newError(ErrLumoAuth, CodeError, "could not sign the DPoP proof: "+err.Error())
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		signature := make([]byte, 0, 2*size)
		signature = append(signature, leftPad(r.Bytes(), size)...)
		signature = append(signature, leftPad(sv.Bytes(), size)...)
		return signature, nil
	case ed25519.PrivateKey:
		return ed25519.Sign(key, signingInput), nil
	default:
		return nil, NewValidationError("unsupported DPoP key type")
	}
}

// Nonce returns the nonce the signer remembers for rawURL's origin, or "".
func (s *DPoPSigner) Nonce(rawURL string) string {
	origin := dpopOrigin(rawURL)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nonces[origin]
}

// SetNonce remembers a server-issued nonce for rawURL's origin
// (scheme://host[:port]). Later proofs for that origin carry it. Pass ""
// to forget the nonce.
func (s *DPoPSigner) SetNonce(rawURL, nonce string) {
	origin := dpopOrigin(rawURL)
	s.mu.Lock()
	defer s.mu.Unlock()
	if nonce == "" {
		delete(s.nonces, origin)
		return
	}
	s.nonces[origin] = nonce
}

// RememberNonce reads a DPoP-Nonce header from a response and stores it
// for the origin of the request that produced it. It reports whether a
// nonce was present. Call it on every response from a server that uses
// DPoP nonces; the SDK does so for its own requests.
func (s *DPoPSigner) RememberNonce(resp *http.Response) bool {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return false
	}
	nonce := resp.Header.Get(DPoPNonceHeader)
	if nonce == "" {
		return false
	}
	s.SetNonce(resp.Request.URL.String(), nonce)
	return true
}

// AuthorizeRequest sets the Authorization header for a resource call —
// an MCP server, say — and, when the token is DPoP-bound (carries cnf.jkt),
// the `DPoP` scheme plus a proof over the request with `ath`:
//
//	req, _ := http.NewRequestWithContext(ctx, "POST", "https://mcp.example.com/mcp", body)
//	if err := signer.AuthorizeRequest(req, mcpToken); err != nil {
//	    return err
//	}
//
// An unbound token is sent as `Authorization: Bearer`, without a proof.
// If the server answers 401 with a DPoP-Nonce header, call RememberNonce
// on the response and send the request again.
func (s *DPoPSigner) AuthorizeRequest(req *http.Request, accessToken string) error {
	if req == nil || req.URL == nil {
		return NewValidationError("a request with a URL is required")
	}
	if accessToken == "" {
		return NewValidationError("an access token is required")
	}
	if !DPoPBound(accessToken) {
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Del(DPoPHeader)
		return nil
	}
	proof, err := s.Proof(req.Method, req.URL.String(), WithProofAccessToken(accessToken))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", DPoPTokenType+" "+accessToken)
	req.Header.Set(DPoPHeader, proof)
	return nil
}

// DPoPBound reports whether a JWT access token is sender-constrained — it
// carries a cnf.jkt claim — and so must be presented with the DPoP scheme
// and a proof. Opaque or malformed tokens are reported as unbound.
//
// The claims are read WITHOUT signature verification: this only picks the
// authorization scheme, it never grants anything.
func DPoPBound(token string) bool {
	claims, err := decodeJWTPayload(token)
	if err != nil {
		return false
	}
	cnf, _ := claims["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	return jkt != ""
}

// DPoPAccessTokenHash computes the `ath` claim: base64url(SHA-256(token)).
func DPoPAccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return b64url(sum[:])
}

// dpopHTU normalises a request URL into the `htu` value: scheme, host,
// optional port and path, with no query or fragment.
func dpopHTU(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", validationErrorf("a DPoP proof needs an absolute request URL, got %q", rawURL)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + path, nil
}

// dpopOrigin returns scheme://host[:port] for nonce book-keeping.
func dpopOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return rawURL
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// randomJTI returns 16 random bytes as base64url (22 characters).
func randomJTI() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", newError(ErrLumoAuth, CodeError, "could not generate a DPoP jti: "+err.Error())
	}
	return b64url(raw), nil
}

// dpopTokenURL is the absolute token endpoint URL for the transport's base
// URL and org — the `htu` of a token-endpoint proof.
func (c *httpClient) dpopTokenURL() (string, error) {
	_, path, err := c.resolve(RouteOAuthToken, nil)
	if err != nil {
		return "", err
	}
	return c.baseURL + path, nil
}
