package lumoauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // registers SHA-384 and SHA-512 for crypto.Hash.New
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"time"
)

// private_key_jwt client assertions (RFC 7523 §2.2, OpenID Connect Core §9).
//
// A LumoAuth agent registered with the "Private key JWT" identity type has no
// client secret. Whenever it needs a token, it signs a short-lived JWT with its
// private key and sends that instead:
//
//	signer, err := lumoauth.LoadClientAssertionSigner(os.Getenv("AGENT_PRIVATE_KEY"),
//		lumoauth.ClientAssertionOptions{KeyID: "agent-2026-11"})
//	agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{ClientID: "agt_…", PrivateKey: signer})
//
// Register signer.JWKS() (the public key only) on the agent. What the server
// checks, and what Assertion produces: header alg (ES256, ES384, ES512,
// EdDSA, RS256–RS512 or PS256–PS512), kid and typ client-authentication+jwt;
// iss = sub = the agent ID; aud = the organization's issuer identifier alone
// (not the token endpoint URL); iat now, exp at most 10 minutes later (60s by
// default) and a random jti. Every assertion is single-use, so sign a new one
// per request.

const (
	// ClientAssertionType is the client_assertion_type of a JWT client assertion.
	ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// ClientAssertionTyp is the typ header of a client-authentication JWT.
	ClientAssertionTyp = "client-authentication+jwt"
	// MaxClientAssertionLifetime is the longest validity LumoAuth accepts.
	MaxClientAssertionLifetime = 10 * time.Minute

	// EnvAgentPrivateKey holds the PEM private key of a private key JWT agent.
	EnvAgentPrivateKey = "AGENT_PRIVATE_KEY"
	// EnvAgentKeyID holds the kid of the registered public key.
	EnvAgentKeyID = "AGENT_KEY_ID"
)

var rsaAssertionAlgorithms = map[string]crypto.Hash{
	"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512,
	"PS256": crypto.SHA256, "PS384": crypto.SHA384, "PS512": crypto.SHA512,
}

// ClientAssertionOptions configures a ClientAssertionSigner.
type ClientAssertionOptions struct {
	// KeyID is the kid of the registered public key. Required by the server
	// when the agent has more than one key.
	KeyID string
	// Algorithm overrides the key's natural algorithm (ES256/ES384/ES512 by
	// curve, EdDSA, RS256). RSA keys may also use RS384, RS512, PS256, PS384
	// or PS512.
	Algorithm string
	// Lifetime is the time until exp: 1s to 10m. Default 60s.
	Lifetime time.Duration
}

// ClientAssertionSigner signs private_key_jwt client assertions with one key.
type ClientAssertionSigner struct {
	key      crypto.Signer
	alg      string
	hash     crypto.Hash
	keyID    string
	lifetime time.Duration
	now      func() time.Time
}

// NewClientAssertionSigner wraps a private key: an *ecdsa.PrivateKey on
// P-256, P-384 or P-521, an ed25519.PrivateKey or an *rsa.PrivateKey of at
// least 2048 bits.
func NewClientAssertionSigner(key crypto.Signer, opts ClientAssertionOptions) (*ClientAssertionSigner, error) {
	natural, hash, err := naturalAssertionAlgorithm(key)
	if err != nil {
		return nil, err
	}
	alg := natural
	if opts.Algorithm != "" {
		alg = opts.Algorithm
	}
	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		h, known := rsaAssertionAlgorithms[alg]
		if !known {
			return nil, validationErrorf("%s does not fit an RSA key; use RS256, RS384, RS512, PS256, PS384 or PS512", alg)
		}
		if rsaKey.N.BitLen() < 2048 {
			return nil, NewValidationError("RSA keys must be at least 2048 bits")
		}
		hash = h
	} else if alg != natural {
		return nil, validationErrorf("%s does not fit this key; it signs with %s", alg, natural)
	}
	lifetime := opts.Lifetime
	if lifetime == 0 {
		lifetime = time.Minute
	}
	if lifetime < time.Second || lifetime > MaxClientAssertionLifetime {
		return nil, NewValidationError("the client assertion lifetime must be between 1s and 10m")
	}
	return &ClientAssertionSigner{key: key, alg: alg, hash: hash, keyID: opts.KeyID, lifetime: lifetime, now: time.Now}, nil
}

// LoadClientAssertionSigner parses a PEM private key (PKCS#8 "PRIVATE KEY",
// SEC 1 "EC PRIVATE KEY" or PKCS#1 "RSA PRIVATE KEY").
func LoadClientAssertionSigner(pemData string, opts ClientAssertionOptions) (*ClientAssertionSigner, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, NewValidationError("could not parse the agent private key: no PEM block found")
	}
	var parsed any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, NewValidationError("could not parse the agent private key: " + err.Error())
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, NewValidationError("the agent private key is not a signing key")
	}
	return NewClientAssertionSigner(signer, opts)
}

// GenerateClientAssertionSigner creates a new key for algorithm: ES256
// (default when empty), ES384, ES512, EdDSA, or an RSA algorithm (2048 bits).
func GenerateClientAssertionSigner(algorithm, keyID string) (*ClientAssertionSigner, error) {
	if algorithm == "" {
		algorithm = "ES256"
	}
	var key crypto.Signer
	var err error
	switch algorithm {
	case "ES256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ES384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ES512":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "EdDSA":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		if _, ok := rsaAssertionAlgorithms[algorithm]; !ok {
			return nil, validationErrorf("unsupported client assertion algorithm %q", algorithm)
		}
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, newError(ErrLumoAuth, CodeError, "could not generate a key: "+err.Error())
	}
	return NewClientAssertionSigner(key, ClientAssertionOptions{KeyID: keyID, Algorithm: algorithm})
}

// Algorithm is the JWS alg of the assertions.
func (s *ClientAssertionSigner) Algorithm() string { return s.alg }

// KeyID is the kid put in every assertion header ("" when unset).
func (s *ClientAssertionSigner) KeyID() string { return s.keyID }

// Assertion signs one client assertion for clientID (the agent ID) and
// audience (the organization's issuer identifier, see IssuerFor).
func (s *ClientAssertionSigner) Assertion(clientID, audience string) (string, error) {
	if clientID == "" || audience == "" {
		return "", NewValidationError("clientID and audience are required for a client assertion")
	}
	jti := make([]byte, 24)
	if _, err := rand.Read(jti); err != nil {
		return "", newError(ErrLumoAuth, CodeError, "could not create a jti: "+err.Error())
	}
	now := s.now().Unix()
	header := map[string]any{"alg": s.alg, "typ": ClientAssertionTyp}
	if s.keyID != "" {
		header["kid"] = s.keyID
	}
	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": now,
		"exp": now + int64(s.lifetime/time.Second),
		"jti": b64url(jti),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", newError(ErrLumoAuth, CodeError, "could not encode the assertion header: "+err.Error())
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", newError(ErrLumoAuth, CodeError, "could not encode the assertion claims: "+err.Error())
	}
	signingInput := b64url(headerJSON) + "." + b64url(claimsJSON)
	signature, err := s.sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64url(signature), nil
}

// PublicJWK is the public key with kid (when set), alg and use "sig".
func (s *ClientAssertionSigner) PublicJWK() (JWK, error) {
	jwk, err := jwkFromPublicKey(s.key.Public())
	if err != nil {
		return JWK{}, err
	}
	jwk.Kid = s.keyID
	jwk.Alg = s.alg
	jwk.Use = "sig"
	return jwk, nil
}

// JWKS is {"keys": [PublicJWK]}: what to register on the agent.
func (s *ClientAssertionSigner) JWKS() (JWKS, error) {
	jwk, err := s.PublicJWK()
	if err != nil {
		return JWKS{}, err
	}
	return JWKS{Keys: []JWK{jwk}}, nil
}

// PrivateKeyPEM is the private key as PKCS#8 PEM, for your secret store.
func (s *ClientAssertionSigner) PrivateKeyPEM() (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(s.key)
	if err != nil {
		return "", newError(ErrLumoAuth, CodeError, "could not encode the private key: "+err.Error())
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// IssuerFor is the issuer identifier of an organization on baseURL: the
// issuer of /orgs/{orgID}/api/v1/.well-known/openid-configuration, and the
// aud a client assertion must carry. On a custom domain the issuer differs;
// set it explicitly there.
func IssuerFor(baseURL, orgID string) string {
	return strings.TrimRight(baseURL, "/") + "/orgs/" + orgID + "/api/v1"
}

func (s *ClientAssertionSigner) sign(input []byte) ([]byte, error) {
	if key, ok := s.key.(ed25519.PrivateKey); ok {
		return ed25519.Sign(key, input), nil
	}
	h := s.hash.New()
	h.Write(input)
	digest := h.Sum(nil)
	switch key := s.key.(type) {
	case *ecdsa.PrivateKey:
		r, sv, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, newError(ErrLumoAuth, CodeError, "could not sign the client assertion: "+err.Error())
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		return append(leftPad(r.Bytes(), size), leftPad(sv.Bytes(), size)...), nil
	case *rsa.PrivateKey:
		var signature []byte
		var err error
		if strings.HasPrefix(s.alg, "PS") {
			signature, err = rsa.SignPSS(rand.Reader, key, s.hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			signature, err = rsa.SignPKCS1v15(rand.Reader, key, s.hash, digest)
		}
		if err != nil {
			return nil, newError(ErrLumoAuth, CodeError, "could not sign the client assertion: "+err.Error())
		}
		return signature, nil
	default:
		return nil, NewValidationError("unsupported client assertion key type")
	}
}

func naturalAssertionAlgorithm(key crypto.Signer) (string, crypto.Hash, error) {
	switch typed := key.(type) {
	case *ecdsa.PrivateKey:
		switch typed.Curve {
		case elliptic.P256():
			return "ES256", crypto.SHA256, nil
		case elliptic.P384():
			return "ES384", crypto.SHA384, nil
		case elliptic.P521():
			return "ES512", crypto.SHA512, nil
		}
		return "", 0, NewValidationError("EC keys must use P-256, P-384 or P-521")
	case ed25519.PrivateKey:
		return "EdDSA", 0, nil
	case *rsa.PrivateKey:
		return "RS256", crypto.SHA256, nil
	default:
		return "", 0, NewValidationError("a client assertion key must be an ECDSA (P-256/P-384/P-521), Ed25519 or RSA private key")
	}
}
