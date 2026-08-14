package lumoauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
)

// Key handling for the AAuth (Agent Auth) protocol: Ed25519 key
// generation, PEM loading, JWK conversion, and RFC 7638 thumbprints.

// JWK is a JSON Web Key. Only the members AAuth uses are modelled; Extra
// preserves anything else the issuer published.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// JWKS is a JSON Web Key Set, as published at a jwks_uri.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Find returns the key with the given kid.
func (s *JWKS) Find(kid string) (*JWK, bool) {
	for i := range s.Keys {
		if s.Keys[i].Kid == kid {
			return &s.Keys[i], true
		}
	}
	return nil, false
}

// Keypair is a freshly generated AAuth signing key.
type Keypair struct {
	// PrivateKeyPEM is the PKCS#8 private key. Store it in a secret manager.
	PrivateKeyPEM string
	// PublicKeyPEM is the SPKI public key.
	PublicKeyPEM string
	// JWK is the public key with use "sig" and the requested kid.
	JWK JWK
	// JWKS is a key set ready to publish at /.well-known/jwks.json.
	JWKS JWKS
}

// DefaultKid is the key ID used when none is given, matching the JS and
// Python SDKs.
const DefaultKid = "key-1"

// GenerateKeypair creates an Ed25519 key pair for AAuth. Pass an empty kid
// to use DefaultKid.
//
//	keypair, err := lumoauth.GenerateKeypair("")
//	// Register keypair.JWKS with LumoAuth, keep keypair.PrivateKeyPEM secret.
func GenerateKeypair(kid string) (*Keypair, error) {
	if kid == "" {
		kid = DefaultKid
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, newError(ErrLumoAuth, CodeError, "could not generate an Ed25519 key: "+err.Error())
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, newError(ErrLumoAuth, CodeError, "could not encode the private key: "+err.Error())
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, newError(ErrLumoAuth, CodeError, "could not encode the public key: "+err.Error())
	}

	jwk := JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   b64url(publicKey),
		Use: "sig",
		Kid: kid,
	}
	return &Keypair{
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		JWK:           jwk,
		JWKS:          JWKS{Keys: []JWK{jwk}},
	}, nil
}

// LoadPrivateKey parses a PEM private key for AAuth signing. Ed25519 and
// RSA keys are supported, matching the algorithms the server accepts.
func LoadPrivateKey(pemData string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, NewValidationError("could not parse the private key: no PEM block found")
	}

	var parsed any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default: // "PRIVATE KEY" and anything else: try PKCS#8 first.
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes); rsaErr == nil {
				parsed, err = rsaKey, nil
			}
		}
	}
	if err != nil {
		return nil, NewValidationError("could not parse the private key: " + err.Error())
	}

	switch key := parsed.(type) {
	case ed25519.PrivateKey:
		return key, nil
	case *rsa.PrivateKey:
		return key, nil
	default:
		return nil, NewValidationError(
			"AAuth requires an Ed25519 or RSA private key")
	}
}

// PublicJWK derives the public JWK for a PEM private key.
func PublicJWK(privateKeyPEM, kid string) (JWK, error) {
	signer, err := LoadPrivateKey(privateKeyPEM)
	if err != nil {
		return JWK{}, err
	}
	jwk, err := jwkFromPublicKey(signer.Public())
	if err != nil {
		return JWK{}, err
	}
	jwk.Kid = kid
	return jwk, nil
}

// jwkFromPublicKey converts a public key into its JWK representation.
func jwkFromPublicKey(key crypto.PublicKey) (JWK, error) {
	switch typed := key.(type) {
	case ed25519.PublicKey:
		return JWK{Kty: "OKP", Crv: "Ed25519", X: b64url(typed)}, nil
	case *rsa.PublicKey:
		return JWK{
			Kty: "RSA",
			N:   b64url(typed.N.Bytes()),
			E:   b64url(big.NewInt(int64(typed.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		byteLen := (typed.Curve.Params().BitSize + 7) / 8
		return JWK{
			Kty: "EC",
			Crv: curveName(typed.Curve),
			X:   b64url(leftPad(typed.X.Bytes(), byteLen)),
			Y:   b64url(leftPad(typed.Y.Bytes(), byteLen)),
		}, nil
	default:
		return JWK{}, NewValidationError("unsupported public key type for JWK conversion")
	}
}

// PublicKey converts a JWK into a Go public key for signature verification.
func (j *JWK) PublicKey() (crypto.PublicKey, error) {
	switch j.Kty {
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, validationErrorf("unsupported OKP curve %q", j.Crv)
		}
		raw, err := b64urlDecode(j.X)
		if err != nil {
			return nil, NewValidationError("could not decode the JWK x parameter: " + err.Error())
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, validationErrorf(
				"Ed25519 public key must be %d bytes (got %d)", ed25519.PublicKeySize, len(raw))
		}
		return ed25519.PublicKey(raw), nil

	case "RSA":
		modulus, err := b64urlDecode(j.N)
		if err != nil {
			return nil, NewValidationError("could not decode the JWK n parameter: " + err.Error())
		}
		exponent, err := b64urlDecode(j.E)
		if err != nil {
			return nil, NewValidationError("could not decode the JWK e parameter: " + err.Error())
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exponent).Int64()),
		}, nil

	case "EC":
		curve, err := curveFromName(j.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64urlDecode(j.X)
		if err != nil {
			return nil, NewValidationError("could not decode the JWK x parameter: " + err.Error())
		}
		y, err := b64urlDecode(j.Y)
		if err != nil {
			return nil, NewValidationError("could not decode the JWK y parameter: " + err.Error())
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil

	default:
		return nil, validationErrorf("unsupported JWK key type %q", j.Kty)
	}
}

// Thumbprint computes the RFC 7638 JWK thumbprint — the base64url SHA-256
// of the key's canonical form. AAuth uses it as the `jkt` value binding a
// token to a key.
func (j *JWK) Thumbprint() (string, error) {
	var canonical []byte
	var err error

	switch j.Kty {
	case "OKP":
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{j.Crv, j.Kty, j.X})
	case "EC":
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{j.Crv, j.Kty, j.X, j.Y})
	case "RSA":
		canonical, err = json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{j.E, j.Kty, j.N})
	default:
		return "", validationErrorf("unsupported key type for a thumbprint: %q", j.Kty)
	}
	if err != nil {
		return "", NewValidationError("could not canonicalise the JWK: " + err.Error())
	}

	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func curveName(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return ""
	}
}

func curveFromName(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, validationErrorf("unsupported EC curve %q", name)
	}
}

// leftPad zero-pads a big-endian integer to a fixed width, as JWK
// coordinates require.
func leftPad(data []byte, size int) []byte {
	if len(data) >= size {
		return data
	}
	padded := make([]byte, size)
	copy(padded[size-len(data):], data)
	return padded
}
