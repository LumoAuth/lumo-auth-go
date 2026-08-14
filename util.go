package lumoauth

import (
	"encoding/base64"
	"encoding/json"
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is the SDK version reported in the User-Agent header.
const Version = "1.0.0"

// userAgent builds the default User-Agent, including the Go runtime and,
// when the SDK is consumed as a module, its resolved version.
func userAgent() string {
	version := Version
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == modulePath && dep.Version != "" && dep.Version != "(devel)" {
				version = strings.TrimPrefix(dep.Version, "v")
				break
			}
		}
	}
	return "lumoauth-go/" + version + " (" + runtime.Version() + ")"
}

const modulePath = "github.com/lumoauth/lumo-auth-go"

// splitScopes splits a space-separated OAuth scope string, dropping empties.
func splitScopes(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	return strings.Fields(scope)
}

// joinScopes renders a scope slice for the wire.
func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }

// decodeJWTPayload base64url-decodes a JWT's claims segment WITHOUT
// verifying the signature. Use it for display and audit only; anything
// security-relevant must go through VerifyAuthToken or the server.
func decodeJWTPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, NewValidationError("not a JWT: expected at least two dot-separated segments")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, NewValidationError("could not base64url-decode the JWT payload: " + err.Error())
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, NewValidationError("could not decode the JWT payload as JSON: " + err.Error())
	}
	return claims, nil
}

// b64url encodes without padding, per RFC 7515 §2.
func b64url(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// b64urlDecode decodes base64url with or without padding.
func b64urlDecode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
}

// copyStringMap returns a shallow copy, or nil for an empty input.
func copyStringMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
