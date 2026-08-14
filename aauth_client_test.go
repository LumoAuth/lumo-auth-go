package lumoauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// aauthCall records one signed request the AAuth client sent.
type aauthCall struct {
	Path      string
	Host      string
	Body      map[string]any
	RawBody   []byte
	AgentAuth string
	Headers   http.Header
}

func newTestAAuthClient(t *testing.T, calls *[]aauthCall, respond func(w http.ResponseWriter, r *http.Request)) (*AAuthClient, *Keypair, *httptest.Server) {
	t.Helper()

	keypair, err := GenerateKeypair("agent-key")
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		call := aauthCall{
			Path: r.URL.Path,
			// Go moves the Host header into r.Host, so it is not in
			// r.Header — the signature covers it as @authority.
			Host:      r.Host,
			RawBody:   raw,
			AgentAuth: r.Header.Get("Agent-Auth"),
			Headers:   r.Header.Clone(),
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &call.Body)
		}
		*calls = append(*calls, call)

		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		respond(w, r)
	}))
	t.Cleanup(server.Close)

	client, err := NewAAuthClient(AAuthConfig{
		AgentIdentifier: "https://my-agent.example.com",
		PrivateKeyPEM:   keypair.PrivateKeyPEM,
		BaseURL:         server.URL,
		OrgID:           "acme-corp",
		Kid:             "agent-key",
	})
	if err != nil {
		t.Fatalf("NewAAuthClient: %v", err)
	}
	return client, keypair, server
}

func TestNewAAuthClientValidation(t *testing.T) {
	keypair, _ := GenerateKeypair("")

	if _, err := NewAAuthClient(AAuthConfig{PrivateKeyPEM: keypair.PrivateKeyPEM}); !errors.Is(err, ErrConfig) {
		t.Errorf("a missing agent identifier should be a config error, got %v", err)
	}
	if _, err := NewAAuthClient(AAuthConfig{AgentIdentifier: "https://a.test"}); !errors.Is(err, ErrConfig) {
		t.Errorf("a missing private key should be a config error, got %v", err)
	}
	if _, err := NewAAuthClient(AAuthConfig{
		AgentIdentifier: "https://a.test", PrivateKeyPEM: "garbage",
	}); !errors.Is(err, ErrValidation) {
		t.Errorf("an unparseable key should be a validation error, got %v", err)
	}
}

func TestAAuthClientIssuerAndKeyAccessors(t *testing.T) {
	var calls []aauthCall
	client, keypair, server := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {})

	want := server.URL + "/orgs/acme-corp/api/v1"
	if client.Issuer() != want {
		t.Errorf("Issuer() = %q, want %q", client.Issuer(), want)
	}

	jwk, err := client.PublicJWK()
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	if jwk.X != keypair.JWK.X {
		t.Error("PublicJWK should derive the same key that GenerateKeypair produced")
	}
	if jwk.Kid != "agent-key" {
		t.Errorf("Kid = %q", jwk.Kid)
	}

	thumbprint, err := client.PublicJWKThumbprint()
	if err != nil {
		t.Fatalf("PublicJWKThumbprint: %v", err)
	}
	expected, _ := keypair.JWK.Thumbprint()
	if thumbprint != expected {
		t.Errorf("thumbprint = %q, want %q", thumbprint, expected)
	}
}

func TestAAuthRequestAuthToken(t *testing.T) {
	var calls []aauthCall
	client, keypair, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"request_type":  "auth",
			"auth_token":    "auth-jwt-value",
			"expires_in":    900,
			"token_type":    "auth+jwt",
			"refresh_token": "refresh-value",
		})
	})

	result, err := client.RequestAuthToken(context.Background(), AuthTokenParams{
		ResourceToken: "resource-jwt",
		Scope:         "read write",
		AgentToken:    "agent-jwt",
	})
	if err != nil {
		t.Fatalf("RequestAuthToken: %v", err)
	}

	if result.AuthToken != "auth-jwt-value" || result.ExpiresIn != 900 {
		t.Errorf("result = %+v", result)
	}
	if result.RefreshToken != "refresh-value" || result.TokenType != "auth+jwt" {
		t.Errorf("result = %+v", result)
	}
	if result.AuthorizationRequired {
		t.Error("a successful token response is not a consent request")
	}

	call := calls[0]
	if call.Path != "/orgs/acme-corp/api/v1/aauth/agent/token" {
		t.Errorf("path = %q", call.Path)
	}
	if call.Body["request_type"] != "auth" || call.Body["resource_token"] != "resource-jwt" {
		t.Errorf("body = %v", call.Body)
	}
	// The agent credential travels in Agent-Auth, not the body.
	if call.AgentAuth != "agent_token=agent-jwt" {
		t.Errorf("Agent-Auth = %q", call.AgentAuth)
	}
	if _, inBody := call.Body["agent_token"]; inBody {
		t.Error("the agent token must not be sent in the request body")
	}

	// The signature must cover exactly the bytes that were sent.
	verifySentSignature(t, call, keypair, http.MethodPost)
}

// verifySentSignature recomputes the signature base from what the server
// received and checks it against the agent's public key. This is the same
// verification the LumoAuth server performs.
func verifySentSignature(t *testing.T, call aauthCall, keypair *Keypair, method string) {
	t.Helper()

	signatureInput := call.Headers.Get("Signature-Input")
	signature := call.Headers.Get("Signature")
	if signatureInput == "" || signature == "" {
		t.Fatal("the request carried no RFC 9421 signature")
	}

	if got := call.Headers.Get("Content-Digest"); got != ContentDigestSHA256(call.RawBody) {
		t.Errorf("Content-Digest %q does not match the body actually sent", got)
	}

	components, created, nonce, err := parseSignatureInput(signatureInput)
	if err != nil {
		t.Fatalf("parseSignatureInput: %v", err)
	}
	value, err := parseSignatureHeader(signature)
	if err != nil {
		t.Fatalf("parseSignatureHeader: %v", err)
	}

	base := BuildSignatureBase(components, map[string]string{
		"@method":        method,
		"@authority":     strings.ToLower(call.Host),
		"@path":          call.Path,
		"signature-key":  call.Headers.Get("Signature-Key"),
		"content-digest": call.Headers.Get("Content-Digest"),
		"content-type":   call.Headers.Get("Content-Type"),
		"authorization":  call.Headers.Get("Authorization"),
	}, created, nonce)

	publicKey, err := keypair.JWK.PublicKey()
	if err != nil {
		t.Fatalf("JWK.PublicKey: %v", err)
	}
	if !VerifySignatureBase(base, value, publicKey) {
		t.Errorf("the signature does not verify against the request as sent\nbase:\n%s", base)
	}
}

func TestAAuthRequestAuthTokenConsentRequired(t *testing.T) {
	t.Run("200 with a consent payload", func(t *testing.T) {
		var calls []aauthCall
		client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{
				"request_token":     "req-token",
				"authorization_uri": "https://auth.example.com/consent?x=1",
				"expires_in":        600,
			})
		})

		result, err := client.RequestAuthToken(context.Background(), AuthTokenParams{
			ResourceToken: "resource-jwt", AgentToken: "agent-jwt",
		})
		if err != nil {
			t.Fatalf("RequestAuthToken: %v", err)
		}
		if !result.AuthorizationRequired {
			t.Fatalf("result = %+v, want a consent instruction", result)
		}
		if result.AuthorizationURI != "https://auth.example.com/consent?x=1" {
			t.Errorf("AuthorizationURI = %q", result.AuthorizationURI)
		}
		if result.RequestToken != "req-token" {
			t.Errorf("RequestToken = %q", result.RequestToken)
		}
	})

	t.Run("401 with a consent payload is not an error", func(t *testing.T) {
		var calls []aauthCall
		client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 401, map[string]any{
				"error":         "authorization_required",
				"auth_url":      "https://auth.example.com/consent",
				"request_token": "req-token",
			})
		})

		result, err := client.RequestAuthToken(context.Background(), AuthTokenParams{
			ResourceToken: "resource-jwt", AgentToken: "agent-jwt",
		})
		if err != nil {
			t.Fatalf("a consent challenge should not surface as an error: %v", err)
		}
		if !result.AuthorizationRequired || result.AuthorizationURI != "https://auth.example.com/consent" {
			t.Errorf("result = %+v", result)
		}
	})

	t.Run("a genuine 401 is still an error", func(t *testing.T) {
		var calls []aauthCall
		client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 401, map[string]any{
				"error":             "invalid_signature",
				"error_description": "the signature did not verify",
			})
		})

		_, err := client.RequestAuthToken(context.Background(), AuthTokenParams{
			ResourceToken: "resource-jwt", AgentToken: "agent-jwt",
		})
		if !errors.Is(err, ErrAuthentication) {
			t.Fatalf("expected an authentication error, got %v", err)
		}
		if !strings.Contains(err.Error(), "did not verify") {
			t.Errorf("the server's description should surface: %v", err)
		}
	})
}

func TestAAuthRequiresAnAgentToken(t *testing.T) {
	var calls []aauthCall
	client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should have been sent")
	})

	ctx := context.Background()
	cases := map[string]error{
		"RequestAuthToken": func() error {
			_, err := client.RequestAuthToken(ctx, AuthTokenParams{ResourceToken: "r"})
			return err
		}(),
		"ExchangeCode": func() error {
			_, err := client.ExchangeCode(ctx, "code", "https://app.test/cb", "")
			return err
		}(),
		"ExchangeToken": func() error {
			_, err := client.ExchangeToken(ctx, "auth", "resource", "")
			return err
		}(),
		"Refresh": func() error {
			_, err := client.Refresh(ctx, RefreshParams{RefreshToken: "r", ResourceToken: "res"})
			return err
		}(),
		"Revoke": client.Revoke(ctx, "token", AAuthTokenTypeAuth, ""),
	}

	for name, err := range cases {
		if !errors.Is(err, ErrValidation) {
			t.Errorf("%s without an agent token should be a validation error, got %v", name, err)
		}
	}
}

func TestAAuthExchangeCode(t *testing.T) {
	var calls []aauthCall
	client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"request_type": "code", "auth_token": "auth-jwt", "expires_in": 900,
		})
	})

	result, err := client.ExchangeCode(context.Background(),
		"consent-code", "https://app.example.com/callback", "agent-jwt")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if result.AuthToken != "auth-jwt" || result.RequestType != "code" {
		t.Errorf("result = %+v", result)
	}

	body := calls[0].Body
	if body["request_type"] != "code" || body["code"] != "consent-code" {
		t.Errorf("body = %v", body)
	}
	// The redirect URI must match the one the code was delivered to.
	if body["redirect_uri"] != "https://app.example.com/callback" {
		t.Errorf("redirect_uri = %v", body["redirect_uri"])
	}

	// A missing redirect URI is caught client-side.
	if _, err := client.ExchangeCode(context.Background(), "code", "", "agent-jwt"); !errors.Is(err, ErrValidation) {
		t.Errorf("expected a validation error without a redirect URI, got %v", err)
	}
}

func TestAAuthExchangeToken(t *testing.T) {
	var calls []aauthCall
	client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"request_type": "exchange", "auth_token": "downstream-jwt", "expires_in": 600,
		})
	})

	result, err := client.ExchangeToken(context.Background(),
		"upstream-auth-jwt", "downstream-resource-jwt", "agent-jwt")
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if result.AuthToken != "downstream-jwt" {
		t.Errorf("result = %+v", result)
	}

	body := calls[0].Body
	if body["request_type"] != "exchange" || body["auth_token"] != "upstream-auth-jwt" {
		t.Errorf("body = %v", body)
	}
}

func TestAAuthRefresh(t *testing.T) {
	var calls []aauthCall
	client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"request_type": "refresh", "auth_token": "fresh-jwt", "expires_in": 900,
		})
	})

	ctx := context.Background()
	result, err := client.Refresh(ctx, RefreshParams{
		RefreshToken:  "refresh-value",
		ResourceToken: "fresh-resource-jwt",
		Scope:         "read",
		AgentToken:    "agent-jwt",
	})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if result.AuthToken != "fresh-jwt" {
		t.Errorf("result = %+v", result)
	}

	body := calls[0].Body
	if body["resource_token"] != "fresh-resource-jwt" || body["scope"] != "read" {
		t.Errorf("body = %v", body)
	}

	// The server requires a fresh resource token on every refresh, so the
	// SDK refuses to send a request that would certainly fail.
	if _, err := client.Refresh(ctx, RefreshParams{
		RefreshToken: "refresh-value", AgentToken: "agent-jwt",
	}); !errors.Is(err, ErrValidation) {
		t.Errorf("expected a validation error without a resource token, got %v", err)
	}
}

func TestAAuthRevoke(t *testing.T) {
	var calls []aauthCall
	client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"revoked": true})
	})

	if err := client.Revoke(context.Background(), "token-jti", AAuthTokenTypeAuth, "agent-jwt"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	call := calls[0]
	if call.Path != "/orgs/acme-corp/api/v1/aauth/token/revoke" {
		t.Errorf("path = %q", call.Path)
	}
	if call.Body["token"] != "token-jti" || call.Body["token_type"] != AAuthTokenTypeAuth {
		t.Errorf("body = %v", call.Body)
	}
}

func TestAAuthConsentURL(t *testing.T) {
	var calls []aauthCall
	client, _, server := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {})

	got, err := client.ConsentURL("req token/with chars")
	if err != nil {
		t.Fatalf("ConsentURL: %v", err)
	}

	want := server.URL + "/orgs/acme-corp/api/v1/aauth/agent/auth?request_token=req+token%2Fwith+chars"
	if got != want {
		t.Errorf("ConsentURL = %q, want %q", got, want)
	}
}

func TestAAuthSignedRequest(t *testing.T) {
	var calls []aauthCall
	client, keypair, server := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	response, err := client.SignedRequest(context.Background(), http.MethodPost,
		server.URL+"/v1/data", "auth-jwt", map[string]any{"query": "everything"})
	if err != nil {
		t.Fatalf("SignedRequest: %v", err)
	}
	defer response.Body.Close()

	call := calls[0]
	if call.Headers.Get("Authorization") != "Bearer auth-jwt" {
		t.Errorf("Authorization = %q", call.Headers.Get("Authorization"))
	}
	// The signature covers the authorization component, binding the
	// proof-of-possession to this exact bearer token.
	verifySentSignature(t, call, keypair, http.MethodPost)

	var sent map[string]any
	if err := json.Unmarshal(call.RawBody, &sent); err != nil {
		t.Fatalf("the body was not sent as JSON: %v", err)
	}
	if sent["query"] != "everything" {
		t.Errorf("body = %v", sent)
	}
}

func TestAAuthDiscovery(t *testing.T) {
	ctx := context.Background()

	t.Run("issuer metadata", func(t *testing.T) {
		var calls []aauthCall
		client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{
				"issuer":                  "https://auth.test/orgs/acme-corp/api/v1",
				"aauth_version":           "1.0",
				"jwks_uri":                "https://auth.test/orgs/acme-corp/api/v1/aauth/jwks.json",
				"request_types_supported": []string{"auth", "code", "exchange", "refresh"},
			})
		})

		metadata, err := client.DiscoverIssuer(ctx)
		if err != nil {
			t.Fatalf("DiscoverIssuer: %v", err)
		}
		if metadata.AAuthVersion != "1.0" || len(metadata.RequestTypesSupported) != 4 {
			t.Errorf("metadata = %+v", metadata)
		}
		if calls[0].Path != "/orgs/acme-corp/api/v1/.well-known/aauth-issuer" {
			t.Errorf("path = %q", calls[0].Path)
		}
	})

	t.Run("agent metadata accepts one object or many", func(t *testing.T) {
		var calls []aauthCall
		client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{
				"agent": "https://my-agent.example.com", "jwks_uri": "https://my-agent.example.com/jwks",
			})
		})

		agents, err := client.DiscoverAgents(ctx)
		if err != nil {
			t.Fatalf("DiscoverAgents: %v", err)
		}
		if len(agents) != 1 || agents[0].Agent != "https://my-agent.example.com" {
			t.Errorf("agents = %+v", agents)
		}
	})

	t.Run("resource metadata", func(t *testing.T) {
		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/aauth-resource" {
				t.Errorf("path = %q", r.URL.Path)
			}
			writeJSON(w, 200, []map[string]any{
				{"resource": "https://api.example.com", "supported_scopes": []string{"read"}},
			})
		}))
		defer resourceServer.Close()

		var calls []aauthCall
		client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {})

		resources, err := client.DiscoverResource(ctx, resourceServer.URL+"/")
		if err != nil {
			t.Fatalf("DiscoverResource: %v", err)
		}
		if len(resources) != 1 || resources[0].Resource != "https://api.example.com" {
			t.Errorf("resources = %+v", resources)
		}
	})

	t.Run("jwks", func(t *testing.T) {
		keypair, _ := GenerateKeypair("issuer-key")
		var calls []aauthCall
		client, _, _ := newTestAAuthClient(t, &calls, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, keypair.JWKS)
		})

		keys, err := client.JWKS(ctx)
		if err != nil {
			t.Fatalf("JWKS: %v", err)
		}
		if _, found := keys.Find("issuer-key"); !found {
			t.Errorf("keys = %+v", keys)
		}
		if calls[0].Path != "/orgs/acme-corp/api/v1/aauth/jwks.json" {
			t.Errorf("path = %q", calls[0].Path)
		}
	})
}

func TestAAuthRequiresAnOrgID(t *testing.T) {
	t.Setenv(EnvOrgID, "")

	keypair, _ := GenerateKeypair("")
	client, err := NewAAuthClient(AAuthConfig{
		AgentIdentifier: "https://my-agent.example.com",
		PrivateKeyPEM:   keypair.PrivateKeyPEM,
		BaseURL:         "https://auth.test",
	})
	if err != nil {
		t.Fatalf("NewAAuthClient: %v", err)
	}

	_, err = client.RequestAuthToken(context.Background(), AuthTokenParams{
		ResourceToken: "resource-jwt", AgentToken: "agent-jwt",
	})
	if !errors.Is(err, ErrConfig) {
		t.Errorf("expected a config error without an org ID, got %v", err)
	}
}
