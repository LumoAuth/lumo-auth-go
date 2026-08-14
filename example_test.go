package lumoauth_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	lumoauth "github.com/lumoauth/lumo-auth-go"
)

// The general-purpose client: check a permission for the authenticated
// principal.
func ExampleNew() {
	client, err := lumoauth.New(
		lumoauth.WithAPIKey(os.Getenv("LUMOAUTH_API_KEY")),
		lumoauth.WithOrgID("acme-corp"),
	)
	if err != nil {
		log.Fatal(err)
	}

	allowed, err := client.Permissions.Check(context.Background(), "document.edit", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(allowed)
}

// Relationship-based checks read as questions about a tuple.
func ExampleZanzibarResource_Check() {
	client, _ := lumoauth.New(
		lumoauth.WithAPIKey(os.Getenv("LUMOAUTH_API_KEY")),
		lumoauth.WithOrgID("acme-corp"),
	)

	allowed, err := client.Zanzibar.Check(context.Background(),
		"document:readme", lumoauth.RelationViewer, "user:bob")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(allowed)
}

// ABAC decisions carry the policies that produced them.
func ExampleAbacResource_Check() {
	client, _ := lumoauth.New(
		lumoauth.WithAPIKey(os.Getenv("LUMOAUTH_API_KEY")),
		lumoauth.WithOrgID("acme-corp"),
	)

	decision, err := client.Abac.Check(context.Background(), lumoauth.AbacCheckParams{
		ResourceType: "document",
		Action:       "read",
		ResourceID:   "doc-123",
		Context: map[string]any{
			"environment": map[string]any{"ip": "10.0.0.1"},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	if !decision.Allowed {
		fmt.Println("denied:", decision.Reason)
		return
	}
	for _, policy := range decision.MatchedPolicies {
		fmt.Printf("matched %s (%s)\n", policy.Name, policy.Effect)
	}
}

// An agent checks whether it may act before acting.
func ExampleNewAgent() {
	agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	allowed, err := agent.IsAllowed(ctx, "document.read", map[string]any{"id": "doc_99"})
	if err != nil {
		log.Fatal(err)
	}
	if !allowed {
		return
	}
	// ... read the document
}

// Capability gating at the top of a tool implementation.
func ExampleAgent_RequireCapability() {
	agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{})
	if err != nil {
		log.Fatal(err)
	}

	if err := agent.RequireCapability(context.Background(), "tool:search_web"); err != nil {
		if errors.Is(err, lumoauth.ErrPermissionDenied) {
			fmt.Println("this agent is not registered for web search")
			return
		}
		log.Fatal(err)
	}
	// ... run the search
}

// Human approval before an irreversible action. Require returns an error
// for anything except approval, so the happy path reads as a guard.
func ExampleApprovalsResource_Require() {
	agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{})
	if err != nil {
		log.Fatal(err)
	}

	approval, err := agent.Approvals.Require(context.Background(), lumoauth.ApprovalParams{
		TaskID:     "wire-2026-05-07-001",
		Reason:     "Wire $4,500 to vendor INV-7741",
		Impact:     lumoauth.ImpactHigh,
		OnBehalfOf: "ada@acme.com",
		Meta:       map[string]any{"amount": 4500, "vendor": "INV-7741"},
	}, nil)

	switch {
	case errors.Is(err, lumoauth.ErrApprovalDenied):
		fmt.Println("a human declined the transfer")
		return
	case errors.Is(err, lumoauth.ErrApprovalTimeout):
		fmt.Println("nobody responded in time")
		return
	case err != nil:
		log.Fatal(err)
	}

	// approval.Token authorises the side-effecting call.
	fmt.Println("approved by", approval.ApprovedBy.Email)
}

// A JIT task scopes permissions to one unit of work, and revokes every
// token it issued when the task closes.
func ExampleNewJITContext() {
	agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{})
	if err != nil {
		log.Fatal(err)
	}

	jit, err := lumoauth.NewJITContext(agent)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	defer jit.Close(ctx) // completes the task and revokes its tokens

	if _, err := jit.CreateTask(ctx, lumoauth.CreateTaskParams{
		Name: "Analyse Q4 report",
		Type: "analysis",
	}); err != nil {
		log.Fatal(err)
	}

	result, err := jit.RequestPermission(ctx, map[string]any{
		"type":       "file_access",
		"actions":    []string{"read"},
		"identifier": "report_q4.pdf",
	}, &lumoauth.RequestPermissionOptions{
		Justification: "The user asked for a Q4 summary",
	})
	if err != nil {
		log.Fatal(err)
	}
	if !result.Approved() {
		fmt.Println("not approved:", result.Status)
		return
	}

	token, err := jit.Token(ctx, result.RequestID)
	if err != nil {
		log.Fatal(err)
	}
	_ = token // present it to the resource
}

// Acting on behalf of a user, with the chain recorded in the token.
func ExampleNewDelegationChain() {
	agent, err := lumoauth.NewAgent(lumoauth.AgentConfig{})
	if err != nil {
		log.Fatal(err)
	}

	chain := lumoauth.NewDelegationChain(agent, "https://agent.example.com/callback")
	ctx := context.Background()

	// 1. Send the user here to grant consent.
	consentURL, err := chain.ConsentURL("session-1", []string{"read:documents"}, "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("visit:", consentURL)

	// 2. Your callback receives ?code=…
	if err := chain.HandleConsentCallback(ctx, "session-1", "code-from-callback"); err != nil {
		log.Fatal(err)
	}

	// 3. Call as "agent acting for user". The exchange happens on demand.
	var documents struct {
		Data []map[string]any `json:"data"`
	}
	if err := chain.Do(ctx, "session-1", http.MethodGet,
		"/orgs/acme-corp/api/v1/documents", nil, &documents); err != nil {
		log.Fatal(err)
	}
}

// Browser sign-in over the Authorization Code + PKCE flow.
func ExampleNewWebAuth() {
	auth, err := lumoauth.NewWebAuth(lumoauth.WebConfig{
		Organization:  os.Getenv("LUMO_ORG_ID"),
		ClientID:      os.Getenv("LUMO_CLIENT_ID"),
		ClientSecret:  os.Getenv("LUMO_CLIENT_SECRET"),
		SessionSecret: os.Getenv("SESSION_SECRET"),
	})
	if err != nil {
		log.Fatal(err)
	}

	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := lumoauth.UserFromContext(r.Context())
		fmt.Fprintf(w, "Hi %s", user.Email)
	})

	mux := http.NewServeMux()
	mux.Handle("/auth/", auth.Router())
	mux.Handle("/", auth.Middleware(auth.RequireAuth(dashboard)))

	log.Fatal(http.ListenAndServe(":8080", mux))
}

// An AAuth agent signs its requests with its own key.
func ExampleNewAAuthClient() {
	client, err := lumoauth.NewAAuthClient(lumoauth.AAuthConfig{
		AgentIdentifier: "https://my-agent.example.com",
		PrivateKeyPEM:   os.Getenv("AGENT_PRIVATE_KEY"),
		OrgID:           "acme-corp",
	})
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.RequestAuthToken(context.Background(), lumoauth.AuthTokenParams{
		ResourceToken: os.Getenv("RESOURCE_TOKEN"),
		Scope:         "read write",
		AgentToken:    os.Getenv("AGENT_TOKEN"),
	})
	if err != nil {
		log.Fatal(err)
	}

	if result.AuthorizationRequired {
		fmt.Println("send the user to:", result.AuthorizationURI)
		return
	}

	response, err := client.SignedRequest(context.Background(),
		http.MethodGet, "https://api.example.com/v1/data", result.AuthToken, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
}

// Publish a JWKS so LumoAuth can verify the agent's signatures.
func ExampleGenerateKeypair() {
	keypair, err := lumoauth.GenerateKeypair("")
	if err != nil {
		log.Fatal(err)
	}

	// Store this in a secret manager.
	_ = keypair.PrivateKeyPEM
	// Register this with LumoAuth, or serve it at /.well-known/jwks.json.
	_ = keypair.JWKS

	fmt.Println(keypair.JWK.Kty, keypair.JWK.Crv, keypair.JWK.Kid)
	// Output: OKP Ed25519 key-1
}

// The resource-server side: verify the token, then prove the caller holds
// the key it is bound to.
func ExampleVerifyAuthToken() {
	handler := func(w http.ResponseWriter, r *http.Request, body []byte) {
		token := r.Header.Get("Authorization")[len("Bearer "):]

		claims, err := lumoauth.VerifyAuthToken(r.Context(), token, lumoauth.VerifyOptions{
			Issuer:   "https://app.lumoauth.dev/orgs/acme-corp/api/v1",
			Resource: "https://api.example.com",
		})
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// AAuth tokens are proof-of-possession: verifying the JWT alone
		// would let a stolen token through.
		if err := claims.VerifyProofOfPossession(r, body); err != nil {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}

		if !claims.HasScope("read") {
			http.Error(w, "insufficient scope", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "hello %s", claims.Agent)
	}
	_ = handler
}

// Reaching past the curated namespaces to the rest of the REST API.
func ExampleClient_Do() {
	client, err := lumoauth.New(
		lumoauth.WithAPIKey(os.Getenv("LUMOAUTH_API_KEY")),
		lumoauth.WithOrgID("acme-corp"),
	)
	if err != nil {
		log.Fatal(err)
	}

	path, err := client.OrgPath("/admin/users")
	if err != nil {
		log.Fatal(err)
	}

	var page struct {
		Data []map[string]any `json:"data"`
	}
	if err := client.Do(context.Background(), http.MethodGet, path, nil, &page); err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(page.Data), "users")
}

// Errors are matched with the standard library.
func Example_errorHandling() {
	client, err := lumoauth.New(
		lumoauth.WithAPIKey(os.Getenv("LUMOAUTH_API_KEY")),
		lumoauth.WithOrgID("acme-corp"),
	)
	if err != nil {
		log.Fatal(err)
	}

	_, err = client.Permissions.Check(context.Background(), "document.edit", nil)
	switch {
	case err == nil:
		// allowed or denied — check the returned bool

	case errors.Is(err, lumoauth.ErrAuthentication):
		fmt.Println("the credential is invalid or expired")

	case errors.Is(err, lumoauth.ErrRateLimited):
		var apiErr *lumoauth.APIError
		errors.As(err, &apiErr)
		fmt.Println("retry after", apiErr.RetryAfter)

	case errors.Is(err, lumoauth.ErrNetwork):
		fmt.Println("could not reach LumoAuth:", err)

	default:
		fmt.Println("unexpected:", err)
	}
}
