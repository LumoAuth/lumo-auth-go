package lumoauth

// Conformance against the cross-SDK contract (../sdk-contract):
//
//  1. every entry in Routes exists in routes.json (same method, placeholder
//     names ignored);
//  2. every contract route in a namespace this SDK claims (features.json)
//     is in Routes, unless listed in known_missing_routes with a reason;
//  3. every error code in errors.json is one of the Code* constants;
//  4. a body code of body_code_map gives its class and its parents.
//
// Skips when the contract is not checked out next to sdk-go
// (LUMO_SDK_CONTRACT overrides).

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

type contractRoute struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Method    string `json:"method"`
	Path      string `json:"path"`
}

var placeholder = regexp.MustCompile(`\{[^}]+\}`)

func contractDir(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("LUMO_SDK_CONTRACT"), filepath.Join("..", "sdk-contract")}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(c, "routes.json")); err == nil {
			return c
		}
	}
	t.Skip("sdk-contract not found (set LUMO_SDK_CONTRACT)")
	return ""
}

func loadContract(t *testing.T, dir, file string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
}

func routeKey(method, path string) string {
	return method + " " + placeholder.ReplaceAllString(path, "{}")
}

func TestContractRoutes(t *testing.T) {
	dir := contractDir(t)
	var contract struct {
		Routes []contractRoute `json:"routes"`
	}
	loadContract(t, dir, "routes.json", &contract)
	var features struct {
		SDKs map[string]struct {
			Namespaces         []string          `json:"namespaces"`
			KnownMissingRoutes map[string]string `json:"known_missing_routes"`
		} `json:"sdks"`
	}
	loadContract(t, dir, "features.json", &features)
	me, ok := features.SDKs["go"]
	if !ok {
		t.Fatal("features.json has no 'go' entry")
	}

	known := map[string]contractRoute{}
	for _, r := range contract.Routes {
		known[routeKey(r.Method, r.Path)] = r
	}
	have := map[string]bool{}
	for name, r := range Routes {
		key := routeKey(r.Method, r.Path)
		have[key] = true
		if _, ok := known[key]; !ok {
			t.Errorf("%s (%s %s) is not in sdk-contract/routes.json", name, r.Method, r.Path)
		}
	}
	claimed := map[string]bool{}
	for _, ns := range me.Namespaces {
		claimed[ns] = true
	}
	for _, r := range contract.Routes {
		if !claimed[r.Namespace] {
			continue
		}
		present := have[routeKey(r.Method, r.Path)]
		if _, allowed := me.KnownMissingRoutes[r.Name]; allowed {
			if present {
				t.Errorf("%s is listed in known_missing_routes but Routes has it — remove the entry", r.Name)
			}
			continue
		}
		if !present {
			t.Errorf("contract route %s (%s %s) is missing from Routes", r.Name, r.Method, r.Path)
		}
	}
}

func TestContractErrorCodes(t *testing.T) {
	dir := contractDir(t)
	var contract struct {
		Errors []struct {
			Name string `json:"name"`
			Code string `json:"code"`
			Go   string `json:"go"`
		} `json:"errors"`
	}
	loadContract(t, dir, "errors.json", &contract)
	codes := map[string]bool{
		CodeError: true, CodeAPI: true, CodeAuthentication: true, CodePermissionDenied: true,
		CodeNotFound: true, CodeRateLimited: true, CodeValidation: true, CodeConfig: true,
		CodeNetwork: true, CodeApprovalDenied: true, CodeApprovalTimeout: true, CodeApprovalNotDelivered: true,
		CodeBudgetExceeded: true,
	}
	for _, e := range contract.Errors {
		if !codes[e.Code] {
			t.Errorf("%s: code %q has no Code* constant in errors.go", e.Name, e.Code)
		}
	}
	if len(codes) != len(contract.Errors) {
		t.Errorf("errors.go defines %d codes, the contract %d", len(codes), len(contract.Errors))
	}
}

func TestContractTokenTypes(t *testing.T) {
	dir := contractDir(t)
	var contract struct {
		Types map[string]struct {
			URN   string            `json:"urn"`
			Names map[string]string `json:"names"`
		} `json:"types"`
	}
	loadContract(t, dir, "token-types.json", &contract)
	constants := map[string]string{
		"TokenTypeAccessToken":  TokenTypeAccessToken,
		"TokenTypeJWT":          TokenTypeJWT,
		"TokenTypeIDToken":      TokenTypeIDToken,
		"TokenTypeRefreshToken": TokenTypeRefreshToken,
	}
	for key, spec := range contract.Types {
		got, ok := constants[spec.Names["go"]]
		if !ok {
			t.Errorf("%s: constant %s is not defined in resource_auth.go", key, spec.Names["go"])
			continue
		}
		if got != spec.URN {
			t.Errorf("%s: %s = %q, contract %q", key, spec.Names["go"], got, spec.URN)
		}
	}
	if len(constants) != len(contract.Types) {
		t.Errorf("resource_auth.go defines %d token types, the contract %d", len(constants), len(contract.Types))
	}
}

// TestContractBodyCodeMap: a response whose body code is a key of
// body_code_map raises that class, which still is every one of its parents
// (errors.json body_code_semantics). In Go "is" means errors.Is with the
// sentinel of each class in the chain, and errors.As finds the class's type.
func TestContractBodyCodeMap(t *testing.T) {
	dir := contractDir(t)
	var contract struct {
		BodyCodeMap map[string]string `json:"body_code_map"`
		BodyFields  struct {
			Code []string `json:"code"`
		} `json:"api_error_body_fields"`
		Errors []struct {
			Name   string `json:"name"`
			Parent string `json:"parent"`
			Status *int   `json:"status"`
			Go     string `json:"go"`
		} `json:"errors"`
	}
	loadContract(t, dir, "errors.json", &contract)
	if len(contract.BodyCodeMap) == 0 {
		t.Fatal("errors.json has no body_code_map")
	}

	sentinels := map[string]error{
		"LumoAuthError":                 ErrLumoAuth,
		"LumoAuthApiError":              ErrAPI,
		"LumoAuthAuthenticationError":   ErrAuthentication,
		"LumoAuthPermissionDeniedError": ErrPermissionDenied,
		"LumoAuthNotFoundError":         ErrNotFound,
		"LumoAuthRateLimitError":        ErrRateLimited,
		"LumoAuthBudgetExceededError":   ErrBudgetExceeded,
	}
	classes := map[string]int{}
	for i, e := range contract.Errors {
		classes[e.Name] = i
	}

	for bodyCode, class := range contract.BodyCodeMap {
		i, ok := classes[class]
		if !ok {
			t.Errorf("body_code_map names %s, which errors.json does not define", class)
			continue
		}
		status := 400
		if contract.Errors[i].Status != nil {
			status = *contract.Errors[i].Status
		}
		// The code may arrive in any of the body fields that the contract lists.
		for _, field := range contract.BodyFields.Code {
			body, _ := json.Marshal(map[string]any{field: bodyCode, "error_description": "refused"})
			resp := &http.Response{StatusCode: status, Header: http.Header{"Retry-After": {"7"}}}
			err := error(apiErrorFromResponse(resp, body))

			for c := class; c != ""; {
				j := classes[c]
				if sentinel, ok := sentinels[c]; ok && !errors.Is(err, sentinel) {
					t.Errorf("%s in %q: the error does not match the sentinel of %s", bodyCode, field, c)
				}
				c = contract.Errors[j].Parent
			}
			switch contract.Errors[i].Go {
			case "BudgetError":
				var typed *BudgetError
				if !errors.As(err, &typed) {
					t.Errorf("%s in %q: errors.As(*BudgetError) = false", bodyCode, field)
				} else if typed.RetryAfter != 7*time.Second {
					t.Errorf("%s in %q: RetryAfter = %v, want 7s", bodyCode, field, typed.RetryAfter)
				}
			default:
				t.Errorf("%s: no errors.As check for the Go type %q; add one", class, contract.Errors[i].Go)
			}
		}
	}
}
