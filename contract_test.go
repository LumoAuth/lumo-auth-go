package lumoauth

// Conformance against the cross-SDK contract (../sdk-contract):
//
//  1. every entry in Routes exists in routes.json (same method, placeholder
//     names ignored);
//  2. every contract route in a namespace this SDK claims (features.json)
//     is in Routes, unless listed in known_missing_routes with a reason;
//  3. every error code in errors.json is one of the Code* constants.
//
// Skips when the contract is not checked out next to sdk-go
// (LUMO_SDK_CONTRACT overrides).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
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
		CodeNetwork: true, CodeApprovalDenied: true, CodeApprovalTimeout: true, CodeBudgetExceeded: true,
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
