package lumoauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Drift detection: every route in the registry must exist in the OpenAPI
// spec the server publishes.
//
// This is the Go half of the same check the JS and Python SDKs run
// (sdk-js/packages/shared/tests/route-drift.test.mjs,
// sdk-python/tests/test_route_drift.py). It catches the failure mode where
// a controller route is renamed server-side and the hand-written SDK keeps
// calling the old path — which otherwise shows up as a 404 in production.
//
// Placeholder names are normalised before comparison, so {orgId} and
// {org_id} compare equal.

// knownDrift lists routes the server serves but the spec does not
// document. They are exercised against the live server; revisit when spec
// coverage catches up.
var knownDrift = map[string]string{
	RouteWebCheckEmail: "served by the web firewall, not the JSON API",
	RouteWebMagicLink:  "served by the web firewall, not the JSON API",
	RouteWellKnownAAuthIssuer: "served at the instance root; the spec only documents " +
		"the org-scoped /orgs/{orgId}/api/v1/.well-known/aauth-issuer",
}

var placeholderPattern = regexp.MustCompile(`\{[^}]+\}`)

// normalizePath collapses placeholder names so naming conventions do not
// register as drift.
func normalizePath(path string) string {
	return placeholderPattern.ReplaceAllString(path, "{}")
}

type specPair struct {
	method string
	path   string
}

// loadSpecPairs reads every (method, path) pair from the OpenAPI spec,
// returning the file it used.
func loadSpecPairs(t *testing.T) (map[specPair]bool, string) {
	t.Helper()

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	candidates := []string{
		filepath.Join(repoRoot, "server", "openapi.json"),
		filepath.Join(repoRoot, "api-clients", "openapi.json"),
	}

	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}

		var spec struct {
			Paths map[string]map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(data, &spec); err != nil {
			t.Fatalf("parsing %s: %v", candidate, err)
		}

		pairs := map[specPair]bool{}
		for path, operations := range spec.Paths {
			for method := range operations {
				switch strings.ToUpper(method) {
				case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD":
					pairs[specPair{strings.ToUpper(method), normalizePath(path)}] = true
				}
			}
		}
		return pairs, candidate
	}
	return nil, ""
}

func TestRoutesExistInOpenAPISpec(t *testing.T) {
	pairs, specFile := loadSpecPairs(t)
	if pairs == nil {
		t.Skip("openapi.json not found in server/ or api-clients/")
	}

	for _, name := range RouteNames() {
		if _, drift := knownDrift[name]; drift {
			continue
		}
		route := Routes[name]

		t.Run(name, func(t *testing.T) {
			if !pairs[specPair{route.Method, normalizePath(route.Path)}] {
				t.Errorf("route %q (%s %s) is not in %s.\n"+
					"Either the SDK path drifted from the server, or this is "+
					"intentional drift that belongs in knownDrift.",
					name, route.Method, route.Path, specFile)
			}
		})
	}
}

func TestKnownDriftIsStillAbsentFromSpec(t *testing.T) {
	pairs, specFile := loadSpecPairs(t)
	if pairs == nil {
		t.Skip("openapi.json not found in server/ or api-clients/")
	}

	names := make([]string, 0, len(knownDrift))
	for name := range knownDrift {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		route, ok := Routes[name]
		if !ok {
			t.Errorf("knownDrift names %q, which is not in the registry", name)
			continue
		}
		if pairs[specPair{route.Method, normalizePath(route.Path)}] {
			t.Errorf("route %q now exists in %s — remove it from knownDrift", name, specFile)
		}
	}
}

func TestRouteRegistryMatchesOtherSDKs(t *testing.T) {
	// The three route registries are meant to stay in lockstep. Compare
	// against the JS registry, which is the widest of the three, so an
	// endpoint added there but not here is visible.
	source, err := os.ReadFile(filepath.Join("..", "sdk-js", "packages", "shared", "src", "routes.ts"))
	if err != nil {
		t.Skip("sdk-js routes.ts not found")
	}

	// Paths in routes.ts appear as: path: '/orgs/{orgId}/…'
	pathPattern := regexp.MustCompile(`path:\s*'([^']+)'`)
	jsPaths := map[string]bool{}
	for _, match := range pathPattern.FindAllStringSubmatch(string(source), -1) {
		jsPaths[normalizePath(match[1])] = true
	}
	if len(jsPaths) == 0 {
		t.Skip("no paths parsed from sdk-js routes.ts")
	}

	goPaths := map[string]bool{}
	for _, route := range Routes {
		goPaths[normalizePath(route.Path)] = true
	}

	var missing []string
	for path := range jsPaths {
		if !goPaths[path] {
			missing = append(missing, path)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Errorf("the JS SDK calls %d endpoint(s) this SDK does not:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}
