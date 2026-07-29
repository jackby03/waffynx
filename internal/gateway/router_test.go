package gateway

import (
	"testing"

	"github.com/jackby03/waffynx/internal/config"
)

func TestRouter_Match_ExactPath(t *testing.T) {
	router := NewRouter()
	err := router.AddRoute(&config.RouteConfig{
		Name:     "exact-route",
		Host:     "example.com",
		Path:     "/api/v1/users",
		Upstream: "http://localhost:8080",
		Methods:  []string{"GET"},
	})
	if err != nil {
		t.Fatalf("unexpected error adding route: %v", err)
	}

	route, params := router.Match("example.com", "/api/v1/users", "GET")
	if route == nil {
		t.Fatal("expected route match, got nil")
	}
	if route.Name != "exact-route" {
		t.Errorf("expected route name 'exact-route', got %s", route.Name)
	}
	if params["path"] != "/api/v1/users" {
		t.Errorf("expected path param '/api/v1/users', got %s", params["path"])
	}
}

func TestRouter_Match_PrefixWildcard(t *testing.T) {
	router := NewRouter()
	err := router.AddRoute(&config.RouteConfig{
		Name:     "wildcard-route",
		Host:     "*.example.com",
		Path:     "/static/*",
		Upstream: "http://localhost:8081",
	})
	if err != nil {
		t.Fatalf("unexpected error adding route: %v", err)
	}

	route, _ := router.Match("cdn.example.com", "/static/js/app.js", "GET")
	if route == nil {
		t.Fatal("expected wildcard host and path match, got nil")
	}
	if route.Name != "wildcard-route" {
		t.Errorf("expected route name 'wildcard-route', got %s", route.Name)
	}
}

func TestRouter_Match_NoMatch(t *testing.T) {
	router := NewRouter()
	_ = router.AddRoute(&config.RouteConfig{
		Name:     "api-route",
		Host:     "api.example.com",
		Path:     "/v1/*",
		Upstream: "http://localhost:8080",
	})

	// Host mismatch
	route, _ := router.Match("other.example.com", "/v1/users", "GET")
	if route != nil {
		t.Errorf("expected nil for host mismatch, got %v", route)
	}

	// Path mismatch
	route, _ = router.Match("api.example.com", "/v2/users", "GET")
	if route != nil {
		t.Errorf("expected nil for path mismatch, got %v", route)
	}
}

func TestRouter_Match_MethodAllowed(t *testing.T) {
	router := NewRouter()
	_ = router.AddRoute(&config.RouteConfig{
		Name:     "read-only-route",
		Host:     "example.com",
		Path:     "/data",
		Methods:  []string{"GET", "HEAD"},
		Upstream: "http://localhost:8080",
	})

	// GET should be allowed
	route, _ := router.Match("example.com", "/data", "GET")
	if route == nil {
		t.Error("expected GET to match route")
	}

	// HEAD should be allowed
	route, _ = router.Match("example.com", "/data", "HEAD")
	if route == nil {
		t.Error("expected HEAD to match route")
	}

	// POST should NOT match
	route, _ = router.Match("example.com", "/data", "POST")
	if route != nil {
		t.Errorf("expected POST to NOT match GET-only route, got %v", route)
	}
}

func TestRouter_Match_NoMethodsFilter(t *testing.T) {
	router := NewRouter()
	_ = router.AddRoute(&config.RouteConfig{
		Name:     "all-methods-route",
		Host:     "example.com",
		Path:     "/open",
		Methods:  []string{}, // Empty = any method
		Upstream: "http://localhost:8080",
	})

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		route, _ := router.Match("example.com", "/open", method)
		if route == nil {
			t.Errorf("expected method %s to match route with empty methods list", method)
		}
	}
}

func TestRouter_Match_Priority(t *testing.T) {
	router := NewRouter()

	// Route 1 (added first)
	_ = router.AddRoute(&config.RouteConfig{
		Name:     "route-first",
		Host:     "example.com",
		Path:     "/api/*",
		Upstream: "http://localhost:8080",
	})

	// Route 2 (added second)
	_ = router.AddRoute(&config.RouteConfig{
		Name:     "route-second",
		Host:     "example.com",
		Path:     "/api/specific",
		Upstream: "http://localhost:8081",
	})

	// First matching route in registration order wins
	route, _ := router.Match("example.com", "/api/specific", "GET")
	if route == nil {
		t.Fatal("expected route match")
	}
	if route.Name != "route-first" {
		t.Errorf("expected first registered route 'route-first' to win, got %s", route.Name)
	}
}
