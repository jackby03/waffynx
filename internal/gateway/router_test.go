package gateway

import (
	"testing"

	"github.com/jackby03/waffynx/internal/config"
)

func TestRouter_Match_ExactPath(t *testing.T) {
	r := NewRouter()
	r.AddRoute(&config.RouteConfig{
		Name:     "test",
		Host:     "example.com",
		Path:     "/api/v1/health",
		Upstream: "http://backend:8080",
	})

	route, _ := r.Match("example.com", "/api/v1/health", "GET")
	if route == nil {
		t.Fatal("expected route to match exact path")
	}
	if route.Name != "test" {
		t.Fatalf("expected route name 'test', got '%s'", route.Name)
	}
}

func TestRouter_Match_NoMatch(t *testing.T) {
	r := NewRouter()
	r.AddRoute(&config.RouteConfig{
		Name:     "test",
		Host:     "example.com",
		Path:     "/api/v1/health",
		Upstream: "http://backend:8080",
	})

	route, _ := r.Match("example.com", "/api/v1/notfound", "GET")
	if route != nil {
		t.Fatal("expected no match for unknown path")
	}
}

func TestRouter_Match_WrongHost(t *testing.T) {
	r := NewRouter()
	r.AddRoute(&config.RouteConfig{
		Name:     "test",
		Host:     "example.com",
		Path:     "/api/v1/health",
		Upstream: "http://backend:8080",
	})

	route, _ := r.Match("other.com", "/api/v1/health", "GET")
	if route != nil {
		t.Fatal("expected no match for wrong host")
	}
}

func TestRouter_Match_WildcardPath(t *testing.T) {
	r := NewRouter()
	r.AddRoute(&config.RouteConfig{
		Name:     "test",
		Host:     "example.com",
		Path:     "/api/v1/*",
		Upstream: "http://backend:8080",
	})

	route, _ := r.Match("example.com", "/api/v1/users", "GET")
	if route == nil {
		t.Fatal("expected wildcard path to match")
	}
}

func TestRouter_Match_MethodAllowed(t *testing.T) {
	r := NewRouter()
	r.AddRoute(&config.RouteConfig{
		Name:     "test",
		Host:     "example.com",
		Path:     "/api/v1/data",
		Methods:  []string{"GET", "POST"},
		Upstream: "http://backend:8080",
	})

	route, _ := r.Match("example.com", "/api/v1/data", "GET")
	if route == nil {
		t.Fatal("expected GET to match route allowing GET")
	}
}

func TestRouter_Match_MethodDenied(t *testing.T) {
	r := NewRouter()
	r.AddRoute(&config.RouteConfig{
		Name:     "test",
		Host:     "example.com",
		Path:     "/api/v1/data",
		Methods:  []string{"GET"},
		Upstream: "http://backend:8080",
	})

	route, _ := r.Match("example.com", "/api/v1/data", "POST")
	if route != nil {
		t.Fatal("expected POST to not match GET-only route")
	}
}

func TestRouter_Match_NoMethods(t *testing.T) {
	r := NewRouter()
	r.AddRoute(&config.RouteConfig{
		Name:     "test",
		Host:     "example.com",
		Path:     "/api/v1/data",
		Upstream: "http://backend:8080",
	})

	route, _ := r.Match("example.com", "/api/v1/data", "DELETE")
	if route == nil {
		t.Fatal("expected any method to match route with no method restrictions")
	}
}

func TestRouter_Match_FirstMatchWins(t *testing.T) {
	r := NewRouter()
	r.AddRoute(&config.RouteConfig{
		Name:     "first",
		Host:     "example.com",
		Path:     "/api/*",
		Methods:  []string{"GET"},
		Upstream: "http://first:8080",
	})
	r.AddRoute(&config.RouteConfig{
		Name:     "second",
		Host:     "example.com",
		Path:     "/api/*",
		Upstream: "http://second:8080",
	})

	route, _ := r.Match("example.com", "/api/v1/data", "GET")
	if route == nil {
		t.Fatal("expected first route to match")
	}
	if route.Name != "first" {
		t.Fatalf("expected first route, got '%s'", route.Name)
	}

	route, _ = r.Match("example.com", "/api/v1/data", "POST")
	if route == nil {
		t.Fatal("expected second route to match when first rejects by method")
	}
	if route.Name != "second" {
		t.Fatalf("expected second route, got '%s'", route.Name)
	}
}

func TestRouter_Match_CaseInsensitiveMethod(t *testing.T) {
	r := NewRouter()
	r.AddRoute(&config.RouteConfig{
		Name:     "test",
		Host:     "example.com",
		Path:     "/api/v1/data",
		Methods:  []string{"get"},
		Upstream: "http://backend:8080",
	})

	route, _ := r.Match("example.com", "/api/v1/data", "GET")
	if route == nil {
		t.Fatal("expected case-insensitive method matching")
	}
}

func TestRouter_Match_MultipleRoutes(t *testing.T) {
	r := NewRouter()
	r.AddRoute(&config.RouteConfig{
		Name:     "first",
		Host:     "example.com",
		Path:     "/api/v1/*",
		Methods:  []string{"GET"},
		Upstream: "http://first:8080",
	})
	r.AddRoute(&config.RouteConfig{
		Name:     "second",
		Host:     "example.com",
		Path:     "/api/v1/*",
		Methods:  []string{"POST"},
		Upstream: "http://second:8080",
	})

	route, _ := r.Match("example.com", "/api/v1/data", "GET")
	if route == nil || route.Name != "first" {
		t.Fatal("expected first route for GET")
	}

	route, _ = r.Match("example.com", "/api/v1/data", "POST")
	if route == nil || route.Name != "second" {
		t.Fatal("expected second route for POST")
	}
}
