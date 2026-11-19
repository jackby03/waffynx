package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func rulesTestToken(t *testing.T, s *Server) string {
	t.Helper()
	token, err := s.authMgr.GenerateToken("admin", "admin", []string{"read", "write"})
	if err != nil {
		t.Fatalf("generating test token: %v", err)
	}
	return token
}

// TestAPI_RulesReturnsTheManagedCatalog guards the endpoint the dashboard renders.
// Before it existed, GET /api/v1/rules matched the root handler, answered 200 with
// an unrelated object, and the UI failed with "r.map is not a function".
func TestAPI_RulesReturnsTheManagedCatalog(t *testing.T) {
	s, handler := newTestAPIServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+rulesTestToken(t, s))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Rules []ruleView `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Rules) == 0 {
		t.Fatal("the managed catalog is empty")
	}
	first := body.Rules[0]
	if first.ID == "" || first.Name == "" || first.Severity == "" || first.Action == "" {
		t.Errorf("incomplete rule: %+v", first)
	}
}

// An unknown /api/v1 path must be a 404, not the SPA/JSON root with a 200.
func TestAPI_UnknownEndpointIs404(t *testing.T) {
	s, handler := newTestAPIServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/does-not-exist", nil)
	req.Header.Set("Authorization", "Bearer "+rulesTestToken(t, s))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %q)", rec.Code, rec.Body.String())
	}
}
