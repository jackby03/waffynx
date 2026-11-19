package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	// The registry is filled by init() functions; the API binary imports this
	// package for the same reason, so the test mirrors production.
	_ "github.com/jackby03/waffynx/plugins/all"
)

// TestPluginsAreListed guards against /api/v1/plugins answering [].
//
// It really happened: the handler read a registry that only cmd/waffynx populated,
// so the control plane reported no plugins while four were linked into the tree.
// The console then rendered an empty plugin list, which looks like a broken product
// rather than a broken import.
func TestPluginsAreListed(t *testing.T) {
	srv, handler := newTestAPIServer(t, nil)
	token, err := srv.authMgr.GenerateToken("admin", "admin", []string{"read", "write"})
	if err != nil {
		t.Fatalf("generating token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding body: %v (%s)", err, rec.Body.String())
	}
	if len(got) < 4 {
		t.Fatalf("got %d plugins, want at least 4: %s", len(got), rec.Body.String())
	}

	names := make(map[string]bool, len(got))
	for _, p := range got {
		name, _ := p["name"].(string)
		if name == "" {
			t.Errorf("plugin without a name: %v", p)
		}
		if v, _ := p["version"].(string); v == "" {
			t.Errorf("plugin %q without a version", name)
		}
		names[name] = true
	}
	for _, want := range []string{"bot-protection", "geo-block", "rate-limit", "request-validation"} {
		if !names[want] {
			t.Errorf("plugin %q missing from %s", want, strings.Join(pluginNames(names), ", "))
		}
	}
}

func pluginNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestPluginMetadataIsComplete logs what the console will render, so a plugin that
// ships without a description or stage is caught here instead of in an empty cell.
func TestPluginMetadataIsComplete(t *testing.T) {
	srv, handler := newTestAPIServer(t, nil)
	token, err := srv.authMgr.GenerateToken("admin", "admin", []string{"read"})
	if err != nil {
		t.Fatalf("generating token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	for _, p := range got {
		name, _ := p["name"].(string)
		if desc, _ := p["description"].(string); desc == "" {
			t.Errorf("plugin %q has no description", name)
		}
		if phase, _ := p["phase"].(string); phase == "" {
			t.Errorf("plugin %q has no phase", name)
		}
		t.Logf("%-20s v%-7s phase=%-8v priority=%v", name, p["version"], p["phase"], p["priority"])
	}
}
