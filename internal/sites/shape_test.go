package sites

import (
	"encoding/json"
	"testing"
)

// TestSiteJSONFieldNames pins the wire contract the dashboard consumes. The UI
// types are hand-written, so a renamed tag would silently render blank cells.
func TestSiteJSONFieldNames(t *testing.T) {
	s := Site{
		Host:     "app.example.com",
		Upstream: "backend:8080",
		TLS:      &TLSPair{CertFile: "/c.crt", KeyFile: "/c.key"},
		Paths:    []PathRule{{Path: "/api", Upstream: "api:9000"}},
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"host", "upstream", "tls", "paths"} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing %q in %s", key, raw)
		}
	}
	tls, _ := got["tls"].(map[string]any)
	for _, key := range []string{"cert_file", "key_file"} {
		if _, ok := tls[key]; !ok {
			t.Errorf("missing tls.%s in %s", key, raw)
		}
	}
}
