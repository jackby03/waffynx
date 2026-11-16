package requestvalidation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackby03/waffynx/internal/plugin"
)

func newTestPlugin(t *testing.T) *RequestValidationPlugin {
	t.Helper()
	p := &RequestValidationPlugin{}
	if err := p.Init(map[string]interface{}{}); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	return p
}

func run(t *testing.T, p *RequestValidationPlugin, values map[string]interface{}) error {
	t.Helper()
	ctx := plugin.NewContext(context.Background(), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	for k, v := range values {
		ctx.Values[k] = v
	}
	_, err := p.Execute(ctx)
	return err
}

// TestRequestValidationBlocksSQLiPatterns is the regression guard for the SQLi
// detection gap found by `waffynx verify`: comment terminators ("admin'--"),
// time-based blind functions and schema/file primitives were not covered.
func TestRequestValidationBlocksSQLiPatterns(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		body string
	}{
		{name: "comment terminator in query", uri: "/login?user=admin'--"},
		{name: "double-dash double quote", uri: `/login?user=admin"--`},
		{name: "comment terminator in body", body: "username=admin'--&password=x"},
		{name: "time-based blind", uri: "/p?id=1' AND sleep(5)--"},
		{name: "postgres sleep", uri: "/p?id=1;SELECT pg_sleep(5)"},
		{name: "mysql benchmark", uri: "/p?id=1 AND benchmark(1000000,MD5(1))"},
		{name: "schema enumeration", uri: "/p?id=1 UNION SELECT table_name FROM information_schema.tables"},
		{name: "file read", uri: "/p?id=1 UNION SELECT load_file('/etc/passwd')"},
		{name: "file write", uri: "/p?id=1 INTO OUTFILE '/var/www/shell.php'"},
	}

	p := newTestPlugin(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]interface{}{}
			if tc.uri != "" {
				values["wn_uri"] = tc.uri
			}
			if tc.body != "" {
				values["wn_body"] = tc.body
			}
			if err := run(t, p, values); err == nil {
				t.Errorf("expected %q to be blocked, got allow", tc.uri+tc.body)
			}
		})
	}
}

// TestRequestValidationAllowsBenignTraffic guards against the new patterns
// turning into false positives on ordinary content.
func TestRequestValidationAllowsBenignTraffic(t *testing.T) {
	p := newTestPlugin(t)

	benign := []map[string]interface{}{
		{"wn_uri": "/search?q=how+to+bake+bread"},
		{"wn_uri": "/api/users?page=2&limit=50"},
		{"wn_uri": "/blog/why-waf-matters", "wn_body": "It's a good question — we'll cover it."},
		{"wn_uri": "/api/orders", "wn_body": `{"items":[{"sku":"A-1","qty":2}]}`},
		{"wn_uri": "/products/nike-air-max-90"},
		{"wn_uri": "/api/v1/reports?from=2026-01-01&to=2026-02-01"},
	}

	for _, values := range benign {
		if err := run(t, p, values); err != nil {
			t.Errorf("benign request blocked (%v): %v", values, err)
		}
	}
}
