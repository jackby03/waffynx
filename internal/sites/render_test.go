package sites

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

var testOpts = RenderOptions{
	SocketPath:  "/opt/waffynx/waffynx.sock",
	HTTPListen:  ":8080",
	TLSListen:   ":8443",
	MaxBodySize: "64k",
	TimeoutMs:   1000,
}

func renderOne(t *testing.T, s Site) string {
	t.Helper()
	frags, err := Render([]Site{s}, testOpts)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(frags) != 1 {
		t.Fatalf("expected exactly 1 fragment, got %d", len(frags))
	}
	for _, body := range frags {
		return body
	}
	return ""
}

// TestRenderGolden pins the generated nginx syntax. Golden files are the review
// artefact: a change to the rendered config must be visible in the diff.
func TestRenderGolden(t *testing.T) {
	cases := map[string]Site{
		"plain-http": {
			Host:     "example.com",
			Upstream: "10.0.0.5:8080",
		},
		"tls": {
			Host:     "secure.example.com",
			Upstream: "10.0.0.6:8443",
			TLS:      &TLSPair{CertFile: "/certs/secure.crt", KeyFile: "/certs/secure.key"},
		},
		"wildcard": {
			Host:     "*.example.com",
			Upstream: "http://backend:80",
		},
		"paths-and-headers": {
			Host:     "api.example.com",
			Upstream: "10.0.0.5:8080",
			Paths: []PathRule{
				{Path: "/api/v2", Upstream: "10.0.0.7:9000"},
				{Path: "/api", Upstream: "10.0.0.6:9000"},
				{Path: "/public"},
			},
			Headers: map[string]string{
				"X-Frame-Options":        "DENY",
				"X-Content-Type-Options": "nosniff",
			},
		},
		// A path rule for "/" sets the default upstream and must not emit a second
		// `location /` block, which nginx rejects as a duplicate.
		"root-path-rule": {
			Host:     "root.example.com",
			Upstream: "10.0.0.5:8080",
			Paths:    []PathRule{{Path: "/", Upstream: "10.0.0.9:8080"}},
		},
	}

	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			got := renderOne(t, cases[name])
			golden := filepath.Join("testdata", name+".nginx.conf")

			if *update {
				if err := os.MkdirAll("testdata", 0o750); err != nil {
					t.Fatalf("mkdir testdata: %v", err)
				}
				if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
					t.Fatalf("writing golden: %v", err)
				}
				return
			}

			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("reading golden (run `go test ./internal/sites -update`): %v", err)
			}
			if got != string(want) {
				t.Errorf("rendered config differs from %s\n--- got ---\n%s\n--- want ---\n%s", golden, got, want)
			}
		})
	}
}

// TestRenderAlwaysEnablesInspection is the invariant that matters most: a site
// without the waffynx directives would proxy traffic completely uninspected.
func TestRenderAlwaysEnablesInspection(t *testing.T) {
	sites := []Site{
		{Host: "a.example.com", Upstream: "10.0.0.5:8080"},
		{Host: "b.example.com", Upstream: "10.0.0.5:8080", TLS: &TLSPair{CertFile: "/c", KeyFile: "/k"}},
		{Host: "c.example.com", Upstream: "10.0.0.5:8080", Paths: []PathRule{{Path: "/x"}}},
	}

	frags, err := Render(sites, testOpts)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(frags) != len(sites) {
		t.Fatalf("expected %d fragments, got %d", len(sites), len(frags))
	}

	for name, body := range frags {
		for _, want := range []string{
			"waffynx on;",
			"waffynx_socket /opt/waffynx/waffynx.sock;",
			"waffynx_fail_open off;",
			"waffynx_max_body_size 64k;",
			"waffynx_timeout 1000;",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q — traffic would be proxied uninspected", name, want)
			}
		}
		// Every non-health location must be inspected: count blocks vs directives.
		if got, want := strings.Count(body, "location "), strings.Count(body, "waffynx on;")+1; got != want {
			t.Errorf("%s: %d locations but %d inspection directives (health excepted)", name, got, want)
		}
	}
}

// TestRenderHealthEndpointIsNotInspected guards the operational contract: a
// failing sidecar must not make the site look down to the orchestrator.
func TestRenderHealthEndpointIsNotInspected(t *testing.T) {
	body := renderOne(t, Site{Host: "example.com", Upstream: "10.0.0.5:8080"})

	idx := strings.Index(body, "location = /health")
	if idx < 0 {
		t.Fatal("health location missing from the rendered config")
	}
	block := body[idx:]
	end := strings.Index(block, "}")
	if end < 0 {
		t.Fatal("malformed health block")
	}
	if strings.Contains(block[:end], "waffynx on;") {
		t.Error("the health endpoint must not be inspected")
	}
}

func TestRenderRejectsInvalidSites(t *testing.T) {
	_, err := Render([]Site{{Host: "bad host;", Upstream: "10.0.0.5:8080"}}, testOpts)
	if err == nil {
		t.Fatal("expected Render to refuse an invalid site rather than emit it")
	}
}

func TestRenderRejectsDuplicateHosts(t *testing.T) {
	_, err := Render([]Site{
		{Host: "example.com", Upstream: "10.0.0.5:8080"},
		{Host: "Example.com", Upstream: "10.0.0.6:8080"},
	}, testOpts)
	if err == nil {
		t.Fatal("expected Render to refuse duplicate hosts")
	}
}

// TestRenderIsDeterministic protects against map-iteration order leaking into the
// output, which would make every apply look like a change.
func TestRenderIsDeterministic(t *testing.T) {
	sites := []Site{
		{Host: "b.example.com", Upstream: "10.0.0.5:8080", Headers: map[string]string{"A": "1", "B": "2", "C": "3"}},
		{Host: "a.example.com", Upstream: "10.0.0.5:8080"},
	}

	first, err := Render(sites, testOpts)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := Render(sites, testOpts)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		for name, body := range first {
			if again[name] != body {
				t.Fatalf("render %d differs for %s", i, name)
			}
		}
	}
}

func TestRenderDefaultsAreUsable(t *testing.T) {
	frags, err := Render([]Site{{Host: "example.com", Upstream: "10.0.0.5:8080"}}, RenderOptions{})
	if err != nil {
		t.Fatalf("Render with zero options: %v", err)
	}
	body := frags["example.com.conf"]
	for _, want := range []string{"listen 8080;", "waffynx_socket /opt/waffynx/waffynx.sock;", "waffynx_timeout 1000;", "waffynx_max_body_size 64k;"} {
		if !strings.Contains(body, want) {
			t.Errorf("defaults: missing %q", want)
		}
	}
}

// TestRenderAlignsBuffersWithInspectionAndAllowsUpgrades guards two directives that
// were missing and that no unit test noticed, because their absence is invisible
// until a real request is proxied.
//
//   - client_body_buffer_size must be at least waffynx_max_body_size. nginx writes
//     anything larger than the buffer to a temp file, where the module cannot see
//     it. Measured on a running image: 10 KB inspected, 12 KB not, with 64k
//     advertised.
//   - client_max_body_size is pinned to the inspection limit so a body that cannot
//     be inspected is refused with 413 rather than forwarded.
//   - proxy_http_version 1.1 plus Upgrade/Connection is what makes websockets work
//     through a reverse proxy.
func TestRenderAlignsBuffersWithInspectionAndAllowsUpgrades(t *testing.T) {
	s := Site{
		Host:     "app.example.com",
		Upstream: "backend:80",
	}
	out, err := Render([]Site{s}, RenderOptions{SocketPath: "/run/waffynx.sock", MaxBodySize: "64k"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := out[s.Host+".conf"]

	for _, want := range []string{
		"client_body_buffer_size 64k;",
		"client_max_body_size 64k;",
		"proxy_http_version 1.1;",
		"proxy_set_header Upgrade $http_upgrade;",
		"proxy_set_header Connection $http_connection;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered fragment is missing %q", want)
		}
	}
}

// The buffer must follow the configured inspection cap, not a hardcoded value.
func TestRenderBufferFollowsMaxBodySize(t *testing.T) {
	out, err := Render([]Site{{Host: "app.example.com", Upstream: "backend:80"}},
		RenderOptions{SocketPath: "/run/waffynx.sock", MaxBodySize: "10m"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := out["app.example.com.conf"]
	if !strings.Contains(got, "client_body_buffer_size 10m;") {
		t.Error("buffer size did not follow MaxBodySize")
	}
	if !strings.Contains(got, "client_max_body_size 10m;") {
		t.Error("accept limit did not follow MaxBodySize")
	}
}
