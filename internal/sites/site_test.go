package sites

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateAcceptsRealisticSites(t *testing.T) {
	cases := []Site{
		{Host: "example.com", Upstream: "10.0.0.5:8080"},
		{Host: "Example.COM", Upstream: "http://backend:80"},     // normalised
		{Host: "*.example.com", Upstream: "10.0.0.5:8080"},       // wildcard
		{Host: "localhost", Upstream: "127.0.0.1:3000"},          // single label
		{Host: "api.example.co.uk", Upstream: "https://svc:443"}, // https upstream
		{Host: "example.com", Upstream: "10.0.0.5:8080", TLS: &TLSPair{CertFile: "/certs/a.crt", KeyFile: "/certs/a.key"}},
		{
			Host:     "example.com",
			Upstream: "10.0.0.5:8080",
			Paths:    []PathRule{{Path: "/api", Upstream: "10.0.0.6:9000"}, {Path: "/static"}},
			Headers:  map[string]string{"X-Frame-Options": "DENY"},
		},
	}

	for _, s := range cases {
		if err := s.Validate(); err != nil {
			t.Errorf("%q should be valid, got: %v", s.Host, err)
		}
	}
}

// TestValidateRejectsDirectiveInjection is the security-critical case: a host
// containing nginx syntax must be rejected, never escaped or emitted.
func TestValidateRejectsDirectiveInjection(t *testing.T) {
	injections := []string{
		`example.com;`,
		`example.com { }`,
		"example.com\nreturn 200;",
		`example.com proxy_pass http://evil`,
		`exa"mple.com`,
		`exa'mple.com`,
		`example.com$host`,
		`example.com/server`,
	}

	for _, host := range injections {
		s := Site{Host: host, Upstream: "10.0.0.5:8080"}
		err := s.Validate()
		if err == nil {
			t.Errorf("host %q must be rejected, got valid", host)
			continue
		}
		if !strings.Contains(err.Error(), "not allowed") && !strings.Contains(err.Error(), "valid DNS label") &&
			!strings.Contains(err.Error(), "empty label") {
			t.Errorf("host %q: expected a rejection reason, got %v", host, err)
		}
	}
}

// TestValidateNormalizesSurroundingWhitespace documents the contract: stray
// leading/trailing whitespace is trimmed (safe), interior whitespace is rejected
// because it would change the server_name token.
func TestValidateNormalizesSurroundingWhitespace(t *testing.T) {
	for _, host := range []string{" example.com", "example.com ", "example.com\n", "example.com\t"} {
		if err := (Site{Host: host, Upstream: "10.0.0.5:8080"}).Validate(); err != nil {
			t.Errorf("host %q should be normalised, not rejected: %v", host, err)
		}
	}
	if got := NormalizeHost("  ExAmple.COM\n"); got != "example.com" {
		t.Errorf("NormalizeHost = %q, want example.com", got)
	}
}

func TestValidateHostRules(t *testing.T) {
	cases := map[string]string{
		"":                               "host is required",
		"exa mple.com":                   "not allowed",
		"10.0.0.5":                       "IP literal",
		"a..b.com":                       "empty label",
		".example.com":                   "must not start or end with a dot",
		"example.com.":                   "must not start or end with a dot",
		"*":                              "wildcard host requires a domain",
		"-example.com":                   "not a valid DNS label",
		"example-.com":                   "not a valid DNS label",
		"exam_ple.com":                   "not a valid DNS label",
		strings.Repeat("a", 64) + ".com": "not a valid DNS label",
	}

	for host, want := range cases {
		err := (Site{Host: host, Upstream: "10.0.0.5:8080"}).Validate()
		if err == nil {
			t.Errorf("host %q: expected rejection", host)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("host %q: expected %q in error, got %v", host, want, err)
		}
	}
}

func TestValidateUpstreamRules(t *testing.T) {
	cases := map[string]string{
		"":                          "is required",
		"backend":                   "must include an explicit port",
		"backend:0":                 "invalid port",
		"backend:99999":             "invalid port",
		"backend:notaport":          "invalid port",
		"http://user:pw@backend:80": "credentials",
		"http://backend:80/api":     "path in the upstream URL",
		"http://backend:80?a=1":     "query strings",
		"ftp://backend:21":          "not supported",
		"10.0.0.5:8080;":            "not allowed",
	}

	for upstream, want := range cases {
		err := (Site{Host: "example.com", Upstream: upstream}).Validate()
		if err == nil {
			t.Errorf("upstream %q: expected rejection", upstream)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("upstream %q: expected %q in error, got %v", upstream, want, err)
		}
	}
}

func TestValidateTLSPair(t *testing.T) {
	s := Site{Host: "example.com", Upstream: "10.0.0.5:8080", TLS: &TLSPair{CertFile: "/certs/a.crt"}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "both cert_file and key_file") {
		t.Errorf("expected a missing-key error, got %v", err)
	}

	s.TLS = &TLSPair{CertFile: "/certs/a.crt;", KeyFile: "/certs/a.key"}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected a path-injection rejection, got %v", err)
	}
}

func TestValidatePathRules(t *testing.T) {
	base := Site{Host: "example.com", Upstream: "10.0.0.5:8080"}

	bad := []PathRule{
		{Path: "api"},
		{Path: "/a b"},
		{Path: "/../etc"},
		{Path: "/x", Upstream: "nope"},
	}
	for _, p := range bad {
		s := base
		s.Paths = []PathRule{p}
		if err := s.Validate(); err == nil {
			t.Errorf("path rule %+v should be rejected", p)
		}
	}

	s := base
	s.Paths = []PathRule{{Path: "/api"}, {Path: "/api"}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Errorf("expected a duplicate-path error, got %v", err)
	}
}

func TestValidateReportsAllProblems(t *testing.T) {
	s := Site{Host: "bad host;", Upstream: "no-port", TLS: &TLSPair{CertFile: "x"}}
	err := s.Validate()
	if err == nil {
		t.Fatal("expected failure")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Problems) < 3 {
		t.Errorf("expected every problem to be reported in one pass, got %d: %v", len(ve.Problems), ve.Problems)
	}
}

func TestValidateSetRejectsDuplicates(t *testing.T) {
	list := []Site{
		{Host: "example.com", Upstream: "10.0.0.5:8080"},
		{Host: "EXAMPLE.com", Upstream: "10.0.0.6:8080"}, // duplicate after normalisation
	}
	err := ValidateSet(list)
	if err == nil || !strings.Contains(err.Error(), "duplicate site") {
		t.Fatalf("expected a duplicate-site error, got %v", err)
	}
}

func TestFragmentNameIsStableAndSafe(t *testing.T) {
	cases := map[string]string{
		"example.com":   "example.com.conf",
		"Example.COM":   "example.com.conf",
		"*.example.com": "wildcard.example.com.conf",
		"a_b.com":       "a_b.com.conf",
	}
	for host, want := range cases {
		if got := FragmentName(host); got != want {
			t.Errorf("FragmentName(%q) = %q, want %q", host, got, want)
		}
	}
	// Hostile input must never yield a path separator, a '..' sequence, or an
	// empty name. These hosts are rejected by Validate; this is defence in depth.
	for _, nasty := range []string{"a/b", `a\b`, "../../etc", "../..", "a b", "", "*", "."} {
		got := FragmentName(nasty)
		if strings.ContainsAny(got, `\/`) {
			t.Errorf("FragmentName(%q) = %q leaks a path separator", nasty, got)
		}
		if strings.Contains(got, "..") {
			t.Errorf("FragmentName(%q) = %q contains a dot-dot sequence", nasty, got)
		}
		if got == "" || got == ".conf" {
			t.Errorf("FragmentName(%q) = %q is empty", nasty, got)
		}
	}
}
