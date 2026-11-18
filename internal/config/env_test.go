package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackby03/waffynx/internal/sites"
)

// fakeEnv returns a getenv that reads only the supplied map, so tests never touch
// or depend on the process environment.
func fakeEnv(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func mustParse(t *testing.T, document string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(document))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func TestApplyEnvOverlayRequiresPairedVariables(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "host without upstream",
			env:  map[string]string{EnvSiteHost: "example.com"},
			want: EnvSiteUpstream,
		},
		{
			name: "upstream without host",
			env:  map[string]string{EnvSiteUpstream: "10.0.0.5:8080"},
			want: EnvSiteHost,
		},
		{
			name: "tls cert without key",
			env: map[string]string{
				EnvSiteHost:     "example.com",
				EnvSiteUpstream: "10.0.0.5:8080",
				EnvSiteTLSCert:  "/certs/example.crt",
			},
			want: EnvSiteTLSKey,
		},
		{
			name: "tls key without cert",
			env: map[string]string{
				EnvSiteHost:     "example.com",
				EnvSiteUpstream: "10.0.0.5:8080",
				EnvSiteTLSKey:   "/certs/example.key",
			},
			want: EnvSiteTLSCert,
		},
		{
			name: "tls without a site",
			env: map[string]string{
				EnvSiteTLSCert: "/certs/example.crt",
				EnvSiteTLSKey:  "/certs/example.key",
			},
			want: EnvSiteHost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustParse(t, "name: overlay-test\n")
			got, err := ApplyEnvOverlay(cfg, fakeEnv(tt.env))
			if err == nil {
				t.Fatalf("expected an error naming %s, got config %+v", tt.want, got)
			}
			if got != nil {
				t.Errorf("a failed overlay must not return a config, got %+v", got)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error must name %s, got: %v", tt.want, err)
			}
		})
	}
}

func TestApplyEnvOverlayAppendsSite(t *testing.T) {
	base := mustParse(t, "name: overlay-test\n")

	got, err := ApplyEnvOverlay(base, fakeEnv(map[string]string{
		EnvSiteHost:     "Example.COM",
		EnvSiteUpstream: "10.0.0.5:8080",
	}))
	if err != nil {
		t.Fatalf("ApplyEnvOverlay: %v", err)
	}
	if len(got.Sites) != 1 {
		t.Fatalf("expected one site, got %+v", got.Sites)
	}
	if got.Sites[0].Host != "Example.COM" || got.Sites[0].Upstream != "10.0.0.5:8080" {
		t.Errorf("unexpected site: %+v", got.Sites[0])
	}
	if got.Sites[0].TLS != nil {
		t.Errorf("expected plain HTTP site, got TLS %+v", got.Sites[0].TLS)
	}
	if len(base.Sites) != 0 {
		t.Errorf("the caller's config was mutated: %+v", base.Sites)
	}
}

func TestApplyEnvOverlayUpdatesExistingHost(t *testing.T) {
	document := `
name: overlay-test
sites:
  - host: example.com
    upstream: 10.0.0.5:8080
    paths:
      - path: /api
        upstream: 10.0.0.5:9000
    plugins:
      - sqli
    headers:
      X-Frame-Options: DENY
    tls:
      cert_file: /certs/old.crt
      key_file: /certs/old.key
  - host: other.example
    upstream: 10.0.0.6:8080
`
	base := mustParse(t, document)

	got, err := ApplyEnvOverlay(base, fakeEnv(map[string]string{
		EnvSiteHost:     "EXAMPLE.com",
		EnvSiteUpstream: "10.0.0.7:8080",
	}))
	if err != nil {
		t.Fatalf("ApplyEnvOverlay: %v", err)
	}
	if len(got.Sites) != 2 {
		t.Fatalf("an existing site must be updated, not duplicated: %+v", got.Sites)
	}

	updated := got.Sites[0]
	if updated.Upstream != "10.0.0.7:8080" {
		t.Errorf("upstream was not updated: %+v", updated)
	}
	if len(updated.Paths) != 1 || len(updated.Plugins) != 1 || updated.Headers["X-Frame-Options"] != "DENY" {
		t.Errorf("per-site details must survive an upstream update: %+v", updated)
	}
	if updated.TLS == nil || updated.TLS.CertFile != "/certs/old.crt" {
		t.Errorf("TLS must be preserved when the overlay does not set it: %+v", updated.TLS)
	}
	if base.Sites[0].Upstream != "10.0.0.5:8080" {
		t.Errorf("the caller's config was mutated: %+v", base.Sites[0])
	}

	withTLS, err := ApplyEnvOverlay(base, fakeEnv(map[string]string{
		EnvSiteHost:     "example.com",
		EnvSiteUpstream: "10.0.0.7:8080",
		EnvSiteTLSCert:  "/certs/new.crt",
		EnvSiteTLSKey:   "/certs/new.key",
	}))
	if err != nil {
		t.Fatalf("ApplyEnvOverlay with TLS: %v", err)
	}
	if withTLS.Sites[0].TLS == nil || withTLS.Sites[0].TLS.CertFile != "/certs/new.crt" {
		t.Errorf("TLS from the environment must replace the old pair: %+v", withTLS.Sites[0].TLS)
	}
}

func TestApplyEnvOverlayAddsTLS(t *testing.T) {
	base := mustParse(t, "name: overlay-test\n")

	got, err := ApplyEnvOverlay(base, fakeEnv(map[string]string{
		EnvSiteHost:     "example.com",
		EnvSiteUpstream: "https://backend:8443",
		EnvSiteTLSCert:  "/certs/example.crt",
		EnvSiteTLSKey:   "/certs/example.key",
	}))
	if err != nil {
		t.Fatalf("ApplyEnvOverlay: %v", err)
	}
	if len(got.Sites) != 1 || got.Sites[0].TLS == nil {
		t.Fatalf("expected one TLS site, got %+v", got.Sites)
	}
	if got.Sites[0].TLS.CertFile != "/certs/example.crt" || got.Sites[0].TLS.KeyFile != "/certs/example.key" {
		t.Errorf("unexpected TLS pair: %+v", got.Sites[0].TLS)
	}
}

func TestApplyEnvOverlayListen(t *testing.T) {
	base := mustParse(t, "name: overlay-test\n")
	if base.Listen != ":8443" {
		t.Fatalf("unexpected default listen: %q", base.Listen)
	}

	got, err := ApplyEnvOverlay(base, fakeEnv(map[string]string{EnvListen: ":9091"}))
	if err != nil {
		t.Fatalf("ApplyEnvOverlay: %v", err)
	}
	if got.Listen != ":9091" {
		t.Errorf("expected listen :9091, got %q", got.Listen)
	}
	if base.Listen != ":8443" {
		t.Errorf("the caller's config was mutated: %q", base.Listen)
	}

	bare, err := ApplyEnvOverlay(base, fakeEnv(map[string]string{EnvListen: "9092"}))
	if err != nil {
		t.Fatalf("ApplyEnvOverlay with a bare port: %v", err)
	}
	if bare.Listen != "9092" {
		t.Errorf("expected listen 9092, got %q", bare.Listen)
	}
}

func TestApplyEnvOverlayRejectsInvalidValuesByName(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "invalid upstream",
			env: map[string]string{
				EnvSiteHost:     "example.com",
				EnvSiteUpstream: "backend",
			},
			want: EnvSiteUpstream,
		},
		{
			name: "injecting host",
			env: map[string]string{
				EnvSiteHost:     "example.com; return 200",
				EnvSiteUpstream: "10.0.0.5:8080",
			},
			want: EnvSiteHost,
		},
		{
			name: "invalid listen",
			env:  map[string]string{EnvListen: "not-a-listen"},
			want: EnvListen,
		},
		{
			name: "invalid TLS path",
			env: map[string]string{
				EnvSiteHost:     "example.com",
				EnvSiteUpstream: "10.0.0.5:8080",
				EnvSiteTLSCert:  "/certs/example\n.crt",
				EnvSiteTLSKey:   "/certs/example.key",
			},
			want: EnvSiteTLSCert,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := mustParse(t, "name: overlay-test\n")
			got, err := ApplyEnvOverlay(base, fakeEnv(tt.env))
			if err == nil {
				t.Fatalf("expected an error naming %s, got %+v", tt.want, got)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error must name %s, got: %v", tt.want, err)
			}
			if got != nil {
				t.Errorf("a failed overlay must not return a config, got %+v", got)
			}
		})
	}
}

func TestApplyEnvOverlayJWTSecret(t *testing.T) {
	base := mustParse(t, "name: overlay-test\n")
	secret := strings.Repeat("s", 64)

	got, err := ApplyEnvOverlay(base, fakeEnv(map[string]string{EnvJWTSecret: secret}))
	if err != nil {
		t.Fatalf("ApplyEnvOverlay: %v", err)
	}
	if got.API.Auth.JWTSecret != secret {
		t.Errorf("expected the environment secret in the overlay, got %q", got.API.Auth.JWTSecret)
	}
	if base.API.Auth.JWTSecret != "" {
		t.Errorf("the caller's config was mutated: %q", base.API.Auth.JWTSecret)
	}
}

func TestApplyEnvOverlayRejectsInvalidBaseConfig(t *testing.T) {
	// No environment at all: the overlay still returns the result of the same
	// validation Parse runs, so it can never hand back a config that would not load.
	got, err := ApplyEnvOverlay(&Config{}, fakeEnv(nil))
	if err == nil {
		t.Fatalf("expected the invalid base config to fail validation, got %+v", got)
	}
	if !strings.Contains(err.Error(), "listen address is required") {
		t.Errorf("expected the validator's error, got: %v", err)
	}
}

func TestApplyEnvOverlayNilConfig(t *testing.T) {
	if got, err := ApplyEnvOverlay(nil, fakeEnv(nil)); err == nil || got != nil {
		t.Fatalf("expected nil config to be rejected, got %+v, %v", got, err)
	}
}

func TestApplyEnvOverlayWithoutEnvironmentReturnsACopy(t *testing.T) {
	base := mustParse(t, `
name: overlay-test
sites:
  - host: example.com
    upstream: 10.0.0.5:8080
`)
	got, err := ApplyEnvOverlay(base, fakeEnv(nil))
	if err != nil {
		t.Fatalf("ApplyEnvOverlay: %v", err)
	}
	if got == base {
		t.Fatal("expected a copy, got the caller's pointer")
	}
	got.Sites[0].Upstream = "10.0.0.9:8080"
	if base.Sites[0].Upstream != "10.0.0.5:8080" {
		t.Errorf("the copy aliases the caller's sites: %+v", base.Sites)
	}
}

func TestValidateListenAddress(t *testing.T) {
	valid := []string{":8443", "127.0.0.1:8443", "[::1]:8443", "8443"}
	for _, address := range valid {
		if err := validateListenAddress(address); err != nil {
			t.Errorf("%q should be a valid listener: %v", address, err)
		}
	}

	invalid := []string{"", "not-a-listen", ":0", ":65536", "host:abc", "a b:8443", "::1:8443", ":"}
	for _, address := range invalid {
		if err := validateListenAddress(address); err == nil {
			t.Errorf("%q should be rejected", address)
		}
	}
}

func TestEnvLookupDefaultsToProcessEnvironment(t *testing.T) {
	const key = "WAFFYNX_ENV_LOOKUP_TEST"
	t.Setenv(key, "value")
	if got := envLookup(nil)(key); got != "value" {
		t.Errorf("expected the process environment, got %q", got)
	}
}

func TestEnvSiteErrorNamesVariables(t *testing.T) {
	plain := envSiteError(errors.New("boom"))
	if !strings.Contains(plain.Error(), EnvSiteHost) || !strings.Contains(plain.Error(), EnvSiteUpstream) {
		t.Errorf("a non-validation error must name the site variables, got: %v", plain)
	}

	tlsOnly := envSiteError(&sites.ValidationError{Problems: []string{"tls requires both cert_file and key_file"}})
	if !strings.Contains(tlsOnly.Error(), EnvSiteTLSCert) || !strings.Contains(tlsOnly.Error(), EnvSiteTLSKey) {
		t.Errorf("a TLS problem must name the TLS variables, got: %v", tlsOnly)
	}

	unknown := envSiteError(&sites.ValidationError{Problems: []string{"something odd"}})
	if !strings.Contains(unknown.Error(), EnvSiteHost) {
		t.Errorf("an unattributed problem must name the host variable, got: %v", unknown)
	}

	// Two problems that resolve to the same variable must name it once, not twice.
	duplicate := envSiteError(&sites.ValidationError{Problems: []string{"host is required", "something odd"}})
	if strings.Count(duplicate.Error(), EnvSiteHost) != 1 {
		t.Errorf("expected the host variable once, got: %v", duplicate)
	}

	empty := envSiteError(&sites.ValidationError{})
	if !strings.Contains(empty.Error(), EnvSiteHost) || !strings.Contains(empty.Error(), EnvSiteUpstream) {
		t.Errorf("an empty problem set must name both site variables, got: %v", empty)
	}
}
