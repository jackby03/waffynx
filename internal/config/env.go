package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/jackby03/waffynx/internal/sites"
)

// Environment variables for the zero-file bootstrap (SPEC-003 plan §5). They are
// constants so the overlay, the bootstrap command and the tests cannot drift.
const (
	EnvSiteHost     = "WAFFYNX_SITE_HOST"
	EnvSiteUpstream = "WAFFYNX_SITE_UPSTREAM"
	EnvSiteTLSCert  = "WAFFYNX_SITE_TLS_CERT"
	EnvSiteTLSKey   = "WAFFYNX_SITE_TLS_KEY"
	EnvListen       = "WAFFYNX_LISTEN"
	//nolint:gosec // G101: this is the name of the environment variable, not a credential.
	EnvJWTSecret = "WAFFYNX_JWT_SECRET"
	EnvDataDir   = "WAFFYNX_DATA_DIR"
)

// ApplyEnvOverlay returns a copy of cfg with the bootstrap environment variables
// applied, re-validated through the same rules config.Parse uses.
//
// The overlay is deliberately a pure function: getenv is injected so tests never
// touch the process environment, and no file is read or written. It never mutates
// cfg, so a failed overlay cannot leave the caller holding half a configuration.
func ApplyEnvOverlay(cfg *Config, getenv func(string) string) (*Config, error) {
	if cfg == nil {
		return nil, errors.New("environment overlay: nil configuration")
	}
	getenv = envLookup(getenv)

	host := envValue(getenv, EnvSiteHost)
	upstream := envValue(getenv, EnvSiteUpstream)
	cert := envValue(getenv, EnvSiteTLSCert)
	key := envValue(getenv, EnvSiteTLSKey)
	listen := envValue(getenv, EnvListen)

	// Paired variables are all-or-nothing: accepting half a site would start the
	// proxy with a topology the operator did not ask for.
	if host == "" && upstream != "" {
		return nil, fmt.Errorf("%s must be set when %s is set", EnvSiteHost, EnvSiteUpstream)
	}
	if upstream == "" && host != "" {
		return nil, fmt.Errorf("%s must be set when %s is set", EnvSiteUpstream, EnvSiteHost)
	}
	if cert == "" && key != "" {
		return nil, fmt.Errorf("%s must be set when %s is set", EnvSiteTLSCert, EnvSiteTLSKey)
	}
	if key == "" && cert != "" {
		return nil, fmt.Errorf("%s must be set when %s is set", EnvSiteTLSKey, EnvSiteTLSCert)
	}
	if cert != "" && host == "" {
		return nil, fmt.Errorf("%s and %s require %s and %s",
			EnvSiteTLSCert, EnvSiteTLSKey, EnvSiteHost, EnvSiteUpstream)
	}

	out := *cfg
	// The sites slice is the only part of the value copy that the overlay can
	// write through, so it is cloned deeply before any update or append.
	out.Sites = cloneSites(cfg.Sites)

	if listen != "" {
		if err := validateListenAddress(listen); err != nil {
			return nil, fmt.Errorf("%s: %w", EnvListen, err)
		}
		out.Listen = listen
	}

	if host != "" {
		site := sites.Site{Host: host, Upstream: upstream}
		if cert != "" {
			site.TLS = &sites.TLSPair{CertFile: cert, KeyFile: key}
		}
		// Validate the overlay on its own first so an error can name the variable
		// the operator set, instead of only the field inside the merged config.
		if err := site.Validate(); err != nil {
			return nil, envSiteError(err)
		}
		out.Sites = upsertEnvSite(out.Sites, site)
	}

	if secret := getenv(EnvJWTSecret); strings.TrimSpace(secret) != "" {
		out.API.Auth.JWTSecret = secret
	}

	// The same validator Parse runs, so the overlay cannot introduce a shape the
	// regular loader would reject.
	if err := out.validate(); err != nil {
		return nil, fmt.Errorf("environment overlay produced an invalid configuration: %w", err)
	}

	return &out, nil
}

// upsertEnvSite updates an existing host in place, preserving its paths, plugins
// and headers, or appends a new site. A host match ignores case, as nginx does.
func upsertEnvSite(list []sites.Site, site sites.Site) []sites.Site {
	want := sites.NormalizeHost(site.Host)
	for i := range list {
		if sites.NormalizeHost(list[i].Host) != want {
			continue
		}
		list[i].Upstream = site.Upstream
		if site.TLS != nil {
			list[i].TLS = site.TLS
		}
		return list
	}
	return append(list, site)
}

// envSiteError names the environment variable(s) whose field failed validation.
func envSiteError(err error) error {
	var validation *sites.ValidationError
	if !errors.As(err, &validation) {
		return fmt.Errorf("%s/%s: %w", EnvSiteHost, EnvSiteUpstream, err)
	}

	names := make([]string, 0, 2)
	add := func(name string) {
		for _, existing := range names {
			if existing == name {
				return
			}
		}
		names = append(names, name)
	}

	tlsProblem := false
	for _, problem := range validation.Problems {
		switch {
		case strings.HasPrefix(problem, "upstream:"):
			add(EnvSiteUpstream)
		case strings.HasPrefix(problem, "tls"):
			tlsProblem = true
		case strings.HasPrefix(problem, "host"):
			add(EnvSiteHost)
		default:
			add(EnvSiteHost)
		}
	}
	if tlsProblem {
		add(EnvSiteTLSCert)
		add(EnvSiteTLSKey)
	}
	if len(names) == 0 {
		add(EnvSiteHost)
		add(EnvSiteUpstream)
	}

	return fmt.Errorf("%s: %w", strings.Join(names, "/"), err)
}

// validateListenAddress keeps untrusted environment input from reaching net.Listen
// unchecked (Constitution §1.4). It accepts the forms the config already uses:
// ":8443", "127.0.0.1:8443", "[::1]:8443" and a bare port.
func validateListenAddress(addr string) error {
	if strings.ContainsAny(addr, " \t\r\n;{}\"'`\\") {
		return fmt.Errorf("%q contains characters that are not allowed", addr)
	}

	if !strings.Contains(addr, ":") {
		return validateListenPort(addr)
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not host:port: %w", addr, err)
	}
	return validateListenPort(port)
}

func validateListenPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port %q is not valid (1-65535)", port)
	}
	return nil
}

func cloneSites(list []sites.Site) []sites.Site {
	if list == nil {
		return nil
	}
	out := make([]sites.Site, len(list))
	for i := range list {
		out[i] = cloneSite(list[i])
	}
	return out
}

func cloneSite(site sites.Site) sites.Site {
	out := site
	if site.TLS != nil {
		tls := *site.TLS
		out.TLS = &tls
	}
	if site.Paths != nil {
		out.Paths = append([]sites.PathRule(nil), site.Paths...)
	}
	if site.Plugins != nil {
		out.Plugins = append([]string(nil), site.Plugins...)
	}
	if site.Headers != nil {
		out.Headers = make(map[string]string, len(site.Headers))
		for name, value := range site.Headers {
			out.Headers[name] = value
		}
	}
	return out
}

func envLookup(getenv func(string) string) func(string) string {
	if getenv == nil {
		return os.Getenv
	}
	return getenv
}

func envValue(getenv func(string) string, key string) string {
	return strings.TrimSpace(getenv(key))
}
