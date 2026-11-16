// Package sites models the reverse-proxy topology and renders it into nginx
// configuration fragments.
//
// The data plane already enforces what it is told; what it lacks is a way to be
// told anything other than a hand-edited nginx.conf. This package is the control
// plane side of that: an untrusted-input validator plus a text renderer. It
// deliberately performs no I/O of its own beyond what the caller supplies, so it
// can be tested without a filesystem or a running nginx.
package sites

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Site is one protected host in the reverse proxy.
type Site struct {
	Host     string            `yaml:"host" json:"host"`
	Upstream string            `yaml:"upstream" json:"upstream"`
	TLS      *TLSPair          `yaml:"tls,omitempty" json:"tls,omitempty"`
	Paths    []PathRule        `yaml:"paths,omitempty" json:"paths,omitempty"`
	Plugins  []string          `yaml:"plugins,omitempty" json:"plugins,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// TLSPair points at an operator-supplied certificate. Issuance is out of scope.
type TLSPair struct {
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

// PathRule optionally routes a path prefix to a different upstream.
type PathRule struct {
	Path     string `yaml:"path" json:"path"`
	Upstream string `yaml:"upstream,omitempty" json:"upstream,omitempty"`
}

// ValidationError reports every problem found, so an API caller can fix them in
// one round trip instead of one per attempt.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return e.Problems[0]
	}
	return fmt.Sprintf("%d problems: %s", len(e.Problems), strings.Join(e.Problems, "; "))
}

// label is one DNS label: alphanumeric, hyphens inside, 1..63 chars.
var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// hostCharset is a belt-and-braces guard. The label rules already reject these,
// but an explicit rejection list makes the nginx-injection defence obvious to a
// reader: a host containing ';' or '{' would inject directives.
const hostCharset = " \t\r\n;{}\"'`\\/$#&|<>()[]=+*?,"

// NormalizeHost lowercases and trims a host for comparison and rendering.
// nginx treats server_name case-insensitively, so this is safe.
func NormalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// Validate checks a single site. It is pure: TLS file existence is checked by the
// apply step, not here, so validation can run without a filesystem.
func (s Site) Validate() error {
	var problems []string
	add := func(format string, args ...interface{}) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	host := NormalizeHost(s.Host)
	// A leading "*." is legitimate; everything after it must be a plain DNS name.
	// Checking the wildcard-free remainder is what keeps ';' and '{' out while
	// still allowing wildcard hosts.
	checkable := host
	if strings.HasPrefix(host, "*.") {
		checkable = host[2:]
	}

	switch {
	case host == "":
		add("host is required")
	case host == "*":
		add("wildcard host requires a domain, e.g. *.example.com")
	case strings.ContainsAny(checkable, hostCharset):
		add("host %q contains characters that are not allowed in a server name", s.Host)
	case len(host) > 253:
		add("host is longer than 253 characters")
	case net.ParseIP(host) != nil:
		add("host %q is an IP literal; use a DNS name", s.Host)
	case strings.Contains(host, ".."):
		add("host %q contains an empty label", s.Host)
	case strings.HasPrefix(host, ".") || strings.HasSuffix(host, "."):
		add("host %q must not start or end with a dot", s.Host)
	default:
		labels := strings.Split(host, ".")
		for i, l := range labels {
			if i == 0 && l == "*" {
				continue // already checked: it must be followed by a domain
			}
			if l == "" {
				add("host %q contains an empty label", s.Host)
				continue
			}
			if !label.MatchString(l) {
				add("host label %q is not a valid DNS label", l)
			}
		}
	}

	if err := validateUpstream(s.Upstream); err != nil {
		add("upstream: %v", err)
	}

	if s.TLS != nil {
		if s.TLS.CertFile == "" || s.TLS.KeyFile == "" {
			add("tls requires both cert_file and key_file")
		}
		for _, f := range []string{s.TLS.CertFile, s.TLS.KeyFile} {
			if f != "" && strings.ContainsAny(f, "\r\n;{}\"") {
				add("tls file path %q contains characters that are not allowed", f)
			}
		}
	}

	seenPaths := make(map[string]bool, len(s.Paths))
	for i, p := range s.Paths {
		if !strings.HasPrefix(p.Path, "/") {
			add("paths[%d]: %q must start with '/'", i, p.Path)
		}
		if strings.ContainsAny(p.Path, " \t\r\n;{}\"") {
			add("paths[%d]: %q contains characters that are not allowed", i, p.Path)
		}
		if strings.Contains(p.Path, "..") {
			add("paths[%d]: %q must not contain '..'", i, p.Path)
		}
		if seenPaths[p.Path] {
			add("paths[%d]: duplicate path %q", i, p.Path)
		}
		seenPaths[p.Path] = true
		if p.Upstream != "" {
			if err := validateUpstream(p.Upstream); err != nil {
				add("paths[%d]: upstream: %v", i, err)
			}
		}
	}

	for name := range s.Headers {
		if strings.ContainsAny(name, " \t\r\n;{}\"") || name == "" {
			add("header name %q contains characters that are not allowed", name)
		}
	}

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// ValidateSet validates every site and rejects duplicate (host, path) pairs, which
// would make nginx emit two conflicting server blocks for the same name.
func ValidateSet(list []Site) error {
	var problems []string
	seen := make(map[string]bool)

	for i := range list {
		if err := list[i].Validate(); err != nil {
			var ve *ValidationError
			if errors.As(err, &ve) {
				for _, p := range ve.Problems {
					problems = append(problems, fmt.Sprintf("site %q: %s", list[i].Host, p))
				}
			} else {
				problems = append(problems, fmt.Sprintf("site %q: %v", list[i].Host, err))
			}
			continue
		}
		key := NormalizeHost(list[i].Host)
		if seen[key] {
			problems = append(problems, fmt.Sprintf("duplicate site for host %q", list[i].Host))
			continue
		}
		seen[key] = true
	}

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// validateUpstream accepts "host:port" or "scheme://host:port". A port is always
// required: nginx would otherwise silently default to 80, which is rarely what an
// operator meant.
func validateUpstream(upstream string) error {
	if upstream == "" {
		return fmt.Errorf("is required")
	}
	if strings.ContainsAny(upstream, " \t\r\n;{}\"'`\\") {
		return fmt.Errorf("%q contains characters that are not allowed", upstream)
	}

	candidate := upstream
	if strings.Contains(upstream, "://") {
		u, err := url.Parse(upstream)
		if err != nil {
			return fmt.Errorf("%q is not a valid URL: %w", upstream, err)
		}
		switch u.Scheme {
		case "http", "https":
		default:
			return fmt.Errorf("scheme %q is not supported (use http or https)", u.Scheme)
		}
		if u.User != nil {
			return fmt.Errorf("credentials in the upstream URL are not allowed")
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("query strings and fragments are not allowed")
		}
		if u.Path != "" && u.Path != "/" {
			return fmt.Errorf("a path in the upstream URL is not allowed")
		}
		candidate = u.Host
	}

	if !strings.Contains(candidate, ":") {
		return fmt.Errorf("%q must include an explicit port (host:port)", upstream)
	}
	host, port, err := net.SplitHostPort(candidate)
	if err != nil {
		return fmt.Errorf("%q is not host:port: %w", upstream, err)
	}
	if host == "" {
		return fmt.Errorf("%q has an empty host", upstream)
	}
	if p, perr := net.LookupPort("tcp", port); perr != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%q has an invalid port", upstream)
	}
	return nil
}

// SortByHost returns the sites ordered by host, so rendered output and API
// listings are deterministic.
func SortByHost(list []Site) []Site {
	out := make([]Site, len(list))
	copy(out, list)
	sort.Slice(out, func(i, j int) bool {
		return NormalizeHost(out[i].Host) < NormalizeHost(out[j].Host)
	})
	return out
}
