package sites

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// RenderOptions carries the values the renderer needs from the runtime
// environment. They are explicit rather than read from disk so rendering is a
// pure function.
type RenderOptions struct {
	// SocketPath is the Go sidecar's Unix socket, passed to waffynx_socket.
	SocketPath string
	// HTTPListen is the plain listener, e.g. ":8080".
	HTTPListen string
	// TLSListen is the TLS listener, e.g. ":8443".
	TLSListen string
	// MaxBodySize is the inspection body cap, e.g. "64k".
	MaxBodySize string
	// TimeoutMs is the sidecar evaluation timeout.
	TimeoutMs int
}

func (o RenderOptions) withDefaults() RenderOptions {
	if o.SocketPath == "" {
		o.SocketPath = "/opt/waffynx/waffynx.sock"
	}
	if o.HTTPListen == "" {
		o.HTTPListen = ":8080"
	}
	if o.TLSListen == "" {
		o.TLSListen = ":8443"
	}
	if o.MaxBodySize == "" {
		o.MaxBodySize = "64k"
	}
	if o.TimeoutMs <= 0 {
		o.TimeoutMs = 1000
	}
	return o
}

// unsafeFileChars matches everything outside a conservative filename alphabet.
var unsafeFileChars = regexp.MustCompile(`[^a-z0-9.-]+`)

// FragmentName is the nginx fragment filename for a host. It is derived only from
// the normalised host, so it is stable across renders and safe as a path element.
func FragmentName(host string) string {
	h := NormalizeHost(host)
	h = strings.ReplaceAll(h, "*.", "wildcard.")
	h = unsafeFileChars.ReplaceAllString(h, "_")
	// Collapse any '..' left over from hostile input: harmless once separators are
	// gone, but some filesystems and bundlers dislike it.
	for strings.Contains(h, "..") {
		h = strings.ReplaceAll(h, "..", "_")
	}
	h = strings.Trim(h, ".")
	if h == "" {
		h = "site"
	}
	return h + ".conf"
}

// Render produces one nginx server block per site, keyed by fragment filename.
//
// Callers must have validated the sites first; Render validates again rather than
// emitting a partial or unsafe configuration.
func Render(list []Site, opts RenderOptions) (map[string]string, error) {
	opts = opts.withDefaults()

	if err := ValidateSet(list); err != nil {
		return nil, err
	}

	out := make(map[string]string, len(list))
	for _, s := range SortByHost(list) {
		fragment, err := renderSite(s, opts)
		if err != nil {
			return nil, fmt.Errorf("rendering %q: %w", s.Host, err)
		}
		name := FragmentName(s.Host)
		if _, clash := out[name]; clash {
			return nil, fmt.Errorf("two sites map to the same fragment %q", name)
		}
		out[name] = fragment
	}
	return out, nil
}

func renderSite(s Site, opts RenderOptions) (string, error) {
	listen := opts.HTTPListen
	if s.TLS != nil {
		listen = opts.TLSListen
	}

	// A path rule for "/" defines the default upstream, so it must not also emit a
	// second `location /` block (nginx rejects duplicate locations).
	defaultUpstream := s.Upstream
	prefixRules := make([]PathRule, 0, len(s.Paths))
	for _, p := range s.Paths {
		if p.Path == "/" {
			if p.Upstream != "" {
				defaultUpstream = p.Upstream
			}
			continue
		}
		prefixRules = append(prefixRules, p)
	}
	// Longest prefix first: nginx matches the longest anyway, but a stable order
	// keeps the rendered output diffable.
	sort.Slice(prefixRules, func(i, j int) bool {
		return len(prefixRules[i].Path) > len(prefixRules[j].Path)
	})

	var b strings.Builder
	b.WriteString("server {\n")
	fmt.Fprintf(&b, "    listen %s;\n", listenDirective(listen, s.TLS != nil))
	fmt.Fprintf(&b, "    server_name %s;\n", NormalizeHost(s.Host))

	if s.TLS != nil {
		fmt.Fprintf(&b, "    ssl_certificate     %s;\n", s.TLS.CertFile)
		fmt.Fprintf(&b, "    ssl_certificate_key %s;\n", s.TLS.KeyFile)
		b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
	}

	for _, p := range prefixRules {
		upstream := p.Upstream
		if upstream == "" {
			upstream = defaultUpstream
		}
		writeLocation(&b, p.Path, upstream, s, opts)
	}
	writeLocation(&b, "/", defaultUpstream, s, opts)

	// The WAF's own health endpoint must not be inspected: a sidecar hiccup should
	// not make the site look down to the orchestrator.
	b.WriteString("\n    location = /health {\n")
	b.WriteString("        waffynx off;\n")
	b.WriteString("        return 200 '{\"status\":\"ok\"}';\n")
	b.WriteString("        add_header Content-Type application/json;\n")
	b.WriteString("    }\n")

	b.WriteString("}\n")
	return b.String(), nil
}

func writeLocation(b *strings.Builder, locationPath, upstream string, s Site, opts RenderOptions) {
	if locationPath == "/" {
		b.WriteString("\n    location / {\n")
	} else {
		fmt.Fprintf(b, "\n    location %s {\n", locationPath)
	}

	b.WriteString("        waffynx on;\n")
	fmt.Fprintf(b, "        waffynx_socket %s;\n", opts.SocketPath)
	fmt.Fprintf(b, "        waffynx_timeout %d;\n", opts.TimeoutMs)
	b.WriteString("        waffynx_fail_open off;\n")
	fmt.Fprintf(b, "        waffynx_max_body_size %s;\n", opts.MaxBodySize)
	fmt.Fprintf(b, "        proxy_pass %s;\n", proxyTarget(upstream))
	b.WriteString("        proxy_set_header Host $host;\n")
	b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
	b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")

	names := make([]string, 0, len(s.Headers))
	for name := range s.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(b, "        proxy_set_header %s %s;\n", name, s.Headers[name])
	}

	b.WriteString("    }\n")
}

// listenDirective renders nginx's listen value.
//
// Two details that a golden-file review caught and unit assertions had missed:
//   - `:8080` is not the form the working config uses; nginx wants a bare port
//     when no address is given, so the leading colon is stripped.
//   - a TLS server block needs the `ssl` parameter on listen, or nginx terminates
//     the connection as plain HTTP.
func listenDirective(addr string, tls bool) string {
	port := strings.TrimPrefix(addr, ":")
	if tls {
		return port + " ssl"
	}
	return port
}

// proxyTarget normalises an upstream into the form nginx's proxy_pass wants.
func proxyTarget(upstream string) string {
	if strings.Contains(upstream, "://") {
		return upstream
	}
	return "http://" + upstream
}
