package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/sites"
)

type fakeValidator struct {
	err   error
	calls int
	files map[string]string
}

func (v *fakeValidator) ValidateConfig(_ context.Context, dir string) error {
	v.calls++
	v.files = nil
	entries, err := os.ReadDir(dir)
	if err == nil {
		v.files = make(map[string]string)
		for _, e := range entries {
			data, readErr := os.ReadFile(filepath.Join(dir, e.Name()))
			if readErr == nil {
				v.files[e.Name()] = string(data)
			}
		}
	}
	return v.err
}

type fakeReloader struct {
	err   error
	calls int
}

func (r *fakeReloader) Reload(context.Context) error {
	r.calls++
	return r.err
}

const siteTestConfig = `name: site-test
listen: ":8443"
api:
  auth:
    jwt_secret: "test-secret-key-1234567890-must-be-32-chars"
    token_ttl: 3600
`

type siteFixture struct {
	srv      *Server
	handler  http.Handler
	admin    string
	viewer   string
	cfgPath  string
	sitesDir string
	validate *fakeValidator
	reload   *fakeReloader
}

// newSiteFixture wires a real Server against a temporary config file, with the
// nginx validator and reloader replaced by fakes. That keeps the HTTP and
// persistence paths real while avoiding a dependency on a compiled nginx.
func newSiteFixture(t *testing.T) *siteFixture {
	t.Helper()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "waffynx.yaml")
	if err := os.WriteFile(cfgPath, []byte(siteTestConfig), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Parse([]byte(siteTestConfig))
	if err != nil {
		t.Fatalf("parsing config: %v", err)
	}
	cfg.Nginx.ConfigPath = filepath.Join(dir, "nginx")

	srv, err := NewServer(cfg, cfgPath, "")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	validate := &fakeValidator{}
	reload := &fakeReloader{}
	sitesDir := filepath.Join(cfg.Nginx.ConfigPath, "sites")
	srv.siteApplier = &sites.Applier{
		Dir:       sitesDir,
		Validator: validate,
		Reloader:  reload,
	}

	admin, err := srv.authMgr.GenerateToken("admin", "admin", []string{"read", "write"})
	if err != nil {
		t.Fatalf("admin token: %v", err)
	}
	viewer, err := srv.authMgr.GenerateToken("viewer", "viewer", []string{"read"})
	if err != nil {
		t.Fatalf("viewer token: %v", err)
	}

	return &siteFixture{
		srv: srv, handler: srv.Handler(),
		admin: admin, viewer: viewer,
		cfgPath: cfgPath, sitesDir: sitesDir,
		validate: validate, reload: reload,
	}
}

func (f *siteFixture) do(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *siteFixture) configFile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.cfgPath)
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	return string(data)
}

func siteBody(t *testing.T, s sites.Site) string {
	t.Helper()
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshalling site: %v", err)
	}
	return string(data)
}

// TestAPISiteCreateAppliesAndPersists is the whole point of the feature: a 201 is
// only honest if the fragment was rendered, validated, reloaded and written to the
// config file.
func TestAPISiteCreateAppliesAndPersists(t *testing.T) {
	f := newSiteFixture(t)

	rec := f.do(t, http.MethodPost, "/api/v1/sites", f.admin,
		siteBody(t, sites.Site{Host: "app.example.com", Upstream: "10.0.0.5:8080"}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// 1. Rendered and validated.
	if f.validate.calls != 1 {
		t.Errorf("expected the config to be validated once, got %d", f.validate.calls)
	}
	if _, ok := f.validate.files["app.example.com.conf"]; !ok {
		t.Errorf("validator did not see the fragment, saw: %v", keysOf(f.validate.files))
	}

	// 2. Reloaded.
	if f.reload.calls != 1 {
		t.Errorf("expected one reload, got %d", f.reload.calls)
	}

	// 3. On disk under the include directory.
	fragment, err := os.ReadFile(filepath.Join(f.sitesDir, "app.example.com.conf"))
	if err != nil {
		t.Fatalf("fragment not written: %v", err)
	}
	if !strings.Contains(string(fragment), "server_name app.example.com;") {
		t.Errorf("fragment does not serve the host:\n%s", fragment)
	}
	if !strings.Contains(string(fragment), "waffynx on;") {
		t.Errorf("fragment would proxy traffic uninspected:\n%s", fragment)
	}

	// 4. Persisted, preserving the rest of the document.
	cfg := f.configFile(t)
	if !strings.Contains(cfg, "app.example.com") {
		t.Errorf("site was not persisted:\n%s", cfg)
	}
	if !strings.Contains(cfg, "name: site-test") {
		t.Errorf("unrelated config keys were dropped:\n%s", cfg)
	}

	// 5. Visible through the API.
	list := f.do(t, http.MethodGet, "/api/v1/sites", f.viewer, "")
	if list.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", list.Code)
	}
	if !strings.Contains(list.Body.String(), "app.example.com") {
		t.Errorf("site missing from the listing: %s", list.Body.String())
	}
}

func TestAPISiteCreateRejectsInvalidInput(t *testing.T) {
	f := newSiteFixture(t)
	before := f.configFile(t)

	cases := map[string]sites.Site{
		"directive injection in host": {Host: "example.com; return 200", Upstream: "10.0.0.5:8080"},
		"upstream without port":       {Host: "example.com", Upstream: "backend"},
		"missing host":                {Host: "", Upstream: "10.0.0.5:8080"},
		"tls without key":             {Host: "example.com", Upstream: "10.0.0.5:8080", TLS: &sites.TLSPair{CertFile: "/c"}},
	}

	for name, site := range cases {
		t.Run(name, func(t *testing.T) {
			rec := f.do(t, http.MethodPost, "/api/v1/sites", f.admin, siteBody(t, site))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}

	if f.configFile(t) != before {
		t.Error("a rejected site must not touch the config file")
	}
	if f.validate.calls != 0 {
		t.Errorf("a rejected site must not reach nginx, validator ran %d times", f.validate.calls)
	}
}

func TestAPISiteCreateRejectsDuplicate(t *testing.T) {
	f := newSiteFixture(t)
	site := siteBody(t, sites.Site{Host: "app.example.com", Upstream: "10.0.0.5:8080"})

	if rec := f.do(t, http.MethodPost, "/api/v1/sites", f.admin, site); rec.Code != http.StatusCreated {
		t.Fatalf("first create: %d %s", rec.Code, rec.Body.String())
	}
	rec := f.do(t, http.MethodPost, "/api/v1/sites", f.admin, site)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestAPISiteCreateFailsClosedWhenNginxRejects covers the failure that matters: the
// configuration must not reach disk if nginx refuses it.
func TestAPISiteCreateFailsClosedWhenNginxRejects(t *testing.T) {
	f := newSiteFixture(t)
	before := f.configFile(t)
	f.validate.err = errors.New(`nginx: [emerg] unknown directive "waffynx"`)

	rec := f.do(t, http.MethodPost, "/api/v1/sites", f.admin,
		siteBody(t, sites.Site{Host: "app.example.com", Upstream: "10.0.0.5:8080"}))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "unknown directive") {
		t.Errorf("nginx's message must reach the caller, got: %s", rec.Body.String())
	}
	if f.configFile(t) != before {
		t.Error("a topology nginx rejected must not be persisted")
	}
	if f.reload.calls != 0 {
		t.Errorf("must not reload with a rejected config, reloaded %d times", f.reload.calls)
	}
	if entries, _ := os.ReadDir(f.sitesDir); len(entries) != 0 {
		t.Errorf("rejected fragments survived: %v", entries)
	}
}

func TestAPISiteUpdateReplacesFragment(t *testing.T) {
	f := newSiteFixture(t)
	if rec := f.do(t, http.MethodPost, "/api/v1/sites", f.admin,
		siteBody(t, sites.Site{Host: "app.example.com", Upstream: "10.0.0.5:8080"})); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}

	rec := f.do(t, http.MethodPut, "/api/v1/sites/app.example.com", f.admin,
		siteBody(t, sites.Site{Host: "app.example.com", Upstream: "10.0.0.9:9090"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	fragment, err := os.ReadFile(filepath.Join(f.sitesDir, "app.example.com.conf"))
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}
	if !strings.Contains(string(fragment), "10.0.0.9:9090") {
		t.Errorf("fragment was not updated:\n%s", fragment)
	}
	if strings.Contains(string(fragment), "10.0.0.5:8080") {
		t.Errorf("fragment still points at the old upstream:\n%s", fragment)
	}
}

func TestAPISiteUpdateCannotRename(t *testing.T) {
	f := newSiteFixture(t)
	if rec := f.do(t, http.MethodPost, "/api/v1/sites", f.admin,
		siteBody(t, sites.Site{Host: "app.example.com", Upstream: "10.0.0.5:8080"})); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}

	rec := f.do(t, http.MethodPut, "/api/v1/sites/app.example.com", f.admin,
		siteBody(t, sites.Site{Host: "other.example.com", Upstream: "10.0.0.5:8080"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when renaming, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "cannot be changed") {
		t.Errorf("expected an explanatory message, got: %s", rec.Body.String())
	}
}

func TestAPISiteDeleteRemovesFragmentAndConfig(t *testing.T) {
	f := newSiteFixture(t)
	if rec := f.do(t, http.MethodPost, "/api/v1/sites", f.admin,
		siteBody(t, sites.Site{Host: "app.example.com", Upstream: "10.0.0.5:8080"})); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}

	rec := f.do(t, http.MethodDelete, "/api/v1/sites/app.example.com", f.admin, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	if _, err := os.Stat(filepath.Join(f.sitesDir, "app.example.com.conf")); !os.IsNotExist(err) {
		t.Error("the fragment should have been removed")
	}
	if strings.Contains(f.configFile(t), "app.example.com") {
		t.Error("the site should have been removed from the config")
	}
	if rec := f.do(t, http.MethodDelete, "/api/v1/sites/app.example.com", f.admin, ""); rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 on the second delete, got %d", rec.Code)
	}
}

func TestAPISiteGetUnknownReturns404(t *testing.T) {
	f := newSiteFixture(t)
	if rec := f.do(t, http.MethodGet, "/api/v1/sites/nope.example.com", f.viewer, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// TestAPISitesRequireAdmin documents the RBAC split: reading the topology is fine
// for any authenticated user, changing it is not.
func TestAPISitesRequireAdmin(t *testing.T) {
	f := newSiteFixture(t)
	site := siteBody(t, sites.Site{Host: "app.example.com", Upstream: "10.0.0.5:8080"})

	if rec := f.do(t, http.MethodGet, "/api/v1/sites", f.viewer, ""); rec.Code != http.StatusOK {
		t.Errorf("viewer should be able to list sites, got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/api/v1/sites", f.viewer, site); rec.Code != http.StatusForbidden {
		t.Errorf("viewer should not create sites, got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodDelete, "/api/v1/sites/app.example.com", f.viewer, ""); rec.Code != http.StatusForbidden {
		t.Errorf("viewer should not delete sites, got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/api/v1/sites", "", site); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated create should be 401, got %d", rec.Code)
	}
}

func TestAPISiteListIsStableOrder(t *testing.T) {
	f := newSiteFixture(t)
	for _, host := range []string{"c.example.com", "a.example.com", "b.example.com"} {
		if rec := f.do(t, http.MethodPost, "/api/v1/sites", f.admin,
			siteBody(t, sites.Site{Host: host, Upstream: "10.0.0.5:8080"})); rec.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", host, rec.Code, rec.Body.String())
		}
	}

	rec := f.do(t, http.MethodGet, "/api/v1/sites", f.viewer, "")
	body := rec.Body.String()
	a, b, c := strings.Index(body, "a.example.com"), strings.Index(body, "b.example.com"), strings.Index(body, "c.example.com")
	if a < 0 || b < 0 || c < 0 || a >= b || b >= c {
		t.Errorf("expected hosts ordered a,b,c; got %s", body)
	}
}

func TestMergeSitesIntoConfigPreservesOtherKeys(t *testing.T) {
	merged, parsed, err := mergeSitesIntoConfig([]byte(siteTestConfig), []sites.Site{
		{Host: "app.example.com", Upstream: "10.0.0.5:8080"},
	})
	if err != nil {
		t.Fatalf("mergeSitesIntoConfig: %v", err)
	}
	if !bytes.Contains(merged, []byte("name: site-test")) {
		t.Errorf("unrelated keys were dropped:\n%s", merged)
	}
	if len(parsed.Sites) != 1 || parsed.Sites[0].Host != "app.example.com" {
		t.Errorf("sites not parsed back: %+v", parsed.Sites)
	}

	// Removing every site must delete the key rather than leave an empty list.
	cleared, clearedCfg, err := mergeSitesIntoConfig(merged, nil)
	if err != nil {
		t.Fatalf("clearing: %v", err)
	}
	if len(clearedCfg.Sites) != 0 {
		t.Errorf("expected no sites after clearing, got %+v", clearedCfg.Sites)
	}
	if bytes.Contains(cleared, []byte("sites:")) {
		t.Errorf("empty sites key should be removed:\n%s", cleared)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
