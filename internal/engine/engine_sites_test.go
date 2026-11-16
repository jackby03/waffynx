//go:build !windows

package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/sites"
)

// fakeNginx stands in for the nginx binary. It fails when any file under the
// config directory contains "BAD", which lets a test drive the real
// write -> nginx -t -> rollback path without compiling nginx.
func fakeNginx(t *testing.T) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "fake-nginx")
	body := `#!/bin/sh
cfg=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-c" ]; then cfg="$a"; fi
  prev="$a"
done
root=$(dirname "$cfg")
if grep -rq BAD "$root" 2>/dev/null; then
  echo "nginx: [emerg] invalid directive in generated config" >&2
  exit 1
fi
exit 0
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing fake nginx: %v", err)
	}
	return script
}

type fakeReloader struct {
	err   error
	calls int
}

func (r *fakeReloader) Reload(context.Context) error {
	r.calls++
	return r.err
}

// engineWithSites wires an Engine whose applier uses the fake nginx validator and
// an injected reloader, so the apply protocol can be exercised without a running
// proxy. Reload itself needs a live process, which is out of scope here.
func engineWithSites(t *testing.T) (*Engine, *fakeReloader, string) {
	t.Helper()
	binary := fakeNginx(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte("http { include sites/*.conf; }\n"), 0o600); err != nil {
		t.Fatalf("writing nginx.conf: %v", err)
	}

	cfg := &config.Config{Name: "engine-sites-test"}
	cfg.Nginx.BinaryPath = binary
	cfg.Nginx.ConfigPath = dir

	e := New(cfg)
	reloader := &fakeReloader{}
	e.siteApplier = &sites.Applier{
		Dir:       filepath.Join(dir, "sites"),
		Validator: nginxValidator{binaryPath: binary, configPath: dir},
		Reloader:  reloader,
	}
	return e, reloader, filepath.Join(dir, "sites")
}

func TestNginxValidatorSurfacesTheErrorMessage(t *testing.T) {
	binary := fakeNginx(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte("http {}\n"), 0o600); err != nil {
		t.Fatalf("writing nginx.conf: %v", err)
	}

	v := nginxValidator{binaryPath: binary, configPath: dir}
	if err := v.ValidateConfig(context.Background(), dir); err != nil {
		t.Fatalf("expected a clean config to validate, got: %v", err)
	}

	sitesDir := filepath.Join(dir, "sites")
	if err := os.MkdirAll(sitesDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sitesDir, "bad.conf"), []byte("BAD\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := v.ValidateConfig(context.Background(), dir)
	if err == nil {
		t.Fatal("expected validation to fail on a bad fragment")
	}
	if !strings.Contains(err.Error(), "invalid directive") {
		t.Errorf("nginx's own message must surface to the caller, got: %v", err)
	}
}

func TestEngineApplySitesWritesAndReloads(t *testing.T) {
	e, reloader, sitesDir := engineWithSites(t)

	res, err := e.ApplySites(context.Background(), map[string]string{
		"good.example.com.conf": "server { server_name good.example.com; }\n",
	})
	if err != nil {
		t.Fatalf("ApplySites: %v", err)
	}
	if res.Restored {
		t.Error("a successful apply must not roll back")
	}
	if len(res.Written) != 1 {
		t.Errorf("expected one written fragment, got %v", res.Written)
	}
	if reloader.calls != 1 {
		t.Errorf("expected one reload, got %d", reloader.calls)
	}
	if _, err := os.Stat(filepath.Join(sitesDir, "good.example.com.conf")); err != nil {
		t.Errorf("fragment was not written: %v", err)
	}
}

// TestEngineApplySitesRollsBackOnRejectedConfig is the end-to-end safety property:
// nginx rejects the rendered config, so nothing may become live and the previous
// fragments must survive.
func TestEngineApplySitesRollsBackOnRejectedConfig(t *testing.T) {
	e, reloader, sitesDir := engineWithSites(t)
	ctx := context.Background()

	previous := map[string]string{"good.example.com.conf": "server { server_name good.example.com; }\n"}
	if _, err := e.ApplySites(ctx, previous); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	reloadsBefore := reloader.calls

	res, err := e.ApplySites(ctx, map[string]string{"bad.example.com.conf": "BAD\n"})
	if err == nil {
		t.Fatal("expected ApplySites to fail on a rejected configuration")
	}
	if !res.Restored {
		t.Errorf("expected a rollback, got %+v", res)
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("expected a rejection error, got: %v", err)
	}
	if reloader.calls != reloadsBefore {
		t.Errorf("a rejected config must not be reloaded (reloads %d -> %d)", reloadsBefore, reloader.calls)
	}

	entries, readErr := os.ReadDir(sitesDir)
	if readErr != nil {
		t.Fatalf("readdir: %v", readErr)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != 1 || names[0] != "good.example.com.conf" {
		t.Errorf("expected only the previous fragment after rollback, got %v", names)
	}
	data, err2 := os.ReadFile(filepath.Join(sitesDir, "good.example.com.conf"))
	if err2 != nil {
		t.Fatalf("reading restored fragment: %v", err2)
	}
	if string(data) != previous["good.example.com.conf"] {
		t.Errorf("restored fragment differs: %q", string(data))
	}
}

func TestEngineApplySitesRollsBackOnReloadFailure(t *testing.T) {
	e, reloader, sitesDir := engineWithSites(t)
	ctx := context.Background()

	previous := map[string]string{"good.example.com.conf": "old\n"}
	if _, err := e.ApplySites(ctx, previous); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	reloader.err = errors.New("nginx is not running")
	res, err := e.ApplySites(ctx, map[string]string{"good.example.com.conf": "new\n"})
	if err == nil {
		t.Fatal("expected the apply to fail when the reload fails")
	}
	if !res.Restored {
		t.Errorf("expected a rollback after a failed reload, got %+v", res)
	}
	if !strings.Contains(err.Error(), "reload") {
		t.Errorf("expected a reload error, got: %v", err)
	}

	data, readErr := os.ReadFile(filepath.Join(sitesDir, "good.example.com.conf"))
	if readErr != nil {
		t.Fatalf("reading restored fragment: %v", readErr)
	}
	if string(data) != "old\n" {
		t.Errorf("expected the previous content to be restored, got %q", string(data))
	}
}

func TestEngineApplySitesRefusesMissingConfigPath(t *testing.T) {
	e := New(&config.Config{Name: "no-nginx"})
	// Must fail clearly instead of creating a relative "sites" directory in the
	// working directory, which is what the first version of this did.
	if _, err := e.ApplySites(context.Background(), map[string]string{"a.example.com.conf": "x"}); err == nil {
		t.Fatal("expected an error with no nginx config path configured")
	}
	if _, err := os.Stat("sites"); err == nil {
		t.Fatal("ApplySites created a relative sites directory")
	}
}
