//go:build !windows

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackby03/waffynx/internal/config"
)

// fakeNginx writes a stand-in for the nginx binary. It fails when any file under
// the config directory contains "BAD", which lets a test drive the
// write -> nginx -t -> rollback path without compiling nginx.
func fakeNginx(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-nginx")
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

func engineWithConfigDir(t *testing.T, binary string) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte("http { include sites/*.conf; }\n"), 0o600); err != nil {
		t.Fatalf("writing nginx.conf: %v", err)
	}
	cfg := &config.Config{Name: "engine-sites-test"}
	cfg.Nginx.BinaryPath = binary
	cfg.Nginx.ConfigPath = dir
	return New(cfg), dir
}

func TestNginxValidatorSurfacesTheErrorMessage(t *testing.T) {
	binary := fakeNginx(t)
	_, dir := engineWithConfigDir(t, binary)

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

// TestEngineApplySitesRollsBackOnRejectedConfig walks the real Engine wiring: the
// rejected fragments must not survive, and the previous set must be restored
// before anything can be reloaded.
func TestEngineApplySitesRollsBackOnRejectedConfig(t *testing.T) {
	binary := fakeNginx(t)
	e, dir := engineWithConfigDir(t, binary)
	ctx := context.Background()

	good := map[string]string{"good.example.com.conf": "server { server_name good.example.com; }\n"}
	if _, err := e.ApplySites(ctx, good); err != nil {
		// The reload will fail because no nginx is running; that is expected and
		// exercises the reload-failure branch, which also rolls back.
		if !strings.Contains(err.Error(), "reload") {
			t.Fatalf("unexpected error on the first apply: %v", err)
		}
	}

	sitesDir := filepath.Join(dir, "sites")
	if _, statErr := os.Stat(filepath.Join(sitesDir, "good.example.com.conf")); statErr != nil {
		t.Fatalf("the first apply should have written its fragment: %v", statErr)
	}

	// Now apply fragments that the stand-in nginx rejects.
	bad := map[string]string{"bad.example.com.conf": "BAD\n"}
	res, err := e.ApplySites(ctx, bad)
	if err == nil {
		t.Fatal("expected ApplySites to fail on a rejected configuration")
	}
	if !res.Restored {
		t.Errorf("expected a rollback, got %+v", res)
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("expected a rejection error, got: %v", err)
	}

	entries, readErr := os.ReadDir(sitesDir)
	if readErr != nil {
		t.Fatalf("readdir: %v", readErr)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "bad.example.com") {
			t.Errorf("rejected fragment %q survived the rollback", entry.Name())
		}
	}
}

func TestEngineApplySitesRequiresLinuxWiring(t *testing.T) {
	e := New(&config.Config{Name: "no-nginx"})
	// ConfigPath empty: the engine must fail clearly rather than write somewhere odd.
	if _, err := e.ApplySites(context.Background(), map[string]string{"a.example.com.conf": "x"}); err == nil {
		t.Fatal("expected an error with no nginx config path configured")
	}
}
