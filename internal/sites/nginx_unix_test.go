//go:build !windows

package sites

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakeNginxScript writes a stand-in binary that records its arguments and exits with
// the requested status. It lets the exec paths be tested without compiling nginx.
func fakeNginxScript(t *testing.T, exitCode int, stderr string) (path, argFile string) {
	t.Helper()
	dir := t.TempDir()
	argFile = filepath.Join(dir, "args.txt")
	script := filepath.Join(dir, "nginx")
	body := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + argFile + "\n" +
		"if [ -n \"" + stderr + "\" ]; then echo \"" + stderr + "\" >&2; fi\n" +
		"exit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing fake nginx: %v", err)
	}
	return script, argFile
}

func TestNginxValidatorRunsConfigTest(t *testing.T) {
	binary, argFile := fakeNginxScript(t, 0, "")
	confDir := t.TempDir()

	v := NginxValidator{BinaryPath: binary, ConfigPath: confDir}
	if err := v.ValidateConfig(context.Background(), "/ignored"); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	args, err := os.ReadFile(argFile)
	if err != nil {
		t.Fatalf("reading recorded args: %v", err)
	}
	got := string(args)
	if !strings.Contains(got, "-t") {
		t.Errorf("expected -t in the nginx invocation, got:\n%s", got)
	}
	if !strings.Contains(got, filepath.Join(confDir, "nginx.conf")) {
		t.Errorf("expected the configured nginx.conf path, got:\n%s", got)
	}
}

// TestNginxValidatorSurfacesStderr is what makes a failed apply actionable: the
// operator needs nginx's own diagnosis, not just "exit status 1".
func TestNginxValidatorSurfacesStderr(t *testing.T) {
	binary, _ := fakeNginxScript(t, 1, "nginx: [emerg] unknown directive waffynx")

	v := NginxValidator{BinaryPath: binary, ConfigPath: t.TempDir()}
	err := v.ValidateConfig(context.Background(), "")
	if err == nil {
		t.Fatal("expected a non-zero exit to be reported")
	}
	if !strings.Contains(err.Error(), "unknown directive") {
		t.Errorf("nginx's stderr must be in the error, got: %v", err)
	}
}

func TestNginxReloaderSignalsReload(t *testing.T) {
	binary, argFile := fakeNginxScript(t, 0, "")
	confDir := t.TempDir()

	r := NginxReloader{BinaryPath: binary, ConfigPath: confDir}
	if err := r.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	args, err := os.ReadFile(argFile)
	if err != nil {
		t.Fatalf("reading recorded args: %v", err)
	}
	if !strings.Contains(string(args), "-s\nreload") && !strings.Contains(string(args), "reload") {
		t.Errorf("expected a reload signal, got:\n%s", args)
	}
}

func TestNginxReloaderReportsFailure(t *testing.T) {
	binary, _ := fakeNginxScript(t, 1, "nginx: [error] invalid pid number")

	r := NginxReloader{BinaryPath: binary, ConfigPath: t.TempDir()}
	err := r.Reload(context.Background())
	if err == nil {
		t.Fatal("expected a failing reload to be reported")
	}
	if !strings.Contains(err.Error(), "invalid pid number") {
		t.Errorf("expected nginx's message in the error, got: %v", err)
	}
}
