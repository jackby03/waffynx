package sites

import (
	"context"
	"strings"
	"testing"
)

// TestNginxValidatorRequiresConfiguration covers the misconfiguration paths that do
// not need a binary: an empty path must fail with a clear message instead of the
// opaque "exec: no command" os/exec would produce.
func TestNginxValidatorRequiresConfiguration(t *testing.T) {
	err := NginxValidator{}.ValidateConfig(context.Background(), "/tmp")
	if err == nil {
		t.Fatal("expected an error with no binary path")
	}
	if !strings.Contains(err.Error(), "binary path") {
		t.Errorf("expected the message to name the missing setting, got: %v", err)
	}

	err = NginxValidator{BinaryPath: "/bin/true"}.ValidateConfig(context.Background(), "/tmp")
	if err == nil {
		t.Fatal("expected an error with no config path")
	}
	if !strings.Contains(err.Error(), "config path") {
		t.Errorf("expected the message to name the missing setting, got: %v", err)
	}
}

func TestNginxReloaderRequiresConfiguration(t *testing.T) {
	err := NginxReloader{}.Reload(context.Background())
	if err == nil {
		t.Fatal("expected an error with no binary path")
	}
	if !strings.Contains(err.Error(), "binary path") {
		t.Errorf("expected the message to name the missing setting, got: %v", err)
	}
}
