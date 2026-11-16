package sites

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// errNoBinary is returned when the nginx path is empty, which would otherwise
// surface as a confusing "exec: no command" from os/exec.
var errNoBinary = fmt.Errorf("nginx binary path is not configured")

// NginxValidator checks a rendered configuration with `nginx -t`.
//
// The directory argument of ValidateConfig is ignored on purpose: nginx validates
// the include path baked into its own nginx.conf, so validating a different
// directory would give a false sense of safety.
type NginxValidator struct {
	BinaryPath string
	ConfigPath string
}

// ValidateConfig runs `nginx -t` and returns nginx's own message on failure.
func (v NginxValidator) ValidateConfig(ctx context.Context, _ string) error {
	if v.BinaryPath == "" {
		return errNoBinary
	}
	if v.ConfigPath == "" {
		return fmt.Errorf("nginx config path is not configured")
	}

	cmd := exec.CommandContext(ctx, v.BinaryPath, "-t", "-c", filepath.Join(v.ConfigPath, "nginx.conf"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = "no output"
		}
		return fmt.Errorf("nginx -t: %s: %w", msg, err)
	}
	return nil
}

// NginxReloader asks a running nginx to reload via `nginx -s reload`, which signals
// the master through its pid file. It is used by the control plane, which does not
// own the nginx process; the engine, which does, signals the child directly.
type NginxReloader struct {
	BinaryPath string
	ConfigPath string
}

// Reload sends the reload signal.
func (r NginxReloader) Reload(ctx context.Context) error {
	if r.BinaryPath == "" {
		return errNoBinary
	}

	args := []string{"-s", "reload"}
	if r.ConfigPath != "" {
		args = append(args, "-c", filepath.Join(r.ConfigPath, "nginx.conf"))
	}

	cmd := exec.CommandContext(ctx, r.BinaryPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = "no output"
		}
		return fmt.Errorf("nginx -s reload: %s: %w", msg, err)
	}
	return nil
}
