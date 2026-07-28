//go:build !windows

package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/jackby03/waffynx/internal/logging"
)

// Start launches the Go sidecar first, then nginx.
// The sidecar must be running before nginx so the ngx_waffynx
// module can connect to the Unix socket on its first request.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("engine already running")
	}

	// -- 1. Start the Go sidecar (Unix socket HTTP server) --
	e.sidecar = NewSidecar(e.cfg.Sidecar.SocketPath, e.policy, e.chain, e.scorer, e.learning)
	if err := e.sidecar.Start(); err != nil {
		return fmt.Errorf("starting sidecar: %w", err)
	}

	// -- 2. Start nginx --
	e.cmd = exec.CommandContext(ctx, e.cfg.Nginx.BinaryPath,
		"-c", e.cfg.Nginx.ConfigPath+"/nginx.conf",
		"-g", "daemon off;",
	)
	e.cmd.Stdout = os.Stdout
	e.cmd.Stderr = os.Stderr
	e.cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	logging.Info().
		Str("binary", e.cfg.Nginx.BinaryPath).
		Str("socket", e.cfg.Sidecar.SocketPath).
		Msg("starting nginx engine with waffynx module")

	if err := e.cmd.Start(); err != nil {
		e.sidecar.Stop()
		return fmt.Errorf("starting nginx: %w", err)
	}

	e.running = true
	return nil
}

// Stop gracefully shuts down nginx (SIGTERM) then the sidecar.
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	logging.Info().Msg("stopping waffynx engine")

	// Stop nginx first
	if e.cmd != nil && e.cmd.Process != nil {
		if err := e.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			logging.Warn().Err(err).Msg("SIGTERM failed, sending SIGKILL")
			e.cmd.Process.Kill()
		}
		e.cmd.Wait()
	}

	// Then stop the sidecar
	if e.sidecar != nil {
		if err := e.sidecar.Stop(); err != nil {
			logging.Warn().Err(err).Msg("sidecar stop error")
		}
	}

	e.running = false
	return nil
}

// Reload sends SIGHUP to nginx to reload its configuration.
func (e *Engine) Reload() error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.running || e.cmd == nil {
		return fmt.Errorf("engine not running")
	}

	logging.Info().Msg("reloading nginx configuration")
	return e.cmd.Process.Signal(syscall.SIGHUP)
}
