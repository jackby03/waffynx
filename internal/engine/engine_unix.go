//go:build !windows

package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/sites"
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
	e.sidecar = NewSidecar(e.cfg.Sidecar.SocketPath, e.policy, e.chain, e.scorer, e.learning, e.audit, e.rules, e.broker)
	if e.cfg.Sidecar.EventAPIURL != "" && e.cfg.Sidecar.EventAuthToken != "" {
		e.sidecar.SetEventPublisher(events.NewPublisher(
			e.cfg.Sidecar.EventAPIURL,
			e.cfg.Sidecar.EventAuthToken,
			time.Duration(e.cfg.Sidecar.EventTimeoutMs)*time.Millisecond,
		))
	}
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
		if stopErr := e.sidecar.Stop(); stopErr != nil {
			logging.Warn().Err(stopErr).Msg("stopping sidecar after failed nginx start")
		}
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
			if killErr := e.cmd.Process.Kill(); killErr != nil {
				logging.Error().Err(killErr).Msg("SIGKILL failed")
			}
		}
		if err := e.cmd.Wait(); err != nil {
			logging.Warn().Err(err).Msg("nginx exited with error")
		}
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

// engineReloader adapts Engine.Reload to the sites.Reloader interface.
type engineReloader struct {
	e *Engine
}

func (r engineReloader) Reload(context.Context) error {
	return r.e.Reload()
}

// ApplySites renders the given fragments into the nginx include directory and
// makes them live.
//
// The order is write -> `nginx -t` -> reload, with a rollback on any failure. A
// rejected configuration never becomes live, and a failed reload leaves the
// previous fragments on disk.
func (e *Engine) ApplySites(ctx context.Context, fragments map[string]string) (sites.ApplyResult, error) {
	if e.cfg.Nginx.ConfigPath == "" {
		return sites.ApplyResult{}, errors.New("applying sites: nginx config path is not configured")
	}
	dir := filepath.Join(e.cfg.Nginx.ConfigPath, "sites")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return sites.ApplyResult{}, fmt.Errorf("creating sites directory: %w", err)
	}

	applier := e.siteApplier
	if applier == nil {
		applier = &sites.Applier{
			Dir: dir,
			Validator: sites.NginxValidator{
				BinaryPath: e.cfg.Nginx.BinaryPath,
				ConfigPath: e.cfg.Nginx.ConfigPath,
			},
			Reloader: engineReloader{e: e},
		}
		e.siteApplier = applier
	}

	return applier.Apply(ctx, fragments)
}
