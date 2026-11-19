package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jackby03/waffynx/internal/analytics"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/hotreload"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/pki"
	"github.com/jackby03/waffynx/internal/ratelimit"
	"github.com/jackby03/waffynx/internal/storage"
	"github.com/jackby03/waffynx/internal/xds"
)

// WireDistributedBackends initializes optional multi-container Control Plane
// backends (PostgreSQL, Redis hot-reload/jails, ClickHouse analytics, Envoy xDS
// with optional mTLS) according to cfg.Distributed and binds them to s.
// Returns a cleanup function closing open network pools.
func (s *Server) WireDistributedBackends(ctx context.Context, cfg *config.Config) (func(), error) {
	if cfg == nil {
		return func() {}, nil
	}
	d := cfg.Distributed
	var closers []func()
	cleanup := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	var db storage.Store
	if d.Postgres.Enabled && d.Postgres.DSN != "" {
		var pg *storage.PostgresStore
		var err error
		for attempt := 1; attempt <= 15; attempt++ {
			pg, err = storage.NewPostgresStore(ctx, d.Postgres.DSN)
			if err == nil {
				break
			}
			logging.Warn().Err(err).Int("attempt", attempt).Msg("waiting for PostgreSQL")
			select {
			case <-ctx.Done():
				cleanup()
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
		}
		db = pg
		closers = append(closers, func() { _ = pg.Close() })
		logging.Info().Msg("PostgreSQL control-plane store connected and migrated")
	}

	var (
		bus   hotreload.Bus
		jails ratelimit.JailStore
	)
	if d.Redis.Enabled && d.Redis.Addr != "" {
		var rbus *hotreload.RedisBus
		var err error
		for attempt := 1; attempt <= 10; attempt++ {
			rbus, err = hotreload.NewRedisBus(d.Redis.Addr, d.Redis.Password, d.Redis.DB)
			if err == nil {
				break
			}
			logging.Warn().Err(err).Int("attempt", attempt).Msg("waiting for Redis hot-reload bus")
			select {
			case <-ctx.Done():
				cleanup()
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
		if err != nil {
			logging.Warn().Err(err).Msg("Redis hot-reload unavailable at boot; continuing without live push")
		} else {
			bus = rbus
			closers = append(closers, func() { _ = rbus.Close() })
			logging.Info().Str("addr", d.Redis.Addr).Msg("Redis hot-reload bus connected")
		}

		rl, rlErr := ratelimit.NewRedisLimiter(ratelimit.Config{
			Enabled:   true,
			Addr:      d.Redis.Addr,
			Password:  d.Redis.Password,
			DB:        d.Redis.DB,
			TimeoutMs: d.Redis.TimeoutMs,
			FailOpen:  d.Redis.FailOpen,
		})
		if rlErr == nil && rl != nil {
			jails = rl
			closers = append(closers, func() { _ = rl.Close() })
		}
	}

	var reader analytics.Reader
	if d.ClickHouse.Enabled && d.ClickHouse.URL != "" {
		ch, err := analytics.NewClickHouseClient(analytics.Config{
			Enabled:  true,
			URL:      d.ClickHouse.URL,
			Database: d.ClickHouse.Database,
			Username: d.ClickHouse.Username,
			Password: d.ClickHouse.Password,
		})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("configuring ClickHouse reader: %w", err)
		}
		reader = ch
		logging.Info().Str("url", d.ClickHouse.URL).Msg("ClickHouse analytics reader configured")
	}

	var (
		xdsSrv    *xds.Server
		xdsTLS    *tls.Config
		xdsListen string
	)
	if d.XDS.Enabled {
		topo := xds.DefaultTopologyConfig()
		if d.XDS.HTTPPort > 0 {
			topo.HTTPPort = d.XDS.HTTPPort
		}
		if d.XDS.HTTPSPort > 0 {
			topo.HTTPSPort = d.XDS.HTTPSPort
		}
		if d.XDS.WAFEngineHost != "" {
			topo.WAFEngineHost = d.XDS.WAFEngineHost
		}
		if d.XDS.WAFEnginePort > 0 {
			topo.WAFEnginePort = d.XDS.WAFEnginePort
		}
		topo.FailureModeAllow = d.XDS.FailureModeAllow
		topo.EdgeTLS = d.XDS.EdgeTLS
		topo.UpstreamMTLS = d.XDS.UpstreamMTLS

		if d.MTLS.Enabled {
			certDir := d.MTLS.CertDir
			if certDir == "" {
				certDir = "/etc/waffynx/certs"
			}
			// Control-API presents its own leaf cert and requires Envoy client cert.
			certFile := firstNonEmpty(d.MTLS.CertFile, filepath.Join(certDir, "control-api.crt"))
			keyFile := firstNonEmpty(d.MTLS.KeyFile, filepath.Join(certDir, "control-api.key"))
			caFile := firstNonEmpty(d.MTLS.CAFile, filepath.Join(certDir, "ca.crt"))
			reloader, err := pki.NewReloader(certFile, keyFile, caFile)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("loading xDS mTLS credentials (fail-closed): %w", err)
			}
			xdsTLS = reloader.ServerTLSConfig(true)

			// Envoy's mounted certificate paths for downstream TLS & mTLS to waf-engine.
			topo.EngineMTLS = true
			topo.EnvoyCertPath = filepath.Join(certDir, "envoy.crt")
			topo.EnvoyKeyPath = filepath.Join(certDir, "envoy.key")
			topo.CACertPath = caFile
		}

		xdsSrv = xds.NewServer(topo)
		xdsListen = d.XDS.Listen
		if xdsListen == "" {
			xdsListen = ":18000"
		}
	}

	if db != nil || bus != nil || xdsSrv != nil || reader != nil || jails != nil {
		s.SetDistributedBackends(db, bus, xdsSrv, xdsListen, xdsTLS, reader, jails)
		if err := s.BootstrapDistributedState(ctx); err != nil {
			logging.Warn().Err(err).Msg("initial distributed state sync incomplete")
		}
	}

	return cleanup, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// LoadWithEnv loads configPath and overlays WAFFYNX_* distributed environment variables.
func LoadWithEnv(configPath string) (*config.Config, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	config.ApplyDistributedEnv(cfg, os.Getenv)
	return cfg, nil
}
