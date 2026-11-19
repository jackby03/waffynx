// Command waf-engine runs the stateless, horizontally scalable Waffynx Data
// Plane microservice serving Envoy ext_proc (L7 WAF inspection) and ext_authz
// (Zero-Trust continuous authorization) over mTLS gRPC (Constitution §1.2-§1.4).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/auth"
	"github.com/jackby03/waffynx/internal/authz"
	"github.com/jackby03/waffynx/internal/catalog"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/envoy"
	"github.com/jackby03/waffynx/internal/hotreload"
	"github.com/jackby03/waffynx/internal/ingestor"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/metrics"
	"github.com/jackby03/waffynx/internal/pki"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
	"github.com/jackby03/waffynx/internal/ratelimit"
	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/telemetry"
	"github.com/jackby03/waffynx/internal/version"

	_ "github.com/jackby03/waffynx/plugins/all"
)

func main() {
	var cfgFile string
	var logLevel string

	cmd := &cobra.Command{
		Use:     "waf-engine",
		Short:   "Waffynx Stateless Zero-Trust WAF Data Plane Engine (Envoy ext_proc + ext_authz)",
		Version: version.Version,
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(cfgFile, logLevel)
		},
	}

	cmd.Flags().StringVarP(&cfgFile, "config", "c", "/opt/waffynx/config/waffynx.yaml", "optional config file path")
	cmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "log level")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfgFile, logLevel string) error {
	var cfg *config.Config
	if cfgFile != "" {
		if loaded, err := config.Load(cfgFile); err == nil {
			cfg = loaded
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("loading config %s: %w", cfgFile, err)
		}
	}
	if cfg == nil {
		var err error
		cfg, err = config.Parse([]byte("listen: ':8443'\n"))
		if err != nil {
			return err
		}
	}
	config.ApplyDistributedEnv(cfg, os.Getenv)
	logging.Setup(cfg.Logging, logLevel)

	d := cfg.Distributed
	grpcListen := d.Engine.GRPCListen
	if grpcListen == "" {
		grpcListen = ":50051"
	}
	healthListen := d.Engine.HealthListen
	if healthListen == "" {
		healthListen = ":8081"
	}
	nodeID := d.Engine.NodeID
	if nodeID == "" {
		if host, err := os.Hostname(); err == nil && host != "" {
			nodeID = host
		} else {
			nodeID = "waf-engine"
		}
	}

	// 1. Load managed Aho-Corasick ruleset (fail-closed if broken).
	var managed *catalog.Catalog
	var err error
	if cfg.WAF.CatalogPath != "" {
		managed, err = catalog.LoadFile(cfg.WAF.CatalogPath)
	} else {
		managed, err = catalog.Embedded()
	}
	if err != nil {
		return fmt.Errorf("loading managed catalog: %w", err)
	}
	logging.Info().Int("rules", managed.Count()).Msg("managed catalog compiled")

	// 2. Load built-in inspection plugins (excluding standalone rate-limit when Redis sliding-window is active).
	chain := plugin.NewChain()
	reg := plugin.GetRegistry()
	for _, pc := range cfg.Plugins {
		if !pc.Enabled || (pc.Name == "rate-limit" && d.Engine.RateLimitEnabled) {
			continue
		}
		p, createErr := reg.Create(pc.Name, pc.Config)
		if createErr != nil {
			logging.Warn().Err(createErr).Str("plugin", pc.Name).Msg("skipping plugin")
			continue
		}
		chain.Add(p)
	}

	// 3. Configure ML AppSec scorer.
	var scorer appsec.Scorer = appsec.NewBasicScorer()
	if cfg.AppSec.Enabled && cfg.AppSec.Engine == "open-appsec" {
		scorer = appsec.NewBridgeScorer(
			cfg.AppSec.BridgeSocket,
			time.Duration(cfg.AppSec.TimeoutMs)*time.Millisecond,
		)
	}

	// 4. Ephemeral Redis state (sliding-window rate limit + IP jails + hot-reload bus).
	var (
		limiter ratelimit.Limiter
		jails   ratelimit.JailStore
		bus     hotreload.Bus
	)
	if d.Redis.Enabled && d.Redis.Addr != "" {
		rl, rlErr := ratelimit.NewRedisLimiter(ratelimit.Config{
			Enabled:   true,
			Addr:      d.Redis.Addr,
			Password:  d.Redis.Password,
			DB:        d.Redis.DB,
			TimeoutMs: d.Redis.TimeoutMs,
			FailOpen:  d.Redis.FailOpen,
		})
		if rlErr != nil {
			logging.Warn().Err(rlErr).Msg("Redis rate limiter unavailable at startup; using in-memory fallback until reconnect")
			mem := ratelimit.NewMemoryLimiter()
			limiter, jails = mem, mem
		} else if rl != nil {
			limiter, jails = rl, rl
			defer func() { _ = rl.Close() }()
		}

		rbus, busErr := hotreload.NewRedisBus(d.Redis.Addr, d.Redis.Password, d.Redis.DB)
		if busErr != nil {
			logging.Warn().Err(busErr).Msg("Redis hot-reload unavailable at startup; enforcing baseline catalog")
		} else {
			bus = rbus
			defer func() { _ = rbus.Close() }()
		}
	} else {
		mem := ratelimit.NewMemoryLimiter()
		defer func() { _ = mem.Close() }()
		limiter, jails = mem, mem
	}

	// 5. Async non-blocking NATS JetStream telemetry emitter (never blocks hot path).
	var emitter telemetry.Emitter
	if d.NATS.Enabled && d.NATS.URL != "" {
		em, natsErr := telemetry.NewNATSEmitter(telemetry.NATSConfig{
			Enabled:       true,
			URL:           d.NATS.URL,
			Token:         d.NATS.Token,
			StreamName:    d.NATS.StreamName,
			SubjectPrefix: d.NATS.SubjectPrefix,
			BufferSize:    d.NATS.BufferSize,
		})
		if natsErr != nil {
			logging.Warn().Err(natsErr).Msg("NATS JetStream unreachable at startup; continuing inspection without external telemetry")
		} else if em != nil {
			emitter = em
			defer func() { _ = em.Close() }()
			logging.Info().Str("nats", d.NATS.URL).Msg("async NATS JetStream telemetry emitter started")
		}
	}

	// 6. Optional local GeoIP database for Zero-Trust country posture checks.
	geo, geoErr := ingestor.NewGeoResolver(d.Engine.GeoIPDBPath)
	if geoErr != nil {
		logging.Warn().Err(geoErr).Msg("GeoIP database unavailable; country checks disabled")
		geo, _ = ingestor.NewGeoResolver("")
	}
	defer func() { _ = geo.Close() }()

	// 7. Zero-Trust JWT verifier for ext_authz.
	var jwtMgr *auth.Manager
	jwtSecret := os.Getenv(config.EnvJWTSecret)
	if jwtSecret == "" {
		jwtSecret = cfg.API.Auth.JWTSecret
	}
	if len(jwtSecret) >= 32 && jwtSecret != "change-me-in-production" {
		jwtMgr = auth.NewManager(jwtSecret, 3600)
	}

	ztEval := authz.NewEvaluator(jwtMgr, geo.Country)
	ztSrv := authz.NewServer(ztEval, emitter, nodeID)

	proc := envoy.NewProcessor(
		envoy.Config{
			NodeID:            nodeID,
			MaxBodyBytes:      d.Engine.MaxBodyBytes,
			ShadowMode:        d.Engine.ShadowMode,
			AppSecFailOpen:    cfg.AppSec.FailOpen,
			RateLimitEnabled:  d.Engine.RateLimitEnabled,
			RateLimitRPS:      d.Engine.RateLimitRPS,
			RateLimitWindow:   time.Second,
			RateLimitFailOpen: d.Redis.FailOpen,
		},
		managed,
		chain,
		rules.NewEngine(),
		policy.NewRuleEngine(),
		scorer,
		limiter,
		jails,
		emitter,
	)

	// 8. Configure gRPC server with strict TLS 1.3 mTLS when enabled (Constitution §1.4).
	var grpcOpts []grpc.ServerOption
	if d.MTLS.Enabled {
		certDir := d.MTLS.CertDir
		if certDir == "" {
			certDir = "/etc/waffynx/certs"
		}
		certFile := d.MTLS.CertFile
		if certFile == "" {
			certFile = filepath.Join(certDir, "waf-engine.crt")
		}
		keyFile := d.MTLS.KeyFile
		if keyFile == "" {
			keyFile = filepath.Join(certDir, "waf-engine.key")
		}
		caFile := d.MTLS.CAFile
		if caFile == "" {
			caFile = filepath.Join(certDir, "ca.crt")
		}
		reloader, pkiErr := pki.NewReloader(certFile, keyFile, caFile)
		if pkiErr != nil {
			return fmt.Errorf("loading waf-engine mTLS credentials (fail-closed): %w", pkiErr)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(reloader.ServerTLSConfig(true))))
	}

	grpcServer := grpc.NewServer(grpcOpts...)
	extprocv3.RegisterExternalProcessorServer(grpcServer, proc)
	authv3.RegisterAuthorizationServer(grpcServer, ztSrv)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 9. Hydrate initial policy snapshot & subscribe to Redis Pub/Sub hot-reload.
	var ready atomic.Bool
	applySnap := func(snap hotreload.PolicySnapshot) {
		proc.ApplySnapshot(snap)
		ztEval.ReplacePolicies(snap.ZTPolicies)
		logging.Info().
			Int64("revision", snap.Revision).
			Int("custom_rules", len(snap.CustomRules)).
			Int("exclusions", len(snap.Exclusions)).
			Int("zt_policies", len(snap.ZTPolicies)).
			Int("banned_ips", len(snap.BannedIPs)).
			Msg("applied lock-free atomic.Pointer policy snapshot")
	}
	if bus != nil {
		if latest, err := bus.LatestSnapshot(ctx); err == nil && latest != nil {
			applySnap(*latest)
		}
		go func() {
			_ = bus.Subscribe(ctx, applySnap)
		}()
	}

	// 10. Start internal health/readiness/metrics HTTP server.
	probeMux := http.NewServeMux()
	probeMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","plane":"data-plane","service":"waf-engine"}`))
	})
	probeMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"starting"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":          "ready",
			"node_id":         nodeID,
			"policy_revision": proc.Revision(),
			"shadow_mode":     d.Engine.ShadowMode,
		})
	})
	probeMux.Handle("GET /metrics", metrics.Handler())

	probeSrv := &http.Server{
		Addr:              healthListen,
		Handler:           probeMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := probeSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Error().Err(err).Msg("waf-engine probe server error")
		}
	}()

	ln, err := net.Listen("tcp", grpcListen)
	if err != nil {
		return fmt.Errorf("listening gRPC on %s: %w", grpcListen, err)
	}
	ready.Store(true)

	logging.Info().
		Str("grpc", grpcListen).
		Str("health", healthListen).
		Str("node_id", nodeID).
		Bool("mtls", d.MTLS.Enabled).
		Bool("shadow_mode", d.Engine.ShadowMode).
		Msg("waf-engine Data Plane ready")

	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcServer.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		logging.Info().Msg("draining waf-engine gRPC connections")
		grpcServer.GracefulStop()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = probeSrv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}
