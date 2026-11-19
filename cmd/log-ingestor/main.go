// Command log-ingestor runs the asynchronous Observability Plane worker that
// consumes security telemetry from NATS JetStream in batches, enriches GeoIP,
// enforces PII redaction, and bulk-inserts into ClickHouse (Phase 4 & Constitution §1.3).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/analytics"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/ingestor"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/metrics"
	"github.com/jackby03/waffynx/internal/version"
)

func main() {
	var healthListen string
	var logLevel string

	cmd := &cobra.Command{
		Use:     "log-ingestor",
		Short:   "Waffynx Async Telemetry Ingestor (NATS JetStream -> GeoIP/PII Mask -> ClickHouse)",
		Version: version.Version,
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(healthListen, logLevel)
		},
	}

	cmd.Flags().StringVar(&healthListen, "health-listen", ":8082", "internal health/metrics listen address")
	cmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "log level")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(healthListen, logLevel string) error {
	logging.Setup(config.LoggingConfig{Level: logLevel, Format: "json", Output: "stdout"}, logLevel)

	natsURL := envOr("WAFFYNX_NATS_URL", "nats://nats:4222")
	chURL := envOr("WAFFYNX_CLICKHOUSE_URL", "http://clickhouse:8123")
	chDB := envOr("WAFFYNX_CLICKHOUSE_DB", "waffynx")
	chUser := os.Getenv("WAFFYNX_CLICKHOUSE_USER")
	chPass := os.Getenv("WAFFYNX_CLICKHOUSE_PASSWORD")
	geoPath := os.Getenv("WAFFYNX_GEOIP_DB")

	batchSize := 500
	if raw := os.Getenv("WAFFYNX_INGEST_BATCH_SIZE"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			batchSize = n
		}
	}
	flushMs := 1000
	if raw := os.Getenv("WAFFYNX_INGEST_FLUSH_MS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			flushMs = n
		}
	}

	chClient, err := analytics.NewClickHouseClient(analytics.Config{
		Enabled:  true,
		URL:      chURL,
		Database: chDB,
		Username: chUser,
		Password: chPass,
	})
	if err != nil {
		return fmt.Errorf("configuring ClickHouse client: %w", err)
	}

	geo, err := ingestor.NewGeoResolver(geoPath)
	if err != nil {
		logging.Warn().Err(err).Str("path", geoPath).Msg("GeoIP MMDB unavailable; continuing with local/XX fallback")
		geo, _ = ingestor.NewGeoResolver("")
	}
	defer func() { _ = geo.Close() }()

	worker := ingestor.NewWorker(ingestor.Config{
		NATSURL:       natsURL,
		NATSToken:     os.Getenv("WAFFYNX_NATS_TOKEN"),
		GeoIPDBPath:   geoPath,
		BatchSize:     batchSize,
		FlushInterval: time.Duration(flushMs) * time.Millisecond,
	}, chClient, geo)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","plane":"observability","service":"log-ingestor"}`))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !worker.Ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"initializing"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ready",
			"written": worker.WrittenCount(),
		})
	})
	mux.Handle("GET /metrics", metrics.Handler())

	probeSrv := &http.Server{
		Addr:              healthListen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := probeSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Error().Err(err).Msg("log-ingestor probe server error")
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err = worker.Run(ctx)
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = probeSrv.Shutdown(shutCtx)
	if err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
