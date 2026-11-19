// Package ingestor implements the asynchronous Observability Plane worker that
// consumes security events from NATS JetStream in batches, enriches them with
// local GeoIP (.mmdb), enforces PII/credential redaction, and bulk-inserts them
// into ClickHouse (Phase 4 & Constitution §1.3, §2.2).
package ingestor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oschwald/maxminddb-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/jackby03/waffynx/internal/analytics"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/telemetry"
)

var (
	ingestedEventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "waffynx_ingestor_events_total",
		Help: "Total security events persisted to ClickHouse by log-ingestor.",
	})
	ingestBatchesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "waffynx_ingestor_batches_total",
		Help: "Total bulk insert batches processed by status.",
	}, []string{"status"})
)

// Config controls batching, GeoIP enrichment, and NATS consumer settings.
type Config struct {
	NATSURL       string
	NATSToken     string
	StreamName    string
	ConsumerName  string
	SubjectFilter string
	GeoIPDBPath   string
	BatchSize     int
	FlushInterval time.Duration
}

// GeoResolver maps an IP string to an ISO country code (or "LOCAL" for RFC1918/loopback).
type GeoResolver struct {
	reader *maxminddb.Reader
}

// NewGeoResolver opens a local MaxMind GeoLite2-Country .mmdb file when path is non-empty.
func NewGeoResolver(path string) (*GeoResolver, error) {
	if path == "" {
		return &GeoResolver{}, nil
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening geoip database %s: %w", path, err)
	}
	return &GeoResolver{reader: r}, nil
}

// Country resolves ip to an ISO 3166-1 alpha-2 code (or "LOCAL" for private networks).
func (g *GeoResolver) Country(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "LOCAL"
	}
	if g == nil || g.reader == nil {
		return "XX"
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := g.reader.Lookup(ip, &rec); err == nil && rec.Country.ISOCode != "" {
		return rec.Country.ISOCode
	}
	return "XX"
}

func (g *GeoResolver) Close() error {
	if g != nil && g.reader != nil {
		return g.reader.Close()
	}
	return nil
}

// Worker batches, enriches, redacts, and bulk-inserts SecurityEvents into ClickHouse.
type Worker struct {
	cfg    Config
	writer analytics.Writer
	geo    *GeoResolver

	mu      sync.Mutex
	batch   []telemetry.SecurityEvent
	written atomic.Uint64
	ready   atomic.Bool
}

// NewWorker initializes a log-ingestor Worker.
func NewWorker(cfg Config, writer analytics.Writer, geo *GeoResolver) *Worker {
	if cfg.StreamName == "" {
		cfg.StreamName = telemetry.DefaultStreamName
	}
	if cfg.ConsumerName == "" {
		cfg.ConsumerName = "waffynx-log-ingestor"
	}
	if cfg.SubjectFilter == "" {
		cfg.SubjectFilter = telemetry.DefaultSubjectPrefix + ".>"
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	return &Worker{
		cfg:    cfg,
		writer: writer,
		geo:    geo,
		batch:  make([]telemetry.SecurityEvent, 0, cfg.BatchSize),
	}
}

// Ready reports whether ClickHouse schema initialization succeeded and NATS is consuming.
func (w *Worker) Ready() bool { return w.ready.Load() }

// WrittenCount reports total events persisted to ClickHouse.
func (w *Worker) WrittenCount() uint64 { return w.written.Load() }

// EnrichAndAppend decodes raw JSON, enriches GeoIP, re-enforces PII redaction,
// appends to the batch, and flushes immediately if BatchSize is reached.
func (w *Worker) EnrichAndAppend(ctx context.Context, raw []byte) error {
	var ev telemetry.SecurityEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return fmt.Errorf("decoding security event: %w", err)
	}
	if ev.CountryCode == "" && ev.RemoteIP != "" && w.geo != nil {
		ev.CountryCode = w.geo.Country(ev.RemoteIP)
	}
	ev = telemetry.RedactEvent(ev)

	w.mu.Lock()
	w.batch = append(w.batch, ev)
	shouldFlush := len(w.batch) >= w.cfg.BatchSize
	w.mu.Unlock()

	if shouldFlush {
		return w.Flush(ctx)
	}
	return nil
}

// Flush writes all currently buffered events to ClickHouse in one bulk insert.
func (w *Worker) Flush(ctx context.Context) error {
	w.mu.Lock()
	if len(w.batch) == 0 {
		w.mu.Unlock()
		return nil
	}
	toWrite := w.batch
	w.batch = make([]telemetry.SecurityEvent, 0, w.cfg.BatchSize)
	w.mu.Unlock()

	if err := w.writer.BulkInsert(ctx, toWrite); err != nil {
		ingestBatchesTotal.WithLabelValues("error").Inc()
		// Re-queue failed batch up to 4x BatchSize so transient ClickHouse restarts don't lose events.
		w.mu.Lock()
		if len(w.batch)+len(toWrite) <= w.cfg.BatchSize*4 {
			w.batch = append(toWrite, w.batch...)
		}
		w.mu.Unlock()
		return err
	}

	n := uint64(len(toWrite))
	w.written.Add(n)
	ingestedEventsTotal.Add(float64(n))
	ingestBatchesTotal.WithLabelValues("ok").Inc()
	return nil
}

// Run initializes ClickHouse schema, connects to NATS JetStream, and processes
// batches until ctx is cancelled, performing a final drain flush on shutdown.
func (w *Worker) Run(ctx context.Context) error {
	// Wait for ClickHouse readiness & create schema with backoff.
	for {
		if err := w.writer.InitSchema(ctx); err == nil {
			break
		} else {
			logging.Warn().Err(err).Msg("waiting for ClickHouse schema init")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	opts := []nats.Option{
		nats.Name(w.cfg.ConsumerName),
		nats.ReconnectWait(time.Second),
		nats.MaxReconnects(-1),
	}
	if w.cfg.NATSToken != "" {
		opts = append(opts, nats.Token(w.cfg.NATSToken))
	}

	var nc *nats.Conn
	for {
		var err error
		nc, err = nats.Connect(w.cfg.NATSURL, opts...)
		if err == nil {
			break
		}
		logging.Warn().Err(err).Str("url", w.cfg.NATSURL).Msg("waiting for NATS")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	defer nc.Close()

	js, err := jetstream.New(nc)
	if err != nil {
		return fmt.Errorf("initializing jetstream: %w", err)
	}

	// Ensure stream exists even if ingestor boots before waf-engine.
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      w.cfg.StreamName,
		Subjects:  []string{w.cfg.SubjectFilter},
		Retention: jetstream.LimitsPolicy,
		MaxAge:    24 * time.Hour,
		MaxBytes:  512 * 1024 * 1024,
		Storage:   jetstream.FileStorage,
		Discard:   jetstream.DiscardOld,
	})
	if err != nil {
		return fmt.Errorf("ensuring stream %s: %w", w.cfg.StreamName, err)
	}

	cons, err := js.CreateOrUpdateConsumer(ctx, w.cfg.StreamName, jetstream.ConsumerConfig{
		Durable:       w.cfg.ConsumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: w.cfg.SubjectFilter,
	})
	if err != nil {
		return fmt.Errorf("creating durable consumer: %w", err)
	}

	w.ready.Store(true)
	logging.Info().
		Str("stream", w.cfg.StreamName).
		Int("batch_size", w.cfg.BatchSize).
		Dur("flush_interval", w.cfg.FlushInterval).
		Msg("log-ingestor consuming security telemetry")

	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := w.Flush(ctx); err != nil {
					logging.Warn().Err(err).Msg("periodic ClickHouse flush failed")
				}
			}
		}
	}()

	for ctx.Err() == nil {
		msgs, fetchErr := cons.Fetch(w.cfg.BatchSize, jetstream.FetchMaxWait(w.cfg.FlushInterval))
		if fetchErr != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		var ackList []jetstream.Msg
		for msg := range msgs.Messages() {
			if err := w.EnrichAndAppend(ctx, msg.Data()); err != nil {
				logging.Warn().Err(err).Msg("dropping malformed telemetry event")
				_ = msg.Term()
				continue
			}
			ackList = append(ackList, msg)
		}
		if len(ackList) > 0 {
			if err := w.Flush(ctx); err != nil {
				logging.Warn().Err(err).Int("count", len(ackList)).Msg("batch flush failed, nakking messages")
				for _, m := range ackList {
					_ = m.Nak()
				}
				continue
			}
			for _, m := range ackList {
				_ = m.Ack()
			}
		}
	}

	// Final graceful drain flush.
	flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = w.Flush(flushCtx)
	return nil
}
