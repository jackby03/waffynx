package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/jackby03/waffynx/internal/logging"
)

const (
	DefaultStreamName    = "WAFFYNX_EVENTS"
	DefaultSubjectPrefix = "waffynx.events"
	DefaultBufferSize    = 4096
)

var (
	telemetryEmitted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "waffynx_telemetry_emitted_total",
		Help: "Total security events emitted asynchronously to the observability bus.",
	}, []string{"action"})
	telemetryDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "waffynx_telemetry_dropped_total",
		Help: "Total security events dropped because the async observability buffer was full.",
	})
)

// NATSConfig holds connection and JetStream parameters for async telemetry.
type NATSConfig struct {
	Enabled       bool   `yaml:"enabled"`
	URL           string `yaml:"url"`
	Token         string `yaml:"token"`
	StreamName    string `yaml:"stream_name"`
	SubjectPrefix string `yaml:"subject_prefix"`
	BufferSize    int    `yaml:"buffer_size"`
}

// NATSEmitter publishes SecurityEvents asynchronously to NATS JetStream via a
// bounded channel. Emit() never blocks the caller (Constitution §1.3).
type NATSEmitter struct {
	nc            *nats.Conn
	js            jetstream.JetStream
	subjectPrefix string
	ch            chan SecurityEvent
	dropped       atomic.Uint64
	done          chan struct{}
	wg            sync.WaitGroup
	closeOnce     sync.Once
}

// NewNATSEmitter connects to NATS, ensures the JetStream stream exists, and
// starts the background async publisher goroutine.
func NewNATSEmitter(cfg NATSConfig) (*NATSEmitter, error) {
	if !cfg.Enabled || cfg.URL == "" {
		return nil, nil
	}
	if cfg.StreamName == "" {
		cfg.StreamName = DefaultStreamName
	}
	if cfg.SubjectPrefix == "" {
		cfg.SubjectPrefix = DefaultSubjectPrefix
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultBufferSize
	}

	opts := []nats.Option{
		nats.Name("waffynx-waf-engine"),
		nats.ReconnectWait(time.Second),
		nats.MaxReconnects(-1),
		nats.Timeout(3 * time.Second),
	}
	if cfg.Token != "" {
		opts = append(opts, nats.Token(cfg.Token))
	}

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS %s: %w", cfg.URL, err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("initializing JetStream: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      cfg.StreamName,
		Subjects:  []string{cfg.SubjectPrefix + ".>"},
		Retention: jetstream.LimitsPolicy,
		MaxAge:    24 * time.Hour,
		MaxBytes:  512 * 1024 * 1024,
		Storage:   jetstream.FileStorage,
		Discard:   jetstream.DiscardOld,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("ensuring JetStream stream %s: %w", cfg.StreamName, err)
	}

	e := &NATSEmitter{
		nc:            nc,
		js:            js,
		subjectPrefix: cfg.SubjectPrefix,
		ch:            make(chan SecurityEvent, cfg.BufferSize),
		done:          make(chan struct{}),
	}
	e.wg.Add(1)
	go e.run()
	return e, nil
}

// Emit enqueues ev for asynchronous publication without blocking.
// PII redaction is enforced before the event enters the channel.
func (e *NATSEmitter) Emit(ev SecurityEvent) {
	if e == nil {
		return
	}
	redacted := RedactEvent(ev)
	select {
	case e.ch <- redacted:
		telemetryEmitted.WithLabelValues(string(redacted.Action)).Inc()
	default:
		e.dropped.Add(1)
		telemetryDropped.Inc()
	}
}

func (e *NATSEmitter) Dropped() uint64 {
	if e == nil {
		return 0
	}
	return e.dropped.Load()
}

func (e *NATSEmitter) run() {
	defer e.wg.Done()
	for {
		select {
		case <-e.done:
			e.drain()
			return
		case ev := <-e.ch:
			e.publishOne(ev)
		}
	}
}

func (e *NATSEmitter) drain() {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case ev := <-e.ch:
			e.publishOne(ev)
		default:
			return
		}
	}
}

func (e *NATSEmitter) publishOne(ev SecurityEvent) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	subject := e.subjectPrefix + "." + string(ev.Action)
	if _, err := e.js.PublishAsync(subject, data); err != nil {
		e.dropped.Add(1)
		telemetryDropped.Inc()
		logging.Debug().Err(err).Str("subject", subject).Msg("async NATS publish dropped")
	}
}

func (e *NATSEmitter) Close() error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		close(e.done)
		e.wg.Wait()
		_ = e.nc.Drain()
		e.nc.Close()
	})
	return nil
}

// MemoryEmitter is a non-blocking bounded in-memory Emitter for tests and
// local single-process operation.
type MemoryEmitter struct {
	ch      chan SecurityEvent
	dropped atomic.Uint64
}

func NewMemoryEmitter(capacity int) *MemoryEmitter {
	if capacity <= 0 {
		capacity = 64
	}
	return &MemoryEmitter{ch: make(chan SecurityEvent, capacity)}
}

func (m *MemoryEmitter) Emit(ev SecurityEvent) {
	redacted := RedactEvent(ev)
	select {
	case m.ch <- redacted:
	default:
		m.dropped.Add(1)
	}
}

func (m *MemoryEmitter) Dropped() uint64 { return m.dropped.Load() }

func (m *MemoryEmitter) Events() []SecurityEvent {
	out := make([]SecurityEvent, 0, len(m.ch))
	for {
		select {
		case ev := <-m.ch:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func (m *MemoryEmitter) Close() error { return nil }
