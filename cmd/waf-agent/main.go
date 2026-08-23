package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/firewall"
	"github.com/jackby03/waffynx/internal/logging"
)

func main() {
	var cfgFile string

	rootCmd := &cobra.Command{
		Use:   "waf-agent",
		Short: "Waffynx Host Agent - Firewall & System Manager",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadAgent(cfgFile)
			if err != nil {
				return fmt.Errorf("loading agent config: %w", err)
			}

			return runAgent(cfg)
		},
	}

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "/opt/waffynx/config/agent.yaml", "config file path")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type agentServer struct {
	cfg     *config.AgentConfig
	mgr     *firewall.Manager
	tracker *eventTracker
}

type eventTracker struct {
	mu        sync.Mutex
	counts    map[string][]time.Time
	threshold int
	window    time.Duration
}

func newEventTracker(threshold int, windowSec int) *eventTracker {
	return &eventTracker{
		counts:    make(map[string][]time.Time),
		threshold: threshold,
		window:    time.Duration(windowSec) * time.Second,
	}
}

func (t *eventTracker) record(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-t.window)

	events := t.counts[ip]
	valid := events[:0]
	for _, ts := range events {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	valid = append(valid, now)
	t.counts[ip] = valid

	return len(valid) >= t.threshold
}

func (t *eventTracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-t.window)
	for ip, events := range t.counts {
		valid := events[:0]
		for _, ts := range events {
			if ts.After(cutoff) {
				valid = append(valid, ts)
			}
		}
		if len(valid) == 0 {
			delete(t.counts, ip)
		} else {
			t.counts[ip] = valid
		}
	}
}

func runAgent(cfg *config.AgentConfig) error {
	logging.Info().Str("version", "1.0.0").Msg("waf-agent starting")

	mgr, err := firewall.NewManager(cfg.Firewall)
	if err != nil {
		return fmt.Errorf("initializing firewall manager: %w", err)
	}

	if err := mgr.Start(); err != nil {
		return fmt.Errorf("starting firewall manager: %w", err)
	}

	tracker := newEventTracker(cfg.EventBroker.BlockThreshold, cfg.EventBroker.WindowSeconds)
	srv := &agentServer{cfg: cfg, mgr: mgr, tracker: tracker}

	if cfg.APIKey == "" || cfg.APIKey == "change-me-in-production" {
		logging.Error().Msg("agent API key is empty or set to default value, change it in production")
		return fmt.Errorf("insecure API key configuration")
	}

	if len(cfg.APIKey) < 32 {
		logging.Error().Msg("agent API key is too short, must be at least 32 characters")
		return fmt.Errorf("insecure API key configuration")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("GET /api/v1/firewall/rules", srv.authMiddleware(srv.handleListRules))
	mux.HandleFunc("POST /api/v1/firewall/block", srv.authMiddleware(srv.handleBlockIP))
	mux.HandleFunc("DELETE /api/v1/firewall/block/{ip}", srv.authMiddleware(srv.handleUnblockIP))

	server := &http.Server{
		Addr:         cfg.Listen,
		Handler:      srv.loggingMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		logging.Info().Str("listen", cfg.Listen).Msg("agent API ready")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Error().Err(err).Msg("agent API server error")
		}
	}()

	var brokerCtx context.Context
	var brokerCancel context.CancelFunc
	if cfg.EventBroker.Enabled {
		brokerCtx, brokerCancel = context.WithCancel(context.Background())
		defer brokerCancel()
		go srv.connectEventBroker(brokerCtx)

		go func() {
			ticker := time.NewTicker(time.Duration(cfg.EventBroker.WindowSeconds) * time.Second / 2)
			defer ticker.Stop()
			for {
				select {
				case <-brokerCtx.Done():
					return
				case <-ticker.C:
					tracker.cleanup()
				}
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	logging.Info().Msg("agent running, waiting for signals")
	sig := <-sigCh
	logging.Info().Str("signal", sig.String()).Msg("received signal, shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)

	return nil
}

func (s *agentServer) connectEventBroker(ctx context.Context) {
	url := strings.TrimRight(s.cfg.EventBroker.Address, "/") + "/api/v1/events"
	logging.Info().Str("url", url).Msg("connecting to event broker")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			logging.Error().Err(err).Msg("event broker request failed")
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logging.Error().Err(err).Msg("event broker connection failed, retrying")
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		s.readSSEStream(ctx, resp.Body)
		resp.Body.Close()

		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (s *agentServer) readSSEStream(ctx context.Context, body io.ReadCloser) {
	defer body.Close()
	reader := bufio.NewReader(body)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				logging.Error().Err(err).Msg("event broker stream error")
			}
			return
		}

		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		payload := strings.TrimPrefix(line, "data: ")
		var evt events.WafEvent
		if err := json.Unmarshal([]byte(payload), &evt); err != nil {
			continue
		}

		if evt.Type != events.TypeBlocked {
			continue
		}

		ip := evt.RemoteIP
		if ip == "" {
			continue
		}

		if s.tracker.record(ip) {
			logging.Warn().Str("ip", ip).Msg("attack threshold exceeded, auto-blocking")
			if err := s.mgr.BlockIP(ip); err != nil {
				logging.Error().Err(err).Str("ip", ip).Msg("auto-block failed")
			}
		}
	}
}

func (s *agentServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.APIKey == "" {
			next(w, r)
			return
		}
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.Header.Get("Authorization")
			if len(key) > 7 && key[:7] == "Bearer " {
				key = key[7:]
			}
		}
		if subtle.ConstantTimeCompare([]byte(key), []byte(s.cfg.APIKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid API key",
			})
			return
		}
		next(w, r)
	}
}

func (s *agentServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logging.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Dur("duration", time.Since(start)).
			Msg("agent api request")
	})
}

func (s *agentServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *agentServer) handleListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.mgr.Rules()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if rules == nil {
		rules = []firewall.Rule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *agentServer) handleBlockIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP       string `json:"ip"`
		Port     int    `json:"port,omitempty"`
		Protocol string `json:"protocol,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip is required"})
		return
	}
	if err := s.mgr.BlockIP(req.IP); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "blocked",
		"ip":     req.IP,
	})
}

func (s *agentServer) handleUnblockIP(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip is required"})
		return
	}
	if err := s.mgr.UnblockIP(ip); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "unblocked",
		"ip":     ip,
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
