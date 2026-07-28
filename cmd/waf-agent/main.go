package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/config"
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
	cfg *config.AgentConfig
	mgr *firewall.Manager
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

	srv := &agentServer{cfg: cfg, mgr: mgr}

	if cfg.APIKey == "change-me-in-production" {
		logging.Warn().Msg("agent API key is set to default value, change it in production")
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
		if key != s.cfg.APIKey {
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
