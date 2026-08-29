package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
)

// appsec-bridge is a standalone daemon that exposes the open-appsec
// evaluation API over a Unix socket. It runs as a separate process
// from the main waffynx sidecar.
//
// Architecture:
//
//	Go Sidecar (BridgeScorer) --unix socket--> appsec-bridge
//
// In production, replace this binary with the real open-appsec C++
// engine that implements the same HTTP/JSON protocol.
//
// Endpoints:
//
//	GET  /health    -> {"status":"ok"}
//	POST /evaluate  -> {"verdict":"block","score":0.92,...}
func main() {
	var socketPath string
	var logLevel string

	rootCmd := &cobra.Command{
		Use:   "appsec-bridge",
		Short: "open-appsec bridge daemon (Go implementation)",
		Long: `Standalone ML evaluation daemon compatible with the 
open-appsec protocol. Swap with the C++ engine for production.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(socketPath, logLevel)
		},
	}

	rootCmd.Flags().StringVarP(&socketPath, "socket", "s",
		"/var/run/open-appsec.sock", "Unix socket path")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l",
		"info", "log level (debug, info, warn, error)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(socketPath, logLevel string) error {
	logging.Setup(config.LoggingConfig{
		Level:  "info",
		Format: "console",
		Output: "stdout",
	}, logLevel)

	scorer := appsec.NewBasicScorer()
	logging.Info().Str("scorer", scorer.Name()).Msg("initialized ML scorer")

	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove old socket: %w", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	defer ln.Close()

	if err := os.Chmod(socketPath, 0600); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"appsec-bridge","scorer":"` + scorer.Name() + `"}`))
	})
	mux.HandleFunc("/evaluate", func(w http.ResponseWriter, r *http.Request) {
		handleEvaluate(w, r, scorer)
	})

	server := &http.Server{Handler: mux}

	go func() {
		logging.Info().Str("socket", socketPath).Msg("appsec-bridge listening")
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			logging.Error().Err(err).Msg("server error")
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	logging.Info().Str("signal", sig.String()).Msg("shutting down")
	server.Close()
	os.Remove(socketPath)
	return nil
}

func handleEvaluate(w http.ResponseWriter, r *http.Request, scorer appsec.Scorer) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var features appsec.Features
	if err := json.NewDecoder(r.Body).Decode(&features); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid json: %s"}`, err), http.StatusBadRequest)
		return
	}

	// If client didn't send pre-parsed query params, parse from URI
	if features.QueryParams == nil {
		features.QueryParams = parseQueryParams(features.URI)
	}
	if features.URILength == 0 {
		features.URILength = len(features.URI)
	}

	result, err := scorer.Evaluate(context.Background(), &features)
	if err != nil {
		logging.Error().Err(err).Msg("evaluation failed")
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	logging.Debug().
		Float64("score", result.Score).
		Str("verdict", string(result.Verdict)).
		Strs("anomalies", result.Anomalies).
		Msg("evaluation complete")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// parseQueryParams extracts query parameters from a URI string.
func parseQueryParams(rawURI string) map[string]string {
	params := make(map[string]string)
	idx := strings.Index(rawURI, "?")
	if idx < 0 || idx == len(rawURI)-1 {
		return params
	}
	queryStr := rawURI[idx+1:]
	for queryStr != "" {
		var pair string
		pair, queryStr, _ = strings.Cut(queryStr, "&")
		if pair == "" {
			continue
		}
		key, val, hasEq := strings.Cut(pair, "=")
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			decodedKey = key
		}
		var decodedVal string
		if hasEq {
			var err error
			decodedVal, err = url.QueryUnescape(val)
			if err != nil {
				decodedVal = val
			}
		}
		params[decodedKey] = decodedVal
	}
	return params
}
