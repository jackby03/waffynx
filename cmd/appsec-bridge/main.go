package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
)

// appsec-bridge is an optional standalone scorer that speaks the open-appsec
// evaluation protocol over a Unix socket, so the engine can reach a scoring
// process that is not itself. It is NOT started by the container by default.
//
// Architecture:
//
//	Go Sidecar (BridgeScorer) --unix socket--> appsec-bridge (or any engine)
//
// It is a reference implementation of that protocol: the bundled C++ engine it
// used to wrap was removed (see third_party/README.md). Set
// appsec.engine: open-appsec plus appsec.bridge_socket to point at whatever you
// run — this binary, or the real open-appsec engine as its own process.
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
		Short: "optional scorer daemon speaking the open-appsec protocol",
		Long: `Standalone scorer for the appsec.bridge_socket contract. Optional: the
engine uses its in-process scorer unless appsec.engine is set to open-appsec.`,
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
	defer func() { _ = ln.Close() }()

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

	// ReadHeaderTimeout bounds how long a client may take to send request
	// headers, mitigating Slowloris-style resource exhaustion (gosec G112).
	// WriteTimeout is deliberately unset: this connection is a Unix socket and
	// the API serves no long-lived streams.
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

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
	if err := server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logging.Warn().Err(err).Msg("closing bridge server")
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		logging.Warn().Err(err).Str("socket", socketPath).Msg("removing bridge socket")
	}
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
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logging.Warn().Err(err).Msg("writing evaluate response")
	}
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
