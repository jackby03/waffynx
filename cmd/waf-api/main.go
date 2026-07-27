package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/marketplace"
)

func main() {
	var cfgFile string

	rootCmd := &cobra.Command{
		Use:   "waf-api",
		Short: "Waffynx Management API Server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			return runAPI(cfg)
		},
	}

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "/opt/waffynx/config/waffynx.yaml", "config file path")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runAPI(cfg *config.Config) error {
	logging.Info().Str("listen", cfg.API.Listen).Msg("starting management API")

	store := marketplace.NewInMemoryStore()

	ln, err := net.Listen("tcp", cfg.API.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.API.Listen, err)
	}
	defer ln.Close()

	logging.Info().Msg("management API ready")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	_ = store

	go func() {
		<-sigCh
		logging.Info().Msg("shutting down API server")
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		conn.Close()
	}

	return nil
}
