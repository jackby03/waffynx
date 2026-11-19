package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/api"
	"github.com/jackby03/waffynx/internal/logging"

	// The plugin registry is filled by init() functions. Without this import the
	// control plane answers /api/v1/plugins with [], which reads as "no plugins
	// installed" instead of "this binary never loaded them".
	_ "github.com/jackby03/waffynx/plugins/all"
)

func main() {
	var cfgFile string
	var uiDir string

	rootCmd := &cobra.Command{
		Use:   "waf-api",
		Short: "Waffynx Control Plane API & Envoy xDS Server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := api.LoadWithEnv(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			logging.Setup(cfg.Logging, "")
			if uiDir == "" {
				uiDir = os.Getenv("WAFFYNX_UI_DIR")
			}

			server, err := api.NewServer(cfg, cfgFile, uiDir)
			if err != nil {
				return fmt.Errorf("initializing api server: %w", err)
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			cleanup, err := server.WireDistributedBackends(ctx, cfg)
			if err != nil {
				return fmt.Errorf("initializing distributed backends: %w", err)
			}
			defer cleanup()

			return server.Run(ctx)
		},
	}

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "/opt/waffynx/config/waffynx.yaml", "config file path")
	rootCmd.Flags().StringVar(&uiDir, "ui-dir", "", "path to UI assets directory (serves from disk instead of embedded bundle)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
