package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

func runAgent(cfg *config.AgentConfig) error {
	logging.Info().Str("version", "1.0.0").Msg("waf-agent starting")

	mgr, err := firewall.NewManager(cfg.Firewall)
	if err != nil {
		return fmt.Errorf("initializing firewall manager: %w", err)
	}

	if err := mgr.Start(); err != nil {
		return fmt.Errorf("starting firewall manager: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	logging.Info().Msg("agent running, waiting for signals")
	sig := <-sigCh
	logging.Info().Str("signal", sig.String()).Msg("received signal, shutting down")

	return nil
}
