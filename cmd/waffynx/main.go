package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/engine"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/version"

	// Register built-in plugins via their init() functions
	_ "github.com/jackby03/waffynx/plugins/bot-protection"
	_ "github.com/jackby03/waffynx/plugins/geo-block"
	_ "github.com/jackby03/waffynx/plugins/rate-limit"
	_ "github.com/jackby03/waffynx/plugins/request-validation"
)

func main() {
	var cfgFile string
	var logLevel string

	rootCmd := &cobra.Command{
		Use:   "waffynx",
		Short: "Waffynx - Next-Generation Web Application Firewall",
		Long: `Waffynx is a next-gen WAF that integrates nginx, open-appsec,
and a plugin marketplace into a unified management platform.`,
		Version: version.Version,
	}

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the Waffynx engine",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			logging.Setup(cfg.Logging, logLevel)

			return runEngine(cfg)
		},
	}

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Validate configuration without starting",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}
			fmt.Printf("Configuration valid: %s (v%s)\n", cfg.Name, version.Version)
			fmt.Printf("  Listen:   %s\n", cfg.Listen)
			fmt.Printf("  Sidecar:  %s\n", cfg.Sidecar.SocketPath)
			fmt.Printf("  Nginx:    %s\n", cfg.Nginx.BinaryPath)
			fmt.Printf("  Routes:   %d configured\n", len(cfg.Routes))
			fmt.Printf("  Plugins:  %d configured\n", len(cfg.Plugins))
			return nil
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Waffynx %s (commit: %s, built: %s)\n",
				version.Version, version.GitCommit, version.BuildTime)
		},
	}

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/opt/waffynx/config/waffynx.yaml", "config file path")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "log level (debug, info, warn, error)")
	rootCmd.AddCommand(startCmd, checkCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runEngine(cfg *config.Config) error {
	eng := engine.New(cfg)

	// Load built-in plugins from the registry
	registry := engine.GetPluginRegistry()
	for _, pc := range cfg.Plugins {
		if !pc.Enabled {
			continue
		}
		p, err := registry.Create(pc.Name, pc.Config)
		if err != nil {
			logging.Warn().Err(err).Str("plugin", pc.Name).Msg("failed to load plugin, skipping")
			continue
		}
		eng.AddPlugin(p)
		logging.Info().Str("plugin", p.Name()).Str("version", p.Version()).Msg("plugin loaded")
	}

	// Add default WAF rules
	eng.AddPolicy(&engine.Policy{
		Name:     "block-sql-injection",
		Phase:    engine.PhaseRequest,
		Priority: 10,
		Enabled:  true,
		Action:   engine.ActionBlock,
	})
	eng.AddPolicy(&engine.Policy{
		Name:     "block-xss",
		Phase:    engine.PhaseRequest,
		Priority: 10,
		Enabled:  true,
		Action:   engine.ActionBlock,
	})
	eng.AddPolicy(&engine.Policy{
		Name:     "rate-limit-api",
		Phase:    engine.PhaseRequest,
		Priority: 50,
		Enabled:  false,
		Action:   engine.ActionBlock,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	if err := eng.Start(ctx); err != nil {
		return fmt.Errorf("starting engine: %w", err)
	}

	logging.Info().Msg("waffynx engine running")

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			logging.Info().Msg("received SIGHUP, reloading")
			if err := eng.Reload(); err != nil {
				logging.Error().Err(err).Msg("reload failed")
			}
		case syscall.SIGINT, syscall.SIGTERM:
			logging.Info().Str("signal", sig.String()).Msg("shutting down")
			return eng.Stop()
		}
	}

	return nil
}
