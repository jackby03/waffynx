package main

import (
	"flag"
	"os"
	"time"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/pki"
)

// waffynx-bootstrap materialises the WAFFYNX_* environment into the config file
// (and optionally provisions the internal Zero-Trust mTLS PKI bundle) before
// any daemon starts.
func main() {
	configPath := flag.String("config", "/opt/waffynx/config/waffynx.yaml", "config file path")
	initPKI := flag.Bool("init-pki", false, "generate internal Zero-Trust CA and service mTLS certificates if missing")
	pkiDir := flag.String("pki-dir", "/etc/waffynx/certs", "directory for generated PKI certificates")
	pkiOnly := flag.Bool("pki-only", false, "only initialize PKI certificates and exit")
	flag.Parse()

	logging.Setup(config.LoggingConfig{
		Level:  "info",
		Format: "console",
		Output: "stderr",
	}, "")

	if *initPKI || *pkiOnly {
		if err := pki.EnsureBundle(*pkiDir, pki.DefaultServices(), 365*24*time.Hour); err != nil {
			logging.Error().Err(err).Str("dir", *pkiDir).Msg("PKI bootstrap failed; refusing to start")
			os.Exit(1)
		}
		logging.Info().Str("dir", *pkiDir).Msg("Zero-Trust internal PKI bundle ready")
		if *pkiOnly {
			return
		}
	}

	result, err := config.Bootstrap(*configPath, os.Getenv)
	if err != nil {
		logging.Error().Err(err).Msg("environment bootstrap failed; refusing to start")
		os.Exit(1)
	}

	if result.Admin.Generated && result.Admin.Password != "" {
		logging.Warn().
			Str("username", result.Admin.Username).
			Str("password", result.Admin.Password).
			Msg("generated an admin password for this deployment; store it now, it will not be shown again")
	}

	if result.Secret.Generated {
		logging.Warn().
			Str("path", result.Secret.Path).
			Msg("generated a new JWT secret; keep the data directory or issued tokens will stop working")
	}

	logging.Info().
		Str("config", *configPath).
		Int("sites", len(result.Config.Sites)).
		Msg("environment bootstrap complete")
}
