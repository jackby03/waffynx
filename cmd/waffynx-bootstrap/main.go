package main

import (
	"flag"
	"os"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
)

// waffynx-bootstrap materialises the WAFFYNX_* environment into the config file
// before any daemon starts. It exists as a separate process because both waf-api
// and the engine must read the same resolved JWT secret and topology; letting each
// daemon generate its own secret would invalidate tokens on every restart.
func main() {
	configPath := flag.String("config", "/opt/waffynx/config/waffynx.yaml", "config file path")
	flag.Parse()

	logging.Setup(config.LoggingConfig{
		Level:  "info",
		Format: "console",
		Output: "stderr",
	}, "")

	result, err := config.Bootstrap(*configPath, os.Getenv)
	if err != nil {
		logging.Error().Err(err).Msg("environment bootstrap failed; refusing to start")
		os.Exit(1)
	}

	// Show the credential once. It is not written in clear text anywhere: the
	// config gets the bcrypt hash, so this output is the only place the operator
	// can read it. Setting WAFFYNX_ADMIN_PASSWORD again rotates it.
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
