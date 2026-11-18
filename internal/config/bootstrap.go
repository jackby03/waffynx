package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jackby03/waffynx/internal/sites"
)

// BootstrapResult reports the effective configuration after the environment
// overlay and the resolved signing key, for the caller to log.
type BootstrapResult struct {
	Config *Config
	Secret JWTSecret
}

// Bootstrap makes an environment-only deployment possible: it loads path, applies
// the WAFFYNX_* overlay, resolves (and persists if needed) the JWT secret, and
// writes the merged configuration back atomically with mode 0600.
//
// Nothing is written until every step has succeeded, so a bad variable or an
// unreadable secret leaves the previous configuration byte-identical. The daemons
// then start from the same file they always did; there is no second config format.
func Bootstrap(path string, getenv func(string) string) (*BootstrapResult, error) {
	getenv = envLookup(getenv)

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	loaded, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("loading config %s: %w", path, err)
	}

	effective, err := ApplyEnvOverlay(loaded, getenv)
	if err != nil {
		return nil, err
	}

	secret, err := ResolveJWTSecret(getenv)
	if err != nil {
		return nil, err
	}
	effective.API.Auth.JWTSecret = secret.Value

	siteOverlay := envValue(getenv, EnvSiteHost) != "" || envValue(getenv, EnvSiteUpstream) != ""
	listenOverlay := envValue(getenv, EnvListen) != ""
	changed := siteOverlay || listenOverlay || loaded.API.Auth.JWTSecret != secret.Value

	result := &BootstrapResult{Config: effective, Secret: secret}
	if changed {
		merged, mergeErr := mergeBootstrapConfig(raw, effective, siteOverlay, listenOverlay)
		if mergeErr != nil {
			return nil, mergeErr
		}
		parsed, parseErr := Parse(merged)
		if parseErr != nil {
			return nil, fmt.Errorf("validating bootstrapped configuration: %w", parseErr)
		}
		if writeErr := writeFileAtomic(path, merged); writeErr != nil {
			return nil, fmt.Errorf("writing bootstrapped configuration: %w", writeErr)
		}
		result.Config = parsed
	}

	// Materialise the fragments every boot, including the no-op path: nginx reads
	// them directly and there is no Applier in the entrypoint. No `nginx -t` here;
	// nginx is not up yet and the engine fails closed if its start fails.
	if err := writeSiteFragments(result.Config); err != nil {
		return nil, err
	}

	return result, nil
}

// writeSiteFragments renders the effective topology into nginx's include
// directory. It deliberately does not validate with nginx: the bootstrap runs
// before nginx starts (and the binary may not exist outside the image), so a
// rejected configuration surfaces as a failed nginx start, not a half-applied
// one.
func writeSiteFragments(cfg *Config) error {
	fragments, err := sites.Render(cfg.Sites, renderOptions(cfg))
	if err != nil {
		return fmt.Errorf("rendering site fragments: %w", err)
	}
	if cfg.Nginx.ConfigPath == "" {
		if len(fragments) == 0 {
			return nil
		}
		return errors.New("nginx.config_path is required to write site fragments")
	}

	dir := filepath.Join(cfg.Nginx.ConfigPath, "sites")
	if _, _, err := sites.SyncFragments(dir, fragments); err != nil {
		return fmt.Errorf("writing site fragments: %w", err)
	}
	return nil
}

// renderOptions mirrors the API's renderer settings so a site persisted by the
// bootstrap renders exactly like one applied through /api/v1/sites.
func renderOptions(cfg *Config) sites.RenderOptions {
	opts := sites.RenderOptions{
		SocketPath:  cfg.Sidecar.SocketPath,
		HTTPListen:  cfg.Nginx.HTTPListen,
		TLSListen:   cfg.Nginx.TLSListen,
		MaxBodySize: "64k",
		TimeoutMs:   cfg.Sidecar.TimeoutMs,
	}
	if opts.HTTPListen == "" {
		opts.HTTPListen = ":8080"
	}
	if opts.TLSListen == "" {
		opts.TLSListen = ":8443"
	}
	// The config may carry a bare port; the renderer writes a listen address.
	if !strings.Contains(opts.HTTPListen, ":") {
		opts.HTTPListen = ":" + opts.HTTPListen
	}
	if !strings.Contains(opts.TLSListen, ":") {
		opts.TLSListen = ":" + opts.TLSListen
	}
	return opts
}

// mergeBootstrapConfig rewrites only the keys the overlay owns, leaving every
// other key in the document untouched. Unknown keys survive because operators also
// edit this file by hand.
func mergeBootstrapConfig(raw []byte, cfg *Config, sitesRequested, listenRequested bool) ([]byte, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("reading current config: %w", err)
	}
	if doc == nil {
		doc = map[string]interface{}{}
	}

	if sitesRequested {
		doc["sites"] = cfg.Sites
	}
	if listenRequested {
		doc["listen"] = cfg.Listen
	}

	api, err := ensureMapping(doc, "api")
	if err != nil {
		return nil, err
	}
	auth, err := ensureMapping(api, "auth")
	if err != nil {
		return nil, err
	}
	auth["jwt_secret"] = cfg.API.Auth.JWTSecret

	merged, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encoding config: %w", err)
	}
	return merged, nil
}

// ensureMapping returns parent[key] as a mapping, creating an empty one when the
// key is absent or null. A non-mapping value is an error rather than a silent
// replacement, because that would drop whatever the operator wrote there.
func ensureMapping(parent map[string]interface{}, key string) (map[string]interface{}, error) {
	switch value := parent[key].(type) {
	case nil:
		mapping := map[string]interface{}{}
		parent[key] = mapping
		return mapping, nil
	case map[string]interface{}:
		return value, nil
	default:
		return nil, fmt.Errorf("config key %q is not a mapping", key)
	}
}
