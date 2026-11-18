package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
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
	if !changed {
		// Restart with no new environment input and an already persisted secret:
		// leave the operator's file alone, comments included.
		return result, nil
	}

	merged, err := mergeBootstrapConfig(raw, effective, siteOverlay, listenOverlay)
	if err != nil {
		return nil, err
	}
	parsed, err := Parse(merged)
	if err != nil {
		return nil, fmt.Errorf("validating bootstrapped configuration: %w", err)
	}
	if err := writeFileAtomic(path, merged); err != nil {
		return nil, fmt.Errorf("writing bootstrapped configuration: %w", err)
	}

	result.Config = parsed
	return result, nil
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
