package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const bootstrapFixture = `# keep this comment
name: bootstrap-test
listen: ":8443"
logging:
  level: debug
custom_key: keep-me
sites:
  - host: old.example
    upstream: 10.0.0.5:8080
api:
  auth:
    jwt_secret: change-me-in-production
    token_ttl: 123
`

func writeBootstrapConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "waffynx.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config fixture: %v", err)
	}
	return path
}

func TestBootstrapAppliesEnvSiteAndSecret(t *testing.T) {
	path := writeBootstrapConfig(t, bootstrapFixture)
	dataDir := filepath.Join(t.TempDir(), "data")

	result, err := Bootstrap(path, fakeEnv(map[string]string{
		EnvSiteHost:     "new.example",
		EnvSiteUpstream: "10.0.0.9:8443",
		EnvListen:       ":9443",
		EnvDataDir:      dataDir,
	}))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if len(result.Config.Sites) != 2 {
		t.Fatalf("expected the existing site and the new one, got %+v", result.Config.Sites)
	}
	if result.Config.Sites[0].Host != "old.example" {
		t.Errorf("the existing site must not be dropped: %+v", result.Config.Sites)
	}
	if result.Config.Sites[1].Host != "new.example" || result.Config.Sites[1].Upstream != "10.0.0.9:8443" {
		t.Errorf("the environment site was not appended: %+v", result.Config.Sites[1])
	}
	if result.Config.Listen != ":9443" {
		t.Errorf("expected listen :9443, got %q", result.Config.Listen)
	}
	if !result.Secret.Generated {
		t.Error("expected a generated JWT secret on the first boot")
	}
	if result.Config.API.Auth.JWTSecret != result.Secret.Value {
		t.Error("the effective config must carry the resolved secret")
	}
	if result.Config.API.Auth.JWTSecret == placeholderJWTSecret {
		t.Fatal("the placeholder secret must never survive")
	}

	persisted, err := os.ReadFile(result.Secret.Path)
	if err != nil {
		t.Fatalf("reading persisted secret: %v", err)
	}
	if string(persisted) != result.Secret.Value {
		t.Errorf("persisted secret %q does not match %q", persisted, result.Secret.Value)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(result.Secret.Path)
		if err != nil {
			t.Fatalf("stat persisted secret: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("expected the secret to be 0600, got %04o", perm)
		}
		cfgInfo, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat bootstrapped config: %v", err)
		}
		if perm := cfgInfo.Mode().Perm(); perm != 0o600 {
			t.Errorf("expected the config to be 0600, got %04o", perm)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading bootstrapped config: %v", err)
	}
	onDisk, err := Parse(raw)
	if err != nil {
		t.Fatalf("the bootstrapped config must parse: %v", err)
	}
	if len(onDisk.Sites) != 2 || onDisk.Listen != ":9443" {
		t.Errorf("unexpected config on disk: %+v", onDisk)
	}
	if onDisk.API.Auth.JWTSecret != result.Secret.Value || onDisk.API.Auth.TokenTTL != 123 {
		t.Errorf("auth settings were not merged correctly: %+v", onDisk.API.Auth)
	}

	var document map[string]interface{}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("unmarshalling bootstrapped config: %v", err)
	}
	if document["custom_key"] != "keep-me" {
		t.Errorf("unknown keys must survive the bootstrap, got %v", document["custom_key"])
	}
}

func TestBootstrapNoOpLeavesConfigByteIdentical(t *testing.T) {
	path := writeBootstrapConfig(t, `
# this comment must survive a restart
name: bootstrap-test
api:
  auth:
    jwt_secret: `+testJWTSecret+`
`)
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, JWTSecretFile), []byte(testJWTSecret), 0o600); err != nil {
		t.Fatalf("writing persisted secret: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading config fixture: %v", err)
	}

	result, err := Bootstrap(path, fakeEnv(map[string]string{EnvDataDir: dataDir}))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if result.Secret.Generated {
		t.Error("the persisted secret must be reused")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading config after bootstrap: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("a no-op bootstrap must not rewrite the file:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestBootstrapEnvSecretWritesNoSecretFile(t *testing.T) {
	path := writeBootstrapConfig(t, bootstrapFixture)
	dataDir := filepath.Join(t.TempDir(), "data")

	result, err := Bootstrap(path, fakeEnv(map[string]string{
		EnvJWTSecret: testJWTSecret,
		EnvDataDir:   dataDir,
	}))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if result.Secret.Generated || result.Secret.Path != "" {
		t.Errorf("an environment secret must not be persisted: %+v", result.Secret)
	}
	if _, err := os.Stat(filepath.Join(dataDir, JWTSecretFile)); !os.IsNotExist(err) {
		t.Errorf("no secret file may be written when the environment supplies one: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading bootstrapped config: %v", err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("the bootstrapped config must parse: %v", err)
	}
	if cfg.API.Auth.JWTSecret != testJWTSecret {
		t.Errorf("the environment secret must reach the daemons through the config, got %q", cfg.API.Auth.JWTSecret)
	}
}

func TestBootstrapInvalidEnvLeavesConfigUntouched(t *testing.T) {
	path := writeBootstrapConfig(t, bootstrapFixture)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading config fixture: %v", err)
	}

	_, err = Bootstrap(path, fakeEnv(map[string]string{EnvSiteHost: "new.example"}))
	if err == nil {
		t.Fatal("expected a half-configured site to be rejected")
	}
	if !strings.Contains(err.Error(), EnvSiteUpstream) {
		t.Errorf("expected the error to name the missing variable, got: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading config after failed bootstrap: %v", err)
	}
	if string(after) != string(before) {
		t.Error("a failed bootstrap must not touch the config file")
	}
}

func TestBootstrapSecretErrorLeavesConfigUntouched(t *testing.T) {
	path := writeBootstrapConfig(t, bootstrapFixture)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading config fixture: %v", err)
	}
	dataDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataDir, JWTSecretFile), 0o700); err != nil {
		t.Fatalf("creating unreadable secret fixture: %v", err)
	}

	_, err = Bootstrap(path, fakeEnv(map[string]string{EnvDataDir: dataDir}))
	if err == nil {
		t.Fatal("expected an unreadable secret to fail the bootstrap")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading config after failed bootstrap: %v", err)
	}
	if string(after) != string(before) {
		t.Error("a failed secret read must not touch the config file")
	}
}

func TestBootstrapConfigErrors(t *testing.T) {
	if _, err := Bootstrap(filepath.Join(t.TempDir(), "missing.yaml"), fakeEnv(nil)); err == nil {
		t.Error("expected a missing config file to fail")
	}

	invalid := writeBootstrapConfig(t, "name: [invalid yaml")
	if _, err := Bootstrap(invalid, fakeEnv(nil)); err == nil {
		t.Error("expected an invalid config file to fail")
	}
}

func TestMergeBootstrapConfigRejectsNonMappings(t *testing.T) {
	cfg := &Config{}
	cfg.API.Auth.JWTSecret = testJWTSecret

	if _, err := mergeBootstrapConfig([]byte("api: ["), cfg, false, false); err == nil {
		t.Error("expected malformed YAML to be rejected")
	}

	if _, err := mergeBootstrapConfig([]byte("api: 5\n"), cfg, false, false); err == nil {
		t.Error("expected a scalar api key to be rejected, not replaced")
	}

	if _, err := mergeBootstrapConfig([]byte("api:\n  auth: 5\n"), cfg, false, false); err == nil {
		t.Error("expected a scalar auth key to be rejected, not replaced")
	}

	// An empty document still gets the keys the overlay owns, so a config that is
	// only a comment can be bootstrapped instead of being rejected.
	merged, err := mergeBootstrapConfig(nil, &Config{Listen: ":8443"}, true, true)
	if err != nil {
		t.Fatalf("mergeBootstrapConfig on an empty document: %v", err)
	}
	if !strings.Contains(string(merged), ":8443") {
		t.Errorf("expected the listen address in the merged document, got:\n%s", merged)
	}
}
