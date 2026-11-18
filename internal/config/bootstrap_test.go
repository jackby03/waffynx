package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jackby03/waffynx/internal/sites"
)

// bootstrapFixtureWithNginx writes a config whose nginx include directory is a
// temp path, so the fragment materialisation never touches /opt during tests.
func bootstrapFixtureWithNginx(t *testing.T) (configPath, nginxConf string) {
	t.Helper()
	nginxConf = filepath.Join(t.TempDir(), "nginx", "conf")
	content := fmt.Sprintf(`# keep this comment
name: bootstrap-test
listen: ":8443"
logging:
  level: debug
custom_key: keep-me
nginx:
  config_path: %q
sites:
  - host: old.example
    upstream: 10.0.0.5:8080
api:
  auth:
    jwt_secret: change-me-in-production
    token_ttl: 123
`, nginxConf)
	return writeBootstrapConfig(t, content), nginxConf
}

func bootstrapFixtureWithoutSites(t *testing.T, nginxConf string) string {
	t.Helper()
	return fmt.Sprintf(`name: bootstrap-test
nginx:
  config_path: %q
api:
  auth:
    jwt_secret: %s
`, nginxConf, testJWTSecret)
}

func writeBootstrapConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "waffynx.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config fixture: %v", err)
	}
	return path
}

func TestBootstrapAppliesEnvSiteAndSecret(t *testing.T) {
	path, _ := bootstrapFixtureWithNginx(t)
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
	nginxConf := filepath.Join(t.TempDir(), "nginx", "conf")
	path := writeBootstrapConfig(t, fmt.Sprintf(`
# this comment must survive a restart
name: bootstrap-test
nginx:
  config_path: %q
api:
  auth:
    jwt_secret: %s
`, nginxConf, testJWTSecret))
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
	path, _ := bootstrapFixtureWithNginx(t)
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
	path, _ := bootstrapFixtureWithNginx(t)
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
	path, _ := bootstrapFixtureWithNginx(t)
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

func TestBootstrapWritesRenderedSiteFragment(t *testing.T) {
	path, nginxConf := bootstrapFixtureWithNginx(t)

	if _, err := Bootstrap(path, fakeEnv(map[string]string{
		EnvSiteHost:     "new.example",
		EnvSiteUpstream: "10.0.0.9:8443",
		EnvDataDir:      t.TempDir(),
	})); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	fragmentPath := filepath.Join(nginxConf, "sites", "new.example.conf")
	fragment, err := os.ReadFile(fragmentPath)
	if err != nil {
		t.Fatalf("reading rendered fragment: %v", err)
	}
	body := string(fragment)
	if !strings.Contains(body, "waffynx on;") {
		t.Errorf("fragment must enable the WAF, got:\n%s", body)
	}
	if !strings.Contains(body, "10.0.0.9:8443") {
		t.Errorf("fragment must point at the env upstream, got:\n%s", body)
	}
	if strings.Contains(body, "backend:80") {
		t.Errorf("fragment still points at the old hardcoded backend:\n%s", body)
	}
}

// TestBootstrapRemovesStaleFragments covers the transition from a site created
// by the environment to a config that no longer has it: the rendered fragment
// must not survive the next boot.
func TestBootstrapRemovesStaleFragments(t *testing.T) {
	path, nginxConf := bootstrapFixtureWithNginx(t)
	dataDir := t.TempDir()

	if _, err := Bootstrap(path, fakeEnv(map[string]string{
		EnvSiteHost:     "new.example",
		EnvSiteUpstream: "10.0.0.9:8443",
		EnvDataDir:      dataDir,
	})); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	stale := filepath.Join(nginxConf, "sites", "new.example.conf")
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("expected the first bootstrap to write %s: %v", stale, err)
	}

	// Simulate the operator removing the site from the persisted config; the
	// environment variables are gone too, which is what a stale-fragment boot
	// looks like.
	if err := os.WriteFile(path, []byte(bootstrapFixtureWithoutSites(t, nginxConf)), 0o600); err != nil {
		t.Fatalf("rewriting config without sites: %v", err)
	}
	if _, err := Bootstrap(path, fakeEnv(map[string]string{EnvDataDir: dataDir})); err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("the stale fragment %s must be removed, got: %v", stale, err)
	}
}

func TestWriteSiteFragmentsWithoutConfigPath(t *testing.T) {
	// No sites and no include directory: nothing to materialise, no error.
	if err := writeSiteFragments(&Config{}); err != nil {
		t.Fatalf("empty topology must be a no-op: %v", err)
	}

	// Sites but no configured path would silently write nowhere; fail closed.
	cfg := &Config{Sites: []sites.Site{{Host: "example.com", Upstream: "10.0.0.5:8080"}}}
	err := writeSiteFragments(cfg)
	if err == nil {
		t.Fatal("expected missing nginx.config_path to be an error")
	}
	if !strings.Contains(err.Error(), "nginx.config_path") {
		t.Errorf("expected the error to name nginx.config_path, got: %v", err)
	}
}

func TestRenderOptionsDefaultsAndBarePorts(t *testing.T) {
	opts := renderOptions(&Config{})
	if opts.HTTPListen != ":8080" || opts.TLSListen != ":8443" {
		t.Errorf("expected default listeners, got HTTP=%q TLS=%q", opts.HTTPListen, opts.TLSListen)
	}

	opts = renderOptions(&Config{Nginx: NginxConfig{HTTPListen: "8080", TLSListen: "8443"}})
	if opts.HTTPListen != ":8080" || opts.TLSListen != ":8443" {
		t.Errorf("expected bare ports to gain a colon, got HTTP=%q TLS=%q", opts.HTTPListen, opts.TLSListen)
	}
}

func TestWriteSiteFragmentsReportsErrors(t *testing.T) {
	t.Run("render failure", func(t *testing.T) {
		cfg := &Config{
			Nginx: NginxConfig{ConfigPath: t.TempDir()},
			Sites: []sites.Site{{Host: "bad;host", Upstream: "10.0.0.5:8080"}},
		}
		err := writeSiteFragments(cfg)
		if err == nil || !strings.Contains(err.Error(), "rendering site fragments") {
			t.Fatalf("expected a render error, got: %v", err)
		}
	})

	t.Run("directory creation failure", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "nginx")
		if err := os.WriteFile(base, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("writing parent fixture: %v", err)
		}
		cfg := &Config{
			Nginx: NginxConfig{ConfigPath: base},
			Sites: []sites.Site{{Host: "example.com", Upstream: "10.0.0.5:8080"}},
		}
		err := writeSiteFragments(cfg)
		if err == nil || !strings.Contains(err.Error(), "writing site fragments") {
			t.Fatalf("expected a fragment-write error, got: %v", err)
		}
	})
}

func TestBootstrapFailsWhenFragmentsCannotBeWritten(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "nginx")
	if err := os.WriteFile(notDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("writing nginx path fixture: %v", err)
	}
	path := writeBootstrapConfig(t, fmt.Sprintf(`name: bootstrap-test
nginx:
  config_path: %q
sites:
  - host: example.com
    upstream: 10.0.0.5:8080
api:
  auth:
    jwt_secret: change-me-in-production
`, notDir))

	_, err := Bootstrap(path, fakeEnv(map[string]string{EnvDataDir: t.TempDir()}))
	if err == nil {
		t.Fatal("expected a fragment-write failure to fail the bootstrap")
	}
	if !strings.Contains(err.Error(), "writing site fragments") {
		t.Errorf("expected the fragment error, got: %v", err)
	}
}

// TestDockerNginxConfigTemplate is the file-content check for the container
// template. A real `nginx -t` needs the compiled module and belongs to the 7.1
// container job.
func TestDockerNginxConfigTemplate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "docker", "nginx.conf"))
	if err != nil {
		t.Fatalf("reading docker nginx.conf: %v", err)
	}
	body := string(data)

	if !strings.Contains(body, "include /opt/waffynx/nginx/conf/sites/*.conf;") {
		t.Error("docker nginx.conf must include the generated site fragments")
	}
	if strings.Contains(body, "proxy_pass") {
		t.Error("docker nginx.conf must not hardcode proxy_pass; the fragments own the topology")
	}
}

func TestDockerNginxHealthServer(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "docker", "nginx.conf"))
	if err != nil {
		t.Fatalf("reading docker nginx.conf: %v", err)
	}
	body := string(data)

	const includeLine = "include /opt/waffynx/nginx/conf/sites/*.conf;"
	includeIdx := strings.Index(body, includeLine)
	if includeIdx < 0 {
		t.Fatal("docker nginx.conf must include the generated site fragments")
	}
	serverIdx := strings.Index(body, "server {")
	if serverIdx < 0 || serverIdx > includeIdx {
		t.Fatalf("the permanent health server must exist before the include (server=%d include=%d)", serverIdx, includeIdx)
	}
	health := body[serverIdx:includeIdx]

	if strings.Count(health, "server {") != 1 {
		t.Errorf("the health block must be a single server block, got:\n%s", health)
	}
	for _, want := range []string{
		"listen 8080;",
		"if ($uri != /health)",
		"return 404;",
		"location = /health",
		"waffynx off;",
		`return 200 '{"status":"ok"}';`,
	} {
		if !strings.Contains(health, want) {
			t.Errorf("health server must contain %q, got:\n%s", want, health)
		}
	}
	if strings.Contains(health, "location / {") {
		t.Error("the health server must not have a catch-all location; the guard handles non-health URIs")
	}
	if strings.Contains(health, "proxy_pass") || strings.Contains(health, "upstream") {
		t.Error("the health server must not forward traffic or define an upstream")
	}
	if strings.Contains(health, "waffynx on;") || strings.Contains(health, "waffynx_socket") {
		t.Error("the health server must not enable WAF inspection or point at the sidecar")
	}
	if healthIdx := strings.Index(body, "location = /health"); healthIdx < 0 || healthIdx > includeIdx {
		t.Error("the /health location must come before the include so the server is the default on 8080")
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
