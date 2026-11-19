package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// placeholderHash is what the shipped config carries. It is not a bcrypt value,
// which is why a fresh deployment had no usable login at all.
var errNoRandom = errors.New("no randomness")

const placeholderHash = "$2a$10$placeholder_hash_change_me"

// TestAdminGeneratedWhenHashIsUnusable is the regression guard for "you cannot log
// in to a new container": the config shipped a placeholder, bcrypt rejected it, and
// the API answered 401 to every attempt.
func TestAdminGeneratedWhenHashIsUnusable(t *testing.T) {
	cfg := &Config{}
	cfg.API.Auth.Users = []UserConfig{{Username: "admin", PasswordHash: placeholderHash}}

	dataDir := t.TempDir()
	env := func(k string) string {
		if k == EnvDataDir {
			return dataDir
		}
		return ""
	}
	admin, err := resolveAdmin(cfg, env)
	if err != nil {
		t.Fatalf("resolveAdmin: %v", err)
	}
	if !admin.Generated || admin.Password == "" {
		t.Fatal("expected a generated password")
	}
	if len(admin.Password) < 20 {
		t.Errorf("generated password is too short: %d chars", len(admin.Password))
	}
	if cfg.API.Auth.Users[0].PasswordHash == placeholderHash {
		t.Error("the placeholder was not replaced")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.API.Auth.Users[0].PasswordHash), []byte(admin.Password)); err != nil {
		t.Errorf("the stored hash does not verify the reported password: %v", err)
	}
}

// An explicit password rotates the credential and is never confused with the
// generated one: the caller must not print a password the operator already knows.
func TestAdminExplicitPassword(t *testing.T) {
	cfg := &Config{}
	env := func(k string) string {
		if k == EnvAdminPassword {
			return "correct horse battery staple"
		}
		return ""
	}

	admin, err := resolveAdmin(cfg, env)
	if err != nil {
		t.Fatalf("resolveAdmin: %v", err)
	}
	if admin.Username != "admin" || admin.Password != "correct horse battery staple" {
		t.Fatalf("unexpected credential: %+v", admin)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.API.Auth.Users[0].PasswordHash), []byte(admin.Password)); err != nil {
		t.Errorf("stored hash does not verify the explicit password: %v", err)
	}
}

// A working hash set up earlier must survive a reboot untouched, and no password
// is generated, so the operator's credential does not silently rotate.
func TestAdminKeptWhenHashIsUsable(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("an-existing-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	cfg.API.Auth.Users = []UserConfig{{Username: "alice", PasswordHash: string(hash)}}

	admin, err := resolveAdmin(cfg, func(string) string { return "" })
	if err != nil {
		t.Fatalf("resolveAdmin: %v", err)
	}
	if admin.Generated || admin.Password != "" {
		t.Errorf("an existing credential must not be replaced: %+v", admin)
	}
	if admin.Username != "alice" {
		t.Errorf("username = %q, want alice", admin.Username)
	}
	if cfg.API.Auth.Users[0].PasswordHash != string(hash) {
		t.Error("the existing hash was modified")
	}
}

func TestAdminGeneratedPasswordIsNotReused(t *testing.T) {
	first, err := generatePassword()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generatePassword()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two generated passwords were identical")
	}
	if strings.ContainsAny(first, "=+/") {
		t.Errorf("password contains characters that are painful to transcribe: %q", first)
	}
}

// Bootstrap must persist the generated hash, or every restart would rotate the
// credential and invalidate the session the operator just created.
func TestBootstrapPersistsGeneratedAdmin(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/waffynx.yaml"
	write := `api:
  auth:
    jwt_secret: "change-me-in-production"
    users:
      - username: admin
        password_hash: "` + placeholderHash + `"
`
	if err := writeFileAtomic(path, []byte(write)); err != nil {
		t.Fatal(err)
	}

	env := map[string]string{
		"WAFFYNX_JWT_SECRET": strings.Repeat("a", 64),
		EnvDataDir:           dir + "/data",
	}
	first, err := Bootstrap(path, func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if !first.Admin.Generated || first.Admin.Password == "" {
		t.Fatal("Bootstrap did not generate a password")
	}

	// A second boot with the same file must keep the credential: no new password,
	// and the hash still verifies the one reported the first time.
	second, err := Bootstrap(path, func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if second.Admin.Generated {
		t.Error("the credential rotated on restart")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(second.Config.API.Auth.Users[0].PasswordHash), []byte(first.Admin.Password)); err != nil {
		t.Errorf("the persisted hash does not verify the first password: %v", err)
	}
}

// bcrypt rejects passwords longer than 72 bytes. The explicit path must surface
// that as an error instead of silently storing a hash nobody can use.
func TestAdminRejectsOverlongPassword(t *testing.T) {
	cfg := &Config{}
	env := func(k string) string {
		if k == EnvAdminPassword {
			return strings.Repeat("x", 100)
		}
		return ""
	}
	if _, err := resolveAdmin(cfg, env); err == nil {
		t.Fatal("expected an error for a password bcrypt cannot hash")
	}
}

// A users list with empty entries (a hand-edited file) must not be mistaken for a
// configured credential.
func TestConfiguredAdminSkipsIncompleteEntries(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	cfg.API.Auth.Users = []UserConfig{
		{},
		{Username: "bob"},
		{Username: "carol", PasswordHash: placeholderHash},
		{Username: "dave", PasswordHash: string(hash)},
	}

	username, ok := configuredAdmin(cfg)
	if !ok || username != "dave" {
		t.Fatalf("configuredAdmin = %q, %v; want dave, true", username, ok)
	}
}

// Ran out of randomness: the boot must fail loudly instead of inventing a weak
// credential. crypto/rand does not fail in practice, which is exactly why the
// path needs a seam to be tested at all.
func TestAdminFailsWhenRandomnessFails(t *testing.T) {
	original := randReader
	randReader = failingReader{}
	defer func() { randReader = original }()

	cfg := &Config{}
	cfg.API.Auth.Users = []UserConfig{{Username: "admin", PasswordHash: placeholderHash}}

	dataDir := t.TempDir()
	env := func(k string) string {
		if k == EnvDataDir {
			return dataDir
		}
		return ""
	}
	if _, err := resolveAdmin(cfg, env); err == nil {
		t.Fatal("expected an error when randomness is unavailable")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errNoRandom }

// A new container with the same data volume must keep the password the operator
// saved. Without the persisted hash the image's placeholder wins, a new password
// is generated, and the one in their notes stops working.
func TestAdminHashSurvivesNewContainer(t *testing.T) {
	dataDir := t.TempDir()
	env := map[string]string{EnvDataDir: dataDir}

	first := &Config{}
	first.API.Auth.Users = []UserConfig{{Username: "admin", PasswordHash: placeholderHash}}
	admin, err := resolveAdmin(first, func(k string) string { return env[k] })
	if err != nil || !admin.Generated {
		t.Fatalf("first boot: %v (generated=%v)", err, admin.Generated)
	}

	// Fresh image: the config carries the placeholder again, the volume does not.
	second := &Config{}
	second.API.Auth.Users = []UserConfig{{Username: "admin", PasswordHash: placeholderHash}}
	again, err := resolveAdmin(second, func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if again.Generated || again.Password != "" {
		t.Errorf("a new container generated a new password: %+v", again)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(second.API.Auth.Users[0].PasswordHash), []byte(admin.Password)); err != nil {
		t.Errorf("the persisted hash does not verify the original password: %v", err)
	}
}

// A corrupt file must not brick startup: it is ignored and a new credential is
// generated, which is the same path as a first boot.
func TestAdminIgnoresCorruptPersistedHash(t *testing.T) {
	dataDir := t.TempDir()
	if err := writeFileAtomic(adminHashPath(func(k string) string {
		if k == EnvDataDir {
			return dataDir
		}
		return ""
	}), []byte("not-a-bcrypt-hash")); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	env := func(k string) string {
		if k == EnvDataDir {
			return dataDir
		}
		return ""
	}
	admin, err := resolveAdmin(cfg, env)
	if err != nil {
		t.Fatalf("resolveAdmin: %v", err)
	}
	if !admin.Generated {
		t.Error("expected a new credential when the persisted hash is unusable")
	}
}

// If the hash cannot be persisted, the boot must fail instead of announcing a
// password that stops working as soon as the container is recreated.
func TestAdminFailsWhenHashCannotBePersisted(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The data directory is a regular file, so creating admin.hash inside it fails.
	env := func(k string) string {
		if k == EnvDataDir {
			return filepath.Join(file, "data")
		}
		return ""
	}

	cfg := &Config{}
	cfg.API.Auth.Users = []UserConfig{{Username: "admin", PasswordHash: placeholderHash}}
	if _, err := resolveAdmin(cfg, env); err == nil {
		t.Fatal("expected an error when the hash cannot be persisted")
	}
}

// With no data directory configured the hash path still resolves under the
// default, which is what a bare host install relies on.
func TestAdminHashPathDefaults(t *testing.T) {
	got := adminHashPath(func(string) string { return "" })
	if !strings.HasSuffix(got, AdminHashFile) {
		t.Errorf("path = %q, want it to end with %q", got, AdminHashFile)
	}
	if !strings.Contains(got, "waffynx") {
		t.Errorf("path = %q, want the default data dir", got)
	}
}
