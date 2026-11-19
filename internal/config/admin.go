package config

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// EnvAdminPassword overrides the admin credential at boot. When it is unset and
// the configured hash is not usable, a password is generated once and reported to
// the caller, which must show it to the operator.
//
//nolint:gosec // G101: this is the name of an environment variable, not a credential.
const EnvAdminPassword = "WAFFYNX_ADMIN_PASSWORD"

// AdminHashFile is the file inside the data directory that persists the admin
// credential, so a new container with the same volume keeps the same password.
const AdminHashFile = "admin.hash"

// AdminCredential is the resolved admin user.
type AdminCredential struct {
	Username string
	// Password is set only when this run generated one. It is never written to
	// disk in clear text: the hash goes into the config and the operator gets the
	// password exactly once, from the bootstrap output.
	Password  string
	Generated bool
}

// minGeneratedPasswordLen keeps the one-time password long enough that the hash is
// the weak part, not the secret. RFC 6749 recommends 128 bits of entropy; 20
// base32 characters is 100 bits, which is deliberate: it has to be transcribed
// from a log line by a human, and 32 would be unusable.
const generatedPasswordBytes = 13 // 13 bytes -> 104 bits -> 21 base32 chars

// randReader is a variable so a test can prove the failure path is handled
// instead of assuming crypto/rand never fails.
var randReader io.Reader = rand.Reader

// resolveAdmin returns the effective admin credential for this boot.
//
// The shipped configuration carries a placeholder hash, which is not a valid
// bcrypt value, so nobody could log in to a fresh container. Rather than ship a
// default password (the worst option) or fail to start (unhelpful for a first
// run), a password is generated and reported once.
func resolveAdmin(cfg *Config, getenv func(string) string) (AdminCredential, error) {
	if pw := strings.TrimSpace(getenv(EnvAdminPassword)); pw != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			return AdminCredential{}, fmt.Errorf("hashing %s: %w", EnvAdminPassword, err)
		}
		hashInto(cfg, "admin", string(hash))
		return AdminCredential{Username: "admin", Password: pw, Generated: true}, nil
	}

	// A usable hash already configured means the operator set this up earlier:
	// keep it and stay quiet.
	if existing, ok := configuredAdmin(cfg); ok {
		return AdminCredential{Username: existing}, nil
	}

	// A hash persisted in the data directory survives a new container with the same
	// volume, which is what makes the printed password usable after a recreate.
	if persisted, ok := persistedAdminHash(getenv); ok {
		hashInto(cfg, "admin", persisted)
		return AdminCredential{Username: "admin"}, nil
	}

	password, err := generatePassword()
	if err != nil {
		return AdminCredential{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("hashing the generated password: %w", err)
	}
	// Persist before returning: if this write fails, the credential must not be
	// announced, or the operator would store a password that stops working on the
	// next boot.
	if err := writeFileAtomic(adminHashPath(getenv), []byte(string(hash))); err != nil {
		return AdminCredential{}, fmt.Errorf("persisting the admin hash: %w", err)
	}
	hashInto(cfg, "admin", string(hash))
	return AdminCredential{Username: "admin", Password: password, Generated: true}, nil
}

// adminHashPath mirrors jwtSecretPath: the data directory is the durable store for
// anything that must outlive the image.
func adminHashPath(getenv func(string) string) string {
	dataDir := envValue(getenv, EnvDataDir)
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	return filepath.Join(dataDir, AdminHashFile)
}

// persistedAdminHash returns a usable hash from the data directory, if any.
// A corrupt or missing file is not an error: the next step generates a new one.
func persistedAdminHash(getenv func(string) string) (string, bool) {
	raw, err := os.ReadFile(adminHashPath(getenv))
	if err != nil {
		return "", false
	}
	hash := strings.TrimSpace(string(raw))
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return "", false
	}
	return hash, true
}

// configuredAdmin reports the username of the first user whose hash is a real
// bcrypt value. An unusable hash (the shipped placeholder) is treated as "no
// credential configured", which is what it is.
func configuredAdmin(cfg *Config) (string, bool) {
	for _, u := range cfg.API.Auth.Users {
		if u.Username == "" || u.PasswordHash == "" {
			continue
		}
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err == nil {
			return u.Username, true
		}
	}
	return "", false
}

// hashInto installs a single admin user, replacing whatever placeholder was there.
func hashInto(cfg *Config, username, hash string) {
	for i := range cfg.API.Auth.Users {
		if cfg.API.Auth.Users[i].Username == username {
			cfg.API.Auth.Users[i].PasswordHash = hash
			return
		}
	}
	cfg.API.Auth.Users = append(cfg.API.Auth.Users, UserConfig{Username: username, PasswordHash: hash})
}

// generatePassword returns a human-transcribable random password.
func generatePassword() (string, error) {
	buf := make([]byte, generatedPasswordBytes)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return "", fmt.Errorf("generating the admin password: %w", err)
	}
	// Base32 without padding: no 0/O, 1/I/l confusion when copied from a log.
	return strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "="), nil
}
