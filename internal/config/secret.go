package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultDataDir is where generated secrets live unless WAFFYNX_DATA_DIR says
	// otherwise. It matches the path used elsewhere in the container layout.
	DefaultDataDir = "/opt/waffynx/data"
	// JWTSecretFile is the file inside the data directory that persists the key.
	JWTSecretFile = "jwt.secret"
	// placeholderJWTSecret is the value shipped in the example config. It is
	// rejected here as well as in api.NewServer: a generated secret must never be
	// replaced by the documented placeholder.
	placeholderJWTSecret = "change-me-in-production"
	// secretBytes is the amount of entropy in a generated key.
	secretBytes = 32
)

// JWTSecret is the resolved signing key and where it came from.
type JWTSecret struct {
	Value     string
	Path      string
	Generated bool
}

// ResolveJWTSecret returns the API signing key without ever silently rotating a
// key that already exists.
//
// Order: WAFFYNX_JWT_SECRET wins and writes nothing; otherwise the persisted
// $WAFFYNX_DATA_DIR/jwt.secret is reused; otherwise 32 random bytes are generated
// and written atomically with mode 0600. A read error on an existing file is
// returned, not treated as "missing": regenerating would invalidate every issued
// token without telling anyone.
func ResolveJWTSecret(getenv func(string) string) (JWTSecret, error) {
	getenv = envLookup(getenv)

	if fromEnv := getenv(EnvJWTSecret); strings.TrimSpace(fromEnv) != "" {
		if strings.TrimSpace(fromEnv) == placeholderJWTSecret {
			return JWTSecret{}, fmt.Errorf("%s is set to the placeholder value", EnvJWTSecret)
		}
		return JWTSecret{Value: fromEnv}, nil
	}

	path := jwtSecretPath(getenv)

	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		value := strings.TrimSpace(string(existing))
		if value != "" {
			if value == placeholderJWTSecret {
				return JWTSecret{}, fmt.Errorf("JWT secret %s contains the placeholder value", path)
			}
			return JWTSecret{Value: value, Path: path}, nil
		}
		// An empty file is not a secret; fall through and generate one.
	case errors.Is(err, os.ErrNotExist):
		// No persisted key yet: this is the first boot.
	default:
		return JWTSecret{}, fmt.Errorf("reading JWT secret %s: %w", path, err)
	}

	value, err := generateJWTSecret()
	if err != nil {
		return JWTSecret{}, err
	}
	if err := writeFileAtomic(path, []byte(value)); err != nil {
		return JWTSecret{}, fmt.Errorf("persisting JWT secret %s: %w", path, err)
	}
	return JWTSecret{Value: value, Path: path, Generated: true}, nil
}

// jwtSecretPath resolves the persistence location. It is separate from
// ResolveJWTSecret so the default can be asserted without touching /opt.
func jwtSecretPath(getenv func(string) string) string {
	dataDir := envValue(getenv, EnvDataDir)
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	return filepath.Join(dataDir, JWTSecretFile)
}

func generateJWTSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating JWT secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// writeFileAtomic replaces path through a temp file in the same directory, so a
// crash can never leave a truncated config or secret. os.CreateTemp creates the
// temp file with mode 0600 and rename preserves it, so the secret is never
// world-readable, not even for an instant.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".waffynx-*")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temporary file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	tmpName = ""
	return nil
}
