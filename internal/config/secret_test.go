package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testJWTSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestResolveJWTSecretEnvWinsAndWritesNothing(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")

	got, err := ResolveJWTSecret(fakeEnv(map[string]string{
		EnvJWTSecret: testJWTSecret,
		EnvDataDir:   dataDir,
	}))
	if err != nil {
		t.Fatalf("ResolveJWTSecret: %v", err)
	}
	if got.Value != testJWTSecret {
		t.Errorf("expected the environment secret, got %q", got.Value)
	}
	if got.Generated || got.Path != "" {
		t.Errorf("an environment secret must not be persisted: %+v", got)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Errorf("the data directory must not be created when the env secret wins: %v", err)
	}
}

func TestResolveJWTSecretReusesExistingFile(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, JWTSecretFile)
	// A trailing newline is what `echo > jwt.secret` produces; it must not become
	// part of the signing key.
	if err := os.WriteFile(path, []byte(testJWTSecret+"\n"), 0o600); err != nil {
		t.Fatalf("writing fixture secret: %v", err)
	}

	first, err := ResolveJWTSecret(fakeEnv(map[string]string{EnvDataDir: dataDir}))
	if err != nil {
		t.Fatalf("ResolveJWTSecret: %v", err)
	}
	second, err := ResolveJWTSecret(fakeEnv(map[string]string{EnvDataDir: dataDir}))
	if err != nil {
		t.Fatalf("ResolveJWTSecret (second call): %v", err)
	}

	if first.Value != testJWTSecret || second.Value != testJWTSecret {
		t.Errorf("expected the persisted secret, got %q then %q", first.Value, second.Value)
	}
	if first.Generated || second.Generated {
		t.Error("an existing secret must not be reported as generated")
	}
	if first.Path != path || second.Path != path {
		t.Errorf("expected path %q, got %q and %q", path, first.Path, second.Path)
	}
}

func TestResolveJWTSecretGeneratesAndPersists(t *testing.T) {
	dataDir := t.TempDir()

	got, err := ResolveJWTSecret(fakeEnv(map[string]string{EnvDataDir: dataDir}))
	if err != nil {
		t.Fatalf("ResolveJWTSecret: %v", err)
	}
	if !got.Generated {
		t.Error("expected the first call to generate a secret")
	}
	if got.Value == placeholderJWTSecret {
		t.Fatal("must never fall back to the placeholder")
	}
	raw, err := hex.DecodeString(got.Value)
	if err != nil || len(raw) != secretBytes {
		t.Errorf("expected %d hex-encoded random bytes, got %q (%v)", secretBytes, got.Value, err)
	}
	if got.Path != filepath.Join(dataDir, JWTSecretFile) {
		t.Errorf("unexpected secret path: %q", got.Path)
	}

	persisted, err := os.ReadFile(got.Path)
	if err != nil {
		t.Fatalf("reading persisted secret: %v", err)
	}
	if string(persisted) != got.Value {
		t.Errorf("persisted secret %q does not match returned %q", persisted, got.Value)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(got.Path)
		if err != nil {
			t.Fatalf("stat persisted secret: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("expected mode 0600, got %04o", perm)
		}
	}

	again, err := ResolveJWTSecret(fakeEnv(map[string]string{EnvDataDir: dataDir}))
	if err != nil {
		t.Fatalf("ResolveJWTSecret (restart): %v", err)
	}
	if again.Value != got.Value || again.Generated {
		t.Errorf("expected the generated secret to be reused, got %+v", again)
	}
}

func TestResolveJWTSecretReadErrorIsNotRegenerated(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, JWTSecretFile)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("creating secret fixture directory: %v", err)
	}

	got, err := ResolveJWTSecret(fakeEnv(map[string]string{EnvDataDir: dataDir}))
	if err == nil {
		t.Fatalf("expected an unreadable secret to be an error, got %+v", got)
	}
	if !strings.Contains(err.Error(), "reading JWT secret") {
		t.Errorf("expected a read error, got: %v", err)
	}
	info, statErr := os.Stat(path)
	if statErr != nil || !info.IsDir() {
		t.Errorf("a read error must not replace the existing path: %v", statErr)
	}
}

func TestResolveJWTSecretNeverUsesPlaceholder(t *testing.T) {
	t.Run("fresh install generates a real secret", func(t *testing.T) {
		got, err := ResolveJWTSecret(fakeEnv(map[string]string{EnvDataDir: t.TempDir()}))
		if err != nil {
			t.Fatalf("ResolveJWTSecret: %v", err)
		}
		if got.Value == placeholderJWTSecret || got.Value == "" {
			t.Errorf("expected a generated secret, got %q", got.Value)
		}
	})

	t.Run("placeholder in the file is rejected", func(t *testing.T) {
		dataDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dataDir, JWTSecretFile), []byte(placeholderJWTSecret), 0o600); err != nil {
			t.Fatalf("writing fixture secret: %v", err)
		}
		got, err := ResolveJWTSecret(fakeEnv(map[string]string{EnvDataDir: dataDir}))
		if err == nil {
			t.Fatalf("expected the placeholder file to be rejected, got %+v", got)
		}
		if !strings.Contains(err.Error(), "placeholder") {
			t.Errorf("expected a placeholder error, got: %v", err)
		}
	})

	t.Run("placeholder in the environment is rejected", func(t *testing.T) {
		got, err := ResolveJWTSecret(fakeEnv(map[string]string{EnvJWTSecret: placeholderJWTSecret}))
		if err == nil {
			t.Fatalf("expected the placeholder environment value to be rejected, got %+v", got)
		}
		if !strings.Contains(err.Error(), EnvJWTSecret) {
			t.Errorf("expected the error to name the variable, got: %v", err)
		}
	})

	t.Run("empty file is treated as missing", func(t *testing.T) {
		dataDir := t.TempDir()
		path := filepath.Join(dataDir, JWTSecretFile)
		if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
			t.Fatalf("writing empty fixture secret: %v", err)
		}
		got, err := ResolveJWTSecret(fakeEnv(map[string]string{EnvDataDir: dataDir}))
		if err != nil {
			t.Fatalf("ResolveJWTSecret: %v", err)
		}
		if !got.Generated || strings.TrimSpace(got.Value) == "" {
			t.Errorf("expected a generated secret, got %+v", got)
		}
	})
}

func TestJWTSecretPath(t *testing.T) {
	if got, want := jwtSecretPath(fakeEnv(nil)), filepath.Join(DefaultDataDir, JWTSecretFile); got != want {
		t.Errorf("expected the default path %q, got %q", want, got)
	}

	dataDir := t.TempDir()
	if got, want := jwtSecretPath(fakeEnv(map[string]string{EnvDataDir: dataDir})), filepath.Join(dataDir, JWTSecretFile); got != want {
		t.Errorf("expected path %q, got %q", want, got)
	}
}

func TestResolveJWTSecretReportsDataDirFailure(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(dataDir, []byte("file"), 0o600); err != nil {
		t.Fatalf("writing data-dir fixture: %v", err)
	}

	got, err := ResolveJWTSecret(fakeEnv(map[string]string{EnvDataDir: dataDir}))
	if err == nil {
		t.Fatalf("expected an unusable data directory to fail, got %+v", got)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	t.Run("writes, replaces and stays 0600", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := writeFileAtomic(path, []byte("first")); err != nil {
			t.Fatalf("writeFileAtomic: %v", err)
		}
		if err := writeFileAtomic(path, []byte("second")); err != nil {
			t.Fatalf("writeFileAtomic (replace): %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading written file: %v", err)
		}
		if string(data) != "second" {
			t.Errorf("expected the replacement content, got %q", data)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat written file: %v", err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("expected mode 0600, got %04o", perm)
			}
		}
	})

	t.Run("creates missing parent directories", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nested", "config.yaml")
		if err := writeFileAtomic(path, []byte("data")); err != nil {
			t.Fatalf("writeFileAtomic: %v", err)
		}
	})

	t.Run("rejects a file as parent", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "parent")
		if err := os.WriteFile(parent, []byte("file"), 0o600); err != nil {
			t.Fatalf("writing parent fixture: %v", err)
		}
		if err := writeFileAtomic(filepath.Join(parent, "child"), []byte("data")); err == nil {
			t.Fatal("expected a file parent to be rejected")
		}
	})

	t.Run("reports a failed rename", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatalf("creating target directory: %v", err)
		}
		if err := writeFileAtomic(target, []byte("data")); err == nil {
			t.Fatal("expected replacing a directory to fail")
		}
	})
}
