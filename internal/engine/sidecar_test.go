package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSidecarSocketPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "sidecar_test.sock")

	s := NewSidecar(socketPath, nil, nil, nil, nil, nil, nil, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("failed to start sidecar: %v", err)
	}
	defer s.Stop()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected socket permissions 0600, got %o", perm)
	}
}
