package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSocketPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "appsec_test.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on socket: %v", err)
	}
	defer ln.Close()

	if err := os.Chmod(socketPath, 0600); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected socket permissions 0600, got %o", perm)
	}
}
