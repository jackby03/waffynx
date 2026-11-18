//go:build !windows

package engine

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackby03/waffynx/internal/plugin"
	wrules "github.com/jackby03/waffynx/internal/rules"
)

func newGroupTestSidecar(t *testing.T) (*Sidecar, string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "waffynx.sock")
	return NewSidecar(sock, nil, plugin.NewChain(), nil, nil, nil, wrules.NewEngine(), nil), sock
}

// currentGroupName returns the primary group of the user running the tests, so the
// assertion works on any Linux runner without hardcoding "nogroup".
func currentGroupName(t *testing.T) string {
	t.Helper()
	cur, err := user.Current()
	if err != nil {
		t.Skipf("cannot determine current user: %v", err)
	}
	g, err := user.LookupGroupId(cur.Gid)
	if err != nil {
		t.Skipf("cannot resolve group id %s: %v", cur.Gid, err)
	}
	return g.Name
}

// TestSidecarSocketGroupWidensTo0660 is the regression guard for a container that
// blocked every request with 403: nginx workers drop to an unprivileged user, the
// sidecar socket was 0600 root-owned, and the workers got EACCES. With fail_open
// off that turns every legitimate request into a denial.
func TestSidecarSocketGroupWidensTo0660(t *testing.T) {
	group := currentGroupName(t)

	s, sock := newGroupTestSidecar(t)
	s.SetSocketGroup(group)

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Stop() }()

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Errorf("expected 0660 so an unprivileged proxy worker can connect, got %o", perm)
	}

	// 0666 or looser is forbidden by Constitution §2.2.
	if perm := info.Mode().Perm(); perm&0o006 != 0 {
		t.Errorf("socket must not be world-accessible, got %o", perm)
	}
}

// TestSidecarSocketGroupUnknownFailsClosed documents that a misconfigured group is
// an error, not a silent fallback to 0600: quietly keeping 0600 would reproduce the
// EACCES the setting exists to avoid.
func TestSidecarSocketGroupUnknownFailsClosed(t *testing.T) {
	s, _ := newGroupTestSidecar(t)
	s.SetSocketGroup("waffynx-no-such-group")

	if err := s.Start(); err == nil {
		t.Fatal("expected Start to fail on an unresolvable socket group")
	} else if !strings.Contains(err.Error(), "socket group") {
		t.Errorf("expected the error to name the group setting, got: %v", err)
	}
}
