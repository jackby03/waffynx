package sites

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type fakeValidator struct {
	err   error
	calls int
	// sawDir records what the validator was pointed at, so a test can assert the
	// fragments were already on disk when validation ran.
	sawDir   string
	sawFiles map[string]string
}

func (v *fakeValidator) ValidateConfig(_ context.Context, dir string) error {
	v.calls++
	v.sawDir = dir
	files, err := readFragments(dir)
	if err != nil {
		return err
	}
	v.sawFiles = files
	return v.err
}

type fakeReloader struct {
	err   error
	calls int
}

func (r *fakeReloader) Reload(context.Context) error {
	r.calls++
	return r.err
}

func newTestApplier(t *testing.T) (*Applier, *fakeValidator, *fakeReloader, string) {
	t.Helper()
	dir := t.TempDir()
	v := &fakeValidator{}
	r := &fakeReloader{}
	return &Applier{Dir: dir, Validator: v, Reloader: r}, v, r, dir
}

func TestApplyWritesValidatesAndReloads(t *testing.T) {
	a, v, r, dir := newTestApplier(t)

	fragments := map[string]string{
		"example.com.conf":     "server { server_name example.com; }\n",
		"api.example.com.conf": "server { server_name api.example.com; }\n",
	}

	res, err := a.Apply(context.Background(), fragments)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Restored {
		t.Error("a successful apply must not report a restore")
	}
	if got, want := strings.Join(res.Written, ","), "api.example.com.conf,example.com.conf"; got != want {
		t.Errorf("Written = %q, want %q", got, want)
	}
	if len(res.Removed) != 0 {
		t.Errorf("expected nothing removed, got %v", res.Removed)
	}

	// Files must be on disk before validation runs: `nginx -t` reads the real
	// include directory.
	if v.calls != 1 {
		t.Errorf("expected the validator to run once, got %d", v.calls)
	}
	if v.sawDir != dir {
		t.Errorf("validator saw dir %q, want %q", v.sawDir, dir)
	}
	if len(v.sawFiles) != 2 {
		t.Errorf("validator saw %d fragments, want 2", len(v.sawFiles))
	}
	if r.calls != 1 {
		t.Errorf("expected one reload, got %d", r.calls)
	}

	// Fragments are written 0600 (SPEC-003 constraint). Windows synthesises 0666
	// for every regular file, so this assertion only means something on POSIX.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, "example.com.conf"))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("expected 0600 on fragments, got %o", mode)
		}
	}
}

// TestApplyValidationFailureRollsBack is the core safety property: a config nginx
// rejects must never become live, and the previous one must survive byte for byte.
func TestApplyValidationFailureRollsBack(t *testing.T) {
	a, _, r, dir := newTestApplier(t)

	previous := map[string]string{
		"example.com.conf":     "server { server_name example.com; }\n",
		"old.example.com.conf": "server { server_name old.example.com; }\n",
	}
	if _, err := a.Apply(context.Background(), previous); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	reloadsBefore := r.calls

	a.Validator.(*fakeValidator).err = errors.New(`nginx: [emerg] unknown directive "waffynx"`)

	desired := map[string]string{
		"example.com.conf":        "server { server_name example.com; }\n",
		"broken.example.com.conf": "server { BAD SYNTAX",
	}

	res, err := a.Apply(context.Background(), desired)
	if err == nil {
		t.Fatal("expected the apply to fail when nginx rejects the config")
	}
	if !strings.Contains(err.Error(), "unknown directive") {
		t.Errorf("expected nginx's message to surface, got %v", err)
	}
	if !res.Restored {
		t.Error("expected the result to report a rollback")
	}
	if r.calls != reloadsBefore {
		t.Errorf("the proxy must not be reloaded with a rejected config (reloads %d -> %d)", reloadsBefore, r.calls)
	}

	// The previous files must be back, byte for byte, and the new one gone.
	onDisk, readErr := readFragments(dir)
	if readErr != nil {
		t.Fatalf("readFragments: %v", readErr)
	}
	if len(onDisk) != len(previous) {
		t.Fatalf("expected %d fragments after rollback, got %d: %v", len(previous), len(onDisk), onDisk)
	}
	for name, want := range previous {
		if onDisk[name] != want {
			t.Errorf("%s was not restored:\n got %q\nwant %q", name, onDisk[name], want)
		}
	}
	if _, exists := onDisk["broken.example.com.conf"]; exists {
		t.Error("the rejected fragment must not survive the rollback")
	}
}

// TestApplyReloadFailureRollsBack covers the nastier case: nginx accepted the
// config but refused to reload. The files are restored and a second reload is
// attempted so the running proxy goes back to the previous state.
func TestApplyReloadFailureRollsBack(t *testing.T) {
	a, _, r, dir := newTestApplier(t)

	previous := map[string]string{"example.com.conf": "old\n"}
	if _, err := a.Apply(context.Background(), previous); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	r.err = errors.New("reload failed: nginx not running")
	res, err := a.Apply(context.Background(), map[string]string{"example.com.conf": "new\n"})
	if err == nil {
		t.Fatal("expected the apply to fail when the reload fails")
	}
	if !res.Restored {
		t.Error("expected a rollback after a failed reload")
	}
	if r.calls != 3 {
		t.Errorf("expected 3 reload attempts (seed, failed apply, restore), got %d", r.calls)
	}

	onDisk, _ := readFragments(dir)
	if onDisk["example.com.conf"] != "old\n" {
		t.Errorf("expected the previous fragment to be restored, got %q", onDisk["example.com.conf"])
	}
}

func TestApplyRemovesStaleFragments(t *testing.T) {
	a, _, _, dir := newTestApplier(t)

	if _, err := a.Apply(context.Background(), map[string]string{
		"a.example.com.conf": "a\n",
		"b.example.com.conf": "b\n",
	}); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	res, err := a.Apply(context.Background(), map[string]string{"a.example.com.conf": "a\n"})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := strings.Join(res.Removed, ","); got != "b.example.com.conf" {
		t.Errorf("Removed = %q, want b.example.com.conf", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.example.com.conf")); !os.IsNotExist(err) {
		t.Error("the stale fragment should have been deleted")
	}
}

// TestApplySkipsUnchangedFiles keeps the reload meaningful: rewriting identical
// content would churn the directory on every apply.
func TestApplySkipsUnchangedFiles(t *testing.T) {
	a, _, _, dir := newTestApplier(t)

	fragments := map[string]string{"a.example.com.conf": "a\n"}
	if _, err := a.Apply(context.Background(), fragments); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	before, err := os.Stat(filepath.Join(dir, "a.example.com.conf"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	res, err := a.Apply(context.Background(), fragments)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if len(res.Written) != 0 || len(res.Removed) != 0 {
		t.Errorf("expected a no-op apply, got written=%v removed=%v", res.Written, res.Removed)
	}
	after, err := os.Stat(filepath.Join(dir, "a.example.com.conf"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("an unchanged fragment was rewritten")
	}
}

func TestApplyRejectsEscapingFragmentNames(t *testing.T) {
	a, _, _, _ := newTestApplier(t)

	for _, name := range []string{"../evil.conf", `sub\dir.conf`, "noext", "", "..", "."} {
		if _, err := a.Apply(context.Background(), map[string]string{name: "x"}); err == nil {
			t.Errorf("fragment name %q must be rejected", name)
		}
	}
}

func TestApplyRequiresWiring(t *testing.T) {
	ctx := context.Background()
	if _, err := (&Applier{}).Apply(ctx, nil); err == nil {
		t.Error("expected an error with no directory")
	}
	if _, err := (&Applier{Dir: t.TempDir()}).Apply(ctx, nil); err == nil {
		t.Error("expected an error with no validator")
	}
	v := &fakeValidator{}
	if _, err := (&Applier{Dir: t.TempDir(), Validator: v}).Apply(ctx, nil); err == nil {
		t.Error("expected an error with no reloader")
	}
}

// TestApplyIsSerialised exercises the mutex: the fake validator checks state, so
// interleaved writes would surface under -race.
func TestApplyIsSerialised(t *testing.T) {
	a, _, _, _ := newTestApplier(t)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			name := fmt.Sprintf("site-%d.example.com.conf", n)
			if _, err := a.Apply(context.Background(), map[string]string{name: "x\n"}); err != nil {
				t.Errorf("concurrent apply: %v", err)
			}
		}(i)
	}
	wg.Wait()

	onDisk, err := readFragments(a.Dir)
	if err != nil {
		t.Fatalf("readFragments: %v", err)
	}
	// Each apply replaced the whole desired set, so exactly one fragment is live.
	if len(onDisk) != 1 {
		t.Errorf("expected the last apply to win with 1 fragment, got %d: %v", len(onDisk), onDisk)
	}
}
