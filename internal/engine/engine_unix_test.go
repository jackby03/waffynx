//go:build !windows

package engine

import (
	"testing"
)

// These cover the lifecycle guards in engine_unix.go, which are the parts that
// can be exercised without a real nginx binary. On Linux they are compiled (and
// therefore counted by the coverage gate), which is why the Linux figure for this
// package runs a few points below the Windows one.

func TestEngineReloadRequiresRunningEngine(t *testing.T) {
	e := New(testConfig())

	if err := e.Reload(); err == nil {
		t.Fatal("expected Reload to fail when the engine is not running")
	}
}

// TestEngineStopIsIdempotent guards the early return: calling Stop on a stopped
// engine must be a no-op, not a panic on a nil process.
func TestEngineStopIsIdempotent(t *testing.T) {
	e := New(testConfig())

	if err := e.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := e.Stop(); err != nil {
		t.Fatalf("second Stop must be a no-op, got %v", err)
	}
	if e.IsRunning() {
		t.Error("engine must not report itself as running after Stop")
	}
}

// TestEngineStopWithoutSidecarIsSafe covers a partially initialised engine: if
// Start failed before the sidecar was created, Stop must still succeed.
func TestEngineStopWithoutSidecarIsSafe(t *testing.T) {
	e := New(testConfig())
	e.running = true // simulate a start that got far enough to flip the flag
	e.sidecar = nil

	if err := e.Stop(); err != nil {
		t.Fatalf("Stop with no sidecar: %v", err)
	}
	if e.IsRunning() {
		t.Error("expected running to be cleared")
	}
}
