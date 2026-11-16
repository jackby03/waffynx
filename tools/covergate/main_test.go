package main

import (
	"os"
	"path/filepath"
	"testing"
)

const module = "github.com/jackby03/waffynx/"

func writeProfile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "coverage.out")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing profile: %v", err)
	}
	return path
}

// TestParseProfileDeduplicatesBlocks covers the trap that produced absurd
// numbers on the first attempt: with -coverpkg, every test binary re-emits the
// same block, so summing the profile inflates the denominator. A block counts as
// covered if any test binary covered it.
func TestParseProfileDeduplicatesBlocks(t *testing.T) {
	profile := writeProfile(t, "mode: set\n"+
		// Same block emitted by two test binaries, covered by one of them.
		module+"internal/engine/sidecar.go:10.1,12.2 4 1\n"+
		module+"internal/engine/sidecar.go:10.1,12.2 4 0\n"+
		// A block nobody covers.
		module+"internal/engine/engine.go:20.1,22.2 6 0\n"+
		// Unrelated package.
		module+"internal/api/server.go:5.1,6.2 2 1\n")

	perPkg, err := parseProfile(profile)
	if err != nil {
		t.Fatalf("parseProfile: %v", err)
	}

	engine, ok := perPkg["internal/engine"]
	if !ok {
		t.Fatal("expected internal/engine in the profile")
	}
	if engine.stmts != 10 {
		t.Errorf("denominator must not double-count the duplicated block: got %d statements, want 10", engine.stmts)
	}
	if engine.covered != 4 {
		t.Errorf("got %d covered statements, want 4", engine.covered)
	}
	if got := engine.percent(); got < 39.9 || got > 40.1 {
		t.Errorf("expected 40%%, got %.2f%%", got)
	}

	api := perPkg["internal/api"]
	if api.stmts != 2 || api.covered != 2 {
		t.Errorf("internal/api: got %d/%d, want 2/2", api.covered, api.stmts)
	}
}

func TestParseProfileRejectsMalformedLines(t *testing.T) {
	profile := writeProfile(t, "mode: set\nthis is not a coverage line\n")
	if _, err := parseProfile(profile); err == nil {
		t.Fatal("expected an error for a malformed line")
	}
}

func TestPackageOfStripsModulePrefix(t *testing.T) {
	cases := map[string]string{
		module + "internal/engine/sidecar.go": "internal/engine",
		module + "cmd/waffynx/main.go":        "cmd/waffynx",
		module + "main.go":                    ".",
		"other/module/file.go":                "other/module",
	}
	for file, want := range cases {
		if got := packageOf(file); got != want {
			t.Errorf("packageOf(%q) = %q, want %q", file, got, want)
		}
	}
}
