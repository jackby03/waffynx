package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

// initRepo creates a git repository with one commit, so treeSHA and diffSHA256
// can be exercised for real instead of mocked.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run("init", "-q")
	if err := writeFile(filepath.Join(dir, "file.txt"), "one\n"); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "init")
	return dir
}

func TestTreeAndDiffSHA(t *testing.T) {
	dir := initRepo(t)

	tree, err := treeSHA(dir)
	if err != nil {
		t.Fatalf("treeSHA: %v", err)
	}
	if len(tree) != 40 {
		t.Errorf("tree sha = %q, want 40 hex chars", tree)
	}

	clean, err := diffSHA256(dir)
	if err != nil {
		t.Fatalf("diffSHA256: %v", err)
	}

	// A dirty tree must hash differently: that is what detects "the report
	// describes code that was not what ran".
	if err := writeFile(filepath.Join(dir, "file.txt"), "two\n"); err != nil {
		t.Fatal(err)
	}
	dirty, err := diffSHA256(dir)
	if err != nil {
		t.Fatalf("diffSHA256: %v", err)
	}
	if dirty == clean {
		t.Error("a modified working tree must produce a different diff hash")
	}
}

func TestReportAndVerifyRoundTrip(t *testing.T) {
	dir := initRepo(t)
	report := filepath.Join(dir, ".artifacts", "report.json")

	if err := runReport([]string{"-root", dir, "-out", report, "-gate", "tests=pass", "-gate", "fuzz=pass"}, os.Stdout); err != nil {
		t.Fatalf("report: %v", err)
	}
	if err := runVerify([]string{"-root", dir, "-report", report, "-expect", "tests,fuzz"}, os.Stdout); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyFailsOnMissingGate(t *testing.T) {
	dir := initRepo(t)
	report := filepath.Join(dir, ".artifacts", "report.json")
	if err := runReport([]string{"-root", dir, "-out", report, "-gate", "tests=pass"}, os.Stdout); err != nil {
		t.Fatalf("report: %v", err)
	}

	err := runVerify([]string{"-root", dir, "-report", report, "-expect", "tests,bench"}, os.Stdout)
	if err == nil || !strings.Contains(err.Error(), "gate missing from the report: bench") {
		t.Fatalf("a gate that never reported must fail, got %v", err)
	}
}

func TestVerifyFailsOnAbsentReport(t *testing.T) {
	dir := initRepo(t)
	err := runVerify([]string{"-root", dir, "-report", filepath.Join(dir, "nope.json"), "-expect", "tests"}, os.Stdout)
	if err == nil || !strings.Contains(err.Error(), "did not run") {
		t.Fatalf("a missing report must be a failure, not a skip, got %v", err)
	}
}

func TestVerifyFailsWhenTreeChangedAfterReport(t *testing.T) {
	dir := initRepo(t)
	report := filepath.Join(dir, ".artifacts", "report.json")
	if err := runReport([]string{"-root", dir, "-out", report, "-gate", "tests=pass"}, os.Stdout); err != nil {
		t.Fatalf("report: %v", err)
	}

	// New commit after the report: the verified tree is no longer the checked-out one.
	if err := writeFile(filepath.Join(dir, "file.txt"), "changed\n"); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "commit", "-qam", "change")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}

	err := runVerify([]string{"-root", dir, "-report", report, "-expect", "tests"}, os.Stdout)
	if err == nil {
		t.Fatal("verify must fail when the checkout moved after the report")
	}
	if !strings.Contains(err.Error(), "the gates ran against different code") &&
		!strings.Contains(err.Error(), "working tree changed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyRequiresExpectation(t *testing.T) {
	dir := initRepo(t)
	report := filepath.Join(dir, "r.json")
	if err := runReport([]string{"-root", dir, "-out", report, "-gate", "tests=pass"}, os.Stdout); err != nil {
		t.Fatal(err)
	}
	// No -expect and no rules file: nothing would be checked, so refuse.
	if err := runVerify([]string{"-root", dir, "-report", report, "-rules", filepath.Join(dir, "missing.json")}, os.Stdout); err == nil {
		t.Fatal("verify without expectations must fail")
	}
}

func TestReportRequiresGates(t *testing.T) {
	dir := initRepo(t)
	err := runReport([]string{"-root", dir, "-out", filepath.Join(dir, "r.json")}, os.Stdout)
	if err == nil || !strings.Contains(err.Error(), "at least one -gate") {
		t.Fatalf("a report with no gates must be rejected, got %v", err)
	}
}
