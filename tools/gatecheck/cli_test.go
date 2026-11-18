package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDispatch(t *testing.T) {
	var out, errOut bytes.Buffer

	if err := run(nil, &out, &errOut); err == nil {
		t.Error("no command must fail")
	}
	if err := run([]string{"bogus"}, &out, &errOut); err == nil ||
		!strings.Contains(err.Error(), "unknown command") {
		t.Errorf("unknown command must fail, got %v", err)
	}

	out.Reset()
	if err := run([]string{"help"}, &out, &errOut); err != nil {
		t.Errorf("help must succeed: %v", err)
	}
	if !strings.Contains(out.String(), "gatecheck <command>") {
		t.Errorf("help must print usage, got %q", out.String())
	}
}

func TestParseFlagsRejectsStrayArgs(t *testing.T) {
	var errOut bytes.Buffer
	err := runTests([]string{"-json", "x", "stray"}, &errOut)
	if err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("stray arguments must be rejected, got %v", err)
	}
}

// End-to-end through the CLI entry points, with real files, so the flag wiring
// is exercised rather than only the parsers.
func TestCLIEndToEnd(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "gates.json")
	if err := writeFile(rulesPath, `{
		"gates": ["tests","bench","fuzz"],
		"tests": {"min_passing": 1},
		"bench": {"required": ["BenchmarkA"], "max_allocs_per_op": {"BenchmarkA": 2}},
		"fuzz": {"min_seeds": {"FuzzThing": 1}}
	}`); err != nil {
		t.Fatal(err)
	}

	testJSON := filepath.Join(dir, "run.json")
	if err := writeFile(testJSON, `{"Action":"pass","Package":"p","Test":"TestA"}`); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runTests([]string{"-json", testJSON, "-rules", rulesPath}, &out); err != nil {
		t.Fatalf("tests: %v", err)
	}
	if !strings.Contains(out.String(), "1 passed") {
		t.Errorf("unexpected output: %q", out.String())
	}

	benchOut := filepath.Join(dir, "bench.txt")
	if err := writeFile(benchOut, "BenchmarkA-6  200  10 ns/op  48 B/op  1 allocs/op\n"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runBench([]string{"-out", benchOut, "-rules", rulesPath}, &out); err != nil {
		t.Fatalf("bench: %v", err)
	}

	// Fuzz target with one in-code seed.
	fuzzRoot := filepath.Join(dir, "tree")
	if err := writeFile(filepath.Join(fuzzRoot, "x_test.go"),
		"package x\nimport \"testing\"\nfunc FuzzThing(f *testing.F) { f.Add(\"s\") }\n"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runFuzz([]string{"-root", fuzzRoot, "-rules", rulesPath}, &out); err != nil {
		t.Fatalf("fuzz: %v", err)
	}
}

func TestCLIMissingRequiredFlags(t *testing.T) {
	var out bytes.Buffer
	if err := runTests([]string{}, &out); err == nil {
		t.Error("tests without -json must fail")
	}
	if err := runBench([]string{}, &out); err == nil {
		t.Error("bench without -out must fail")
	}
	if err := runVerify([]string{}, &out); err == nil {
		t.Error("verify without -report must fail")
	}
}

// Fuzz with no declared targets would prove nothing, so it must refuse.
func TestCLIFuzzWithoutTargets(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "gates.json")
	if err := writeFile(rulesPath, `{"gates":["fuzz"],"tests":{"min_passing":1}}`); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runFuzz([]string{"-root", dir, "-rules", rulesPath}, &out)
	if err == nil || !strings.Contains(err.Error(), "no targets declared") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

// Verify can take its expectations from the rules file instead of -expect.
func TestVerifyUsesRulesWhenExpectEmpty(t *testing.T) {
	dir := initRepo(t)
	rulesPath := filepath.Join(dir, "gates.json")
	if err := writeFile(rulesPath, `{"gates":["tests"],"tests":{"min_passing":1}}`); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(dir, ".artifacts", "r.json")
	if err := runReport([]string{"-root", dir, "-out", report, "-gate", "tests=pass"}, os.Stdout); err != nil {
		t.Fatal(err)
	}
	if err := runVerify([]string{"-root", dir, "-report", report, "-rules", rulesPath}, os.Stdout); err != nil {
		t.Fatalf("verify with rules: %v", err)
	}
}

func TestRulesValidateBounds(t *testing.T) {
	base := func() *Rules {
		r := &Rules{Gates: []string{"tests"}}
		r.Tests.MinPassing = 1
		return r
	}

	r := base()
	r.Bench.MaxAllocsPerOp = map[string]int{"B": -1}
	if err := r.Validate(); err == nil {
		t.Error("a negative alloc ceiling must be rejected")
	}

	r = base()
	r.Fuzz.MinSeeds = map[string]int{"F": 0}
	if err := r.Validate(); err == nil {
		t.Error("a zero seed floor must be rejected")
	}

	r = base()
	r.Tests.Required = []RequiredTest{{GOOS: "linux"}}
	if err := r.Validate(); err == nil {
		t.Error("a required entry without a test name must be rejected")
	}
}

func TestLoadRulesDefaultPath(t *testing.T) {
	if _, err := LoadRules(""); err == nil {
		t.Error("loading the default path outside the repo root must fail loudly")
	}
}

func TestStripGOMAXPROCS(t *testing.T) {
	cases := map[string]string{
		"BenchmarkA-6":   "BenchmarkA",
		"BenchmarkA":     "BenchmarkA",
		"BenchmarkA-big": "BenchmarkA-big",
	}
	for in, want := range cases {
		if got := stripGOMAXPROCS(in); got != want {
			t.Errorf("stripGOMAXPROCS(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShortSHA(t *testing.T) {
	if got := short("0123456789abcdef0123"); got != "0123456789ab" {
		t.Errorf("short long = %q", got)
	}
	if got := short("abc"); got != "abc" {
		t.Errorf("short short = %q", got)
	}
}
