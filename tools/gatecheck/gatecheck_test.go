package main

import (
	"strings"
	"testing"
)

func rulesWith(t *testing.T) *Rules {
	t.Helper()
	return &Rules{}
}

func TestParseTestStreamCountsAndDedupes(t *testing.T) {
	const stream = `
{"Action":"run","Package":"p","Test":"TestA"}
{"Action":"pass","Package":"p","Test":"TestA"}
{"Action":"pass","Package":"p","Test":"TestA"}
{"Action":"run","Package":"p","Test":"TestA/sub"}
{"Action":"pass","Package":"p","Test":"TestA/sub"}
{"Action":"skip","Package":"p","Test":"TestSkip"}
{"Action":"fail","Package":"p","Test":"TestBad"}
{"Action":"fail","Package":"p"}
`
	inv, err := ParseTestStream(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("ParseTestStream: %v", err)
	}
	if inv.Passed != 2 {
		t.Errorf("Passed = %d, want 2 (duplicates collapse, subtests count)", inv.Passed)
	}
	if len(inv.Skipped) != 1 || inv.Skipped[0].Test != "TestSkip" {
		t.Errorf("Skipped = %v, want [TestSkip]", inv.Skipped)
	}
	if len(inv.Failed) != 1 || inv.Failed[0] != "p.TestBad" {
		t.Errorf("Failed = %v, want [p.TestBad]", inv.Failed)
	}
	if len(inv.PackageFailures) != 1 || inv.PackageFailures[0] != "p" {
		t.Errorf("PackageFailures = %v, want [p]", inv.PackageFailures)
	}
}

// A package-level failure means no test reported it: a build error must not look
// like a green run with a smaller suite.
func TestEnforceRejectsPackageFailure(t *testing.T) {
	inv := &TestInventory{PackageFailures: []string{"p"}, passed: map[caseRef]bool{}}
	r := rulesWith(t)
	r.Tests.MinPassing = 1

	err := inv.Enforce(r)
	if err == nil || !strings.Contains(err.Error(), "package failed without a test result") {
		t.Fatalf("expected a package failure to be reported, got %v", err)
	}
}

func TestEnforceFloorAndRequired(t *testing.T) {
	inv := &TestInventory{Passed: 1, passed: map[caseRef]bool{{"p", "TestA"}: true}}
	r := rulesWith(t)
	r.Tests.MinPassing = 5
	r.Tests.Required = []RequiredTest{{Test: "TestA"}, {Test: "TestMissing"}}

	err := inv.Enforce(r)
	if err == nil {
		t.Fatal("expected violations")
	}
	msg := err.Error()
	if !strings.Contains(msg, "floor is 5") {
		t.Errorf("expected the floor violation, got: %v", msg)
	}
	if !strings.Contains(msg, "TestMissing") {
		t.Errorf("expected the missing required test, got: %v", msg)
	}
	if strings.Contains(msg, "TestA") {
		t.Errorf("TestA passed, it must not be reported missing: %v", msg)
	}
}

// The allowlist must be exhaustive in both directions: an undeclared skip fails,
// and a declaration that no longer skips fails too.
func TestEnforceSkipsBothDirections(t *testing.T) {
	r := rulesWith(t)
	r.Tests.MinPassing = 1
	r.Tests.AllowedSkips = []AllowedSkip{
		{Package: "p", Test: "TestStale", Reason: "was skipped once"},
	}

	inv := &TestInventory{Passed: 1, passed: map[caseRef]bool{{"p", "TestA"}: true},
		Skipped: []caseRef{{"p", "TestUndeclared"}}}

	err := inv.Enforce(r)
	if err == nil {
		t.Fatal("expected violations")
	}
	if !strings.Contains(err.Error(), "undeclared skip: p.TestUndeclared") {
		t.Errorf("expected the undeclared skip, got: %v", err)
	}
	if !strings.Contains(err.Error(), "stale allowlist entry: p.TestStale") {
		t.Errorf("expected the stale entry, got: %v", err)
	}
}

// A skip declared for another platform must not silence this one.
func TestEnforceSkipsArePlatformScoped(t *testing.T) {
	r := rulesWith(t)
	r.Tests.MinPassing = 1
	r.Tests.AllowedSkips = []AllowedSkip{
		{Package: "p", Test: "TestSock", Reason: "posix only", GOOS: "plan9"},
	}
	r.Tests.Required = []RequiredTest{{Test: "TestNeedsLinux", GOOS: "plan9"}}

	inv := &TestInventory{Passed: 1, passed: map[caseRef]bool{{"p", "TestA"}: true},
		Skipped: []caseRef{{"p", "TestSock"}}}

	err := inv.Enforce(r)
	if err == nil {
		t.Fatal("expected the skip to be undeclared on this platform")
	}
	if !strings.Contains(err.Error(), "undeclared skip: p.TestSock") {
		t.Errorf("expected an undeclared skip, got: %v", err)
	}
	if strings.Contains(err.Error(), "TestNeedsLinux") {
		t.Errorf("requirement for another platform must be ignored, got: %v", err)
	}
}

func TestParseBenchOutput(t *testing.T) {
	const out = `goos: linux
BenchmarkA-6   200   269.5 ns/op   48 B/op   1 allocs/op
BenchmarkB-6   200   100.0 ns/op   0 B/op    0 allocs/op
BenchmarkA-6   200   300.0 ns/op   64 B/op    2 allocs/op
ok  	pkg	1.2s
`
	res, err := ParseBenchOutput(strings.NewReader(out))
	if err != nil {
		t.Fatalf("ParseBenchOutput: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d benchmarks, want 2", len(res))
	}
	if res["BenchmarkA"].AllocsPerOp != 2 {
		t.Errorf("A allocs = %d, want the worst of the repeated runs (2)", res["BenchmarkA"].AllocsPerOp)
	}
	if res["BenchmarkB"].AllocsPerOp != 0 {
		t.Errorf("B allocs = %d, want 0", res["BenchmarkB"].AllocsPerOp)
	}
}

func TestEnforceBench(t *testing.T) {
	r := rulesWith(t)
	r.Bench.Required = []string{"BenchmarkA"}
	r.Bench.MaxAllocsPerOp = map[string]int{"BenchmarkA": 1}

	results := map[string]BenchResult{
		"BenchmarkA": {Name: "BenchmarkA", AllocsPerOp: 3, HasAllocs: true},
		"BenchmarkZ": {Name: "BenchmarkZ", AllocsPerOp: 0, HasAllocs: true},
	}

	err := r.EnforceBench(results)
	if err == nil {
		t.Fatal("expected violations")
	}
	msg := err.Error()
	if !strings.Contains(msg, "exceeds the ceiling of 1") {
		t.Errorf("expected a ceiling violation, got: %v", msg)
	}
	if !strings.Contains(msg, "unlisted benchmark measured: BenchmarkZ") {
		t.Errorf("expected the unlisted benchmark, got: %v", msg)
	}
}

func TestEnforceBenchMissingRequired(t *testing.T) {
	r := rulesWith(t)
	r.Bench.Required = []string{"BenchmarkGone"}

	err := r.EnforceBench(map[string]BenchResult{})
	if err == nil || !strings.Contains(err.Error(), "required benchmark did not run") {
		t.Fatalf("a deleted benchmark must fail, got %v", err)
	}
}

func TestFuzzSeedsFromASTAndCorpus(t *testing.T) {
	root := t.TempDir()
	src := `package x
import "testing"
func FuzzThing(f *testing.F) {
	f.Add("a")
	f.Add("b")
	g := f
	g.Add("not the receiver")
}
`
	if err := writeFile(root+"/x_test.go", src); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(root+"/testdata/fuzz/FuzzThing/seed1", "x"); err != nil {
		t.Fatal(err)
	}

	counts, err := seedCounts(root, []string{"FuzzThing"})
	if err != nil {
		t.Fatalf("seedCounts: %v", err)
	}
	if counts["FuzzThing"] != 3 {
		t.Errorf("count = %d, want 3 (2 in the AST + 1 corpus file)", counts["FuzzThing"])
	}
}

func TestFuzzMissingTargetFails(t *testing.T) {
	if _, err := seedCounts(t.TempDir(), []string{"FuzzNope"}); err == nil {
		t.Fatal("a declared target that does not exist must fail")
	}
}

func TestEnforceFuzzFloor(t *testing.T) {
	r := rulesWith(t)
	r.Fuzz.MinSeeds = map[string]int{"FuzzThing": 5}

	if err := r.EnforceFuzz(map[string]int{"FuzzThing": 2}); err == nil ||
		!strings.Contains(err.Error(), "corpus with no seeds proves nothing") {
		t.Fatalf("expected a seed floor violation, got %v", err)
	}
}

func TestLoadRulesRejectsUnknownField(t *testing.T) {
	path := t.TempDir() + "/gates.json"
	if err := writeFile(path, `{"gates":["tests"],"tests":{"min_passing":1,"min_passin":10}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(path); err == nil {
		t.Fatal("a misspelled key must be rejected, otherwise the rule silently disappears")
	}
}

func TestRulesValidate(t *testing.T) {
	var r Rules
	if err := r.Validate(); err == nil {
		t.Error("empty rules must be invalid: they would prove nothing")
	}

	r.Gates = []string{"tests"}
	r.Tests.MinPassing = 1
	r.Tests.AllowedSkips = []AllowedSkip{{Package: "p", Test: "T"}}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "reason is required") {
		t.Errorf("a skip without a reason must be rejected, got %v", err)
	}
	r.Tests.AllowedSkips = nil
	if err := r.Validate(); err != nil {
		t.Errorf("valid rules rejected: %v", err)
	}
}

func TestGateFlagsParse(t *testing.T) {
	var g gateFlags
	if err := g.Set("tests=pass"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := g.Set("bench=fail"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := g.Set("bench=maybe"); err == nil {
		t.Error("an unknown status must be rejected")
	}
	if err := g.Set("novalue"); err == nil {
		t.Error("a flag without = must be rejected")
	}
	if len(g) != 2 {
		t.Errorf("got %d gates, want 2", len(g))
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" b, a ,, ")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("splitList = %v, want [a b]", got)
	}
	if splitList("  ") != nil {
		t.Error("blank input must yield nil")
	}
}
