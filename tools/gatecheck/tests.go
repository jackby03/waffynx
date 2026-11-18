package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
)

// testEvent is the subset of `go test -json` this gate reads.
type testEvent struct {
	Action  string
	Package string
	Test    string
}

// TestInventory is what a test run actually observed. The passed set is kept,
// not just its size: a required test has to be named to be proven present.
type TestInventory struct {
	Passed          int
	Failed          []string
	PackageFailures []string
	Skipped         []caseRef

	passed map[caseRef]bool
}

type caseRef struct {
	Package string
	Test    string
}

func (c caseRef) String() string { return c.Package + "." + c.Test }

// ParseTestStream reads the JSON stream produced by `go test -json`. Subtests are
// included; the same (package, test) pair is counted once.
func ParseTestStream(r io.Reader) (*TestInventory, error) {
	inv := &TestInventory{passed: map[caseRef]bool{}}
	skipped := map[caseRef]bool{}

	dec := json.NewDecoder(r)
	for {
		var ev testEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decoding test event: %w", err)
		}

		ref := caseRef{Package: ev.Package, Test: ev.Test}
		switch ev.Action {
		case "pass":
			if ev.Test != "" {
				inv.passed[ref] = true
			}
		case "skip":
			if ev.Test != "" {
				skipped[ref] = true
			}
		case "fail":
			if ev.Test != "" {
				inv.Failed = append(inv.Failed, ref.String())
			} else {
				// A package-level failure is a build error or a panic before any test
				// ran: no test reports it, so name the package.
				inv.PackageFailures = append(inv.PackageFailures, ev.Package)
			}
		}
	}

	inv.Passed = len(inv.passed)
	for ref := range inv.passed {
		delete(skipped, ref) // a test cannot both pass and skip
	}
	for ref := range skipped {
		inv.Skipped = append(inv.Skipped, ref)
	}
	sort.Slice(inv.Skipped, func(i, j int) bool {
		return inv.Skipped[i].String() < inv.Skipped[j].String()
	})
	sort.Strings(inv.Failed)
	inv.PackageFailures = dedupe(inv.PackageFailures)
	return inv, nil
}

// Enforce applies the rules and returns every violation at once, so one run
// reports all of them instead of one per push.
func (inv *TestInventory) Enforce(r *Rules) error {
	var problems []string

	for _, p := range inv.PackageFailures {
		problems = append(problems, fmt.Sprintf("package failed without a test result: %s", p))
	}
	for _, t := range inv.Failed {
		problems = append(problems, "test failed: "+t)
	}
	if inv.Passed < r.Tests.MinPassing {
		problems = append(problems, fmt.Sprintf(
			"only %d tests passed, floor is %d (an empty or partially collected suite is not a pass)",
			inv.Passed, r.Tests.MinPassing))
	}

	declared := map[caseRef]string{}
	for _, s := range r.Tests.AllowedSkips {
		if s.GOOS != "" && s.GOOS != runtime.GOOS {
			continue // does not apply on this platform, so it is neither stale nor a licence
		}
		declared[caseRef{Package: s.Package, Test: s.Test}] = s.Reason
	}

	for _, want := range r.Tests.Required {
		if want.GOOS != "" && want.GOOS != runtime.GOOS {
			continue
		}
		found := false
		for ref := range inv.passed {
			if ref.Test == want.Test {
				found = true
				break
			}
		}
		if !found && !declaredByName(want.Test, declared) {
			problems = append(problems, "required test did not run and pass: "+want.Test)
		}
	}

	seen := map[caseRef]bool{}
	for _, ref := range inv.Skipped {
		seen[ref] = true
		if _, ok := declared[ref]; !ok {
			problems = append(problems, fmt.Sprintf(
				"undeclared skip: %s (declare it in .ci/gates.json with a reason, or make it run)", ref))
		}
	}
	for ref := range declared {
		if !seen[ref] {
			problems = append(problems, fmt.Sprintf(
				"stale allowlist entry: %s no longer skips, remove it from .ci/gates.json", ref))
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n  "))
	}
	return nil
}

func runTests(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("tests", flag.ContinueOnError)
	jsonPath := fs.String("json", "", "file with `go test -json` output (required)")
	rulesPath := fs.String("rules", DefaultRulesPath, "rules file")
	if err := parseFlags(fs, args, os.Stderr); err != nil {
		return err
	}
	if *jsonPath == "" {
		return errors.New("tests: -json is required")
	}

	rules, err := LoadRules(*rulesPath)
	if err != nil {
		return err
	}

	f, err := os.Open(*jsonPath)
	if err != nil {
		return fmt.Errorf("opening test output: %w", err)
	}
	defer func() { _ = f.Close() }()

	inv, err := ParseTestStream(f)
	if err != nil {
		return err
	}
	if err := inv.Enforce(rules); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stdout, "tests: %d passed, %d skipped (all declared)\n", inv.Passed, len(inv.Skipped))
	return nil
}

// declaredByName reports whether a test is skipped by an applicable declaration,
// in which case it is deliberately absent rather than missing.
func declaredByName(name string, declared map[caseRef]string) bool {
	for ref := range declared {
		if ref.Test == name {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
