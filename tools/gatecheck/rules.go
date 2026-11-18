package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// DefaultRulesPath is the profile committed with the repository.
const DefaultRulesPath = ".ci/gates.json"

// Rules is the inventory the gates must observe. It is data, not policy: the
// numbers here are measured, then declared, and only ever tightened.
type Rules struct {
	// Comment is free text for whoever maintains the numbers. It carries no
	// behaviour; it exists so an explanation lives next to the value it explains.
	Comment string `json:"comment,omitempty"`

	// Gates lists the gates that must appear in a report, so a job that silently
	// stops producing one fails instead of passing by absence.
	Gates []string `json:"gates"`

	Tests struct {
		// MinPassing is a floor on the number of tests that passed. It exists so an
		// empty or partially-collected suite cannot be green.
		MinPassing int `json:"min_passing"`
		// Required tests must run and pass, by name. This is how a security
		// regression test stops being deletable. GOOS scopes the requirement to
		// one platform, for tests that only exist under a build tag.
		Required []RequiredTest `json:"required"`
		// AllowedSkips is exhaustive: a skip that is not declared fails, and a
		// declaration that no longer skips also fails, because a stale allowlist
		// is a rule that quietly stopped applying.
		AllowedSkips []AllowedSkip `json:"allowed_skips"`
	} `json:"tests"`

	Bench struct {
		// Required benchmarks must appear in the run. A deleted benchmark fails
		// instead of becoming silence.
		Required []string `json:"required"`
		// MaxAllocsPerOp is an allocation ceiling per benchmark, in allocs/op.
		// Measured with the toolchain CI pins: same code, different Go version,
		// different count (26 vs 31 allocs on BasicScorer_Evaluate_Clean).
		MaxAllocsPerOp map[string]int `json:"max_allocs_per_op"`
	} `json:"bench"`

	Fuzz struct {
		// MinSeeds is a floor per fuzz target, counted from the AST (`f.Add`) plus
		// testdata/fuzz/<Target>, so in-code seeds are not duplicated.
		MinSeeds map[string]int `json:"min_seeds"`
	} `json:"fuzz"`
}

// RequiredTest is a test that must be observed passing. GOOS, when set, limits
// the requirement to that platform: a test behind `//go:build !windows` cannot be
// required on Windows without making the gate wrong on Windows.
type RequiredTest struct {
	Test string `json:"test"`
	GOOS string `json:"goos,omitempty"`
}

// AllowedSkip is one declared skip. The reason is mandatory: an unexplained skip
// is indistinguishable from a test that stopped running.
//
// GOOS scopes the declaration to one platform. It is required in practice for any
// test that skips for a platform reason: declaring it globally would make the
// allowlist stale on the platform where the test does run, and a stale allowlist
// is a rule that quietly stopped applying.
type AllowedSkip struct {
	Test    string `json:"test"`
	Package string `json:"package"`
	Reason  string `json:"reason"`
	GOOS    string `json:"goos,omitempty"`
}

// LoadRules reads and validates the rules file. Unknown fields are rejected so a
// misspelled key cannot silently disable a rule.
func LoadRules(path string) (*Rules, error) {
	if path == "" {
		path = DefaultRulesPath
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening rules %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var r Rules
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parsing rules %s: %w", path, err)
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("invalid rules %s: %w", path, err)
	}
	return &r, nil
}

// Validate rejects a rules file that could only ever pass or never mean anything.
func (r *Rules) Validate() error {
	if len(r.Gates) == 0 {
		return errors.New("gates: at least one gate must be declared")
	}
	if r.Tests.MinPassing <= 0 && len(r.Tests.Required) == 0 {
		return errors.New("tests: declare min_passing or required, otherwise the gate proves nothing")
	}
	for i, s := range r.Tests.AllowedSkips {
		if s.Test == "" || s.Package == "" {
			return fmt.Errorf("tests.allowed_skips[%d]: test and package are required", i)
		}
		if s.Reason == "" {
			return fmt.Errorf("tests.allowed_skips[%d] (%s): reason is required", i, s.Test)
		}
	}
	for name, maxAllocs := range r.Bench.MaxAllocsPerOp {
		if maxAllocs < 0 {
			return fmt.Errorf("bench.max_allocs_per_op[%s]: must be >= 0", name)
		}
	}
	for i, req := range r.Tests.Required {
		if req.Test == "" {
			return fmt.Errorf("tests.required[%d]: test is required", i)
		}
	}
	for name, seeds := range r.Fuzz.MinSeeds {
		if seeds <= 0 {
			return fmt.Errorf("fuzz.min_seeds[%s]: must be > 0", name)
		}
	}
	return nil
}
