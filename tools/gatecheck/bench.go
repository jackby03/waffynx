package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// BenchResult is one benchmark line parsed from `go test -benchmem` output.
type BenchResult struct {
	Name        string
	AllocsPerOp int
	HasAllocs   bool
}

// ParseBenchOutput reads benchmark results. It tolerates log lines and package
// summaries, and keeps the worst (highest) allocation count per benchmark, because
// a benchmark may legitimately run more than once in the same invocation.
func ParseBenchOutput(r io.Reader) (map[string]BenchResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading benchmark output: %w", err)
	}

	results := map[string]BenchResult{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Benchmark") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := stripGOMAXPROCS(fields[0])

		var allocs int
		hasAllocs := false
		for i, f := range fields {
			if f == "allocs/op" && i > 0 {
				n, err := strconv.Atoi(fields[i-1])
				if err != nil {
					return nil, fmt.Errorf("parsing allocs/op for %s: %w", name, err)
				}
				allocs, hasAllocs = n, true
				break
			}
		}

		prev, seen := results[name]
		switch {
		case !seen:
			results[name] = BenchResult{Name: name, AllocsPerOp: allocs, HasAllocs: hasAllocs}
		case hasAllocs && (!prev.HasAllocs || allocs > prev.AllocsPerOp):
			results[name] = BenchResult{Name: name, AllocsPerOp: allocs, HasAllocs: true}
		}
	}
	return results, nil
}

// stripGOMAXPROCS removes the "-6" suffix go test appends to benchmark names.
func stripGOMAXPROCS(name string) string {
	if i := strings.LastIndex(name, "-"); i > 0 {
		if _, err := strconv.Atoi(name[i+1:]); err == nil {
			return name[:i]
		}
	}
	return name
}

// Enforce applies the benchmark rules.
func (r *Rules) EnforceBench(results map[string]BenchResult) error {
	var problems []string

	for _, want := range r.Bench.Required {
		if _, ok := results[want]; !ok {
			problems = append(problems, "required benchmark did not run: "+want+
				" (a deleted benchmark is not a fast one)")
		}
	}

	listed := map[string]bool{}
	for _, name := range r.Bench.Required {
		listed[name] = true
	}
	for _, name := range sortedNames(results) {
		if !listed[name] {
			problems = append(problems, "unlisted benchmark measured: "+name+
				" (declare it in .ci/gates.json so a deletion cannot pass)")
		}
	}

	for name, maxAllocs := range r.Bench.MaxAllocsPerOp {
		res, ok := results[name]
		if !ok {
			continue // already reported by Required
		}
		if !res.HasAllocs {
			problems = append(problems, name+": no allocs/op in the output, run with -benchmem")
			continue
		}
		if res.AllocsPerOp > maxAllocs {
			problems = append(problems, fmt.Sprintf(
				"%s: %d allocs/op exceeds the ceiling of %d (ratchet: tighten after measuring, never loosen)",
				name, res.AllocsPerOp, maxAllocs))
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n  "))
	}
	return nil
}

func sortedNames(results map[string]BenchResult) []string {
	names := make([]string, 0, len(results))
	for name := range results {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func runBench(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	outPath := fs.String("out", "", "file with `go test -benchmem` output (required)")
	rulesPath := fs.String("rules", DefaultRulesPath, "rules file")
	if err := parseFlags(fs, args, os.Stderr); err != nil {
		return err
	}
	if *outPath == "" {
		return errors.New("bench: -out is required")
	}

	rules, err := LoadRules(*rulesPath)
	if err != nil {
		return err
	}

	f, err := os.Open(*outPath)
	if err != nil {
		return fmt.Errorf("opening benchmark output: %w", err)
	}
	defer func() { _ = f.Close() }()

	results, err := ParseBenchOutput(f)
	if err != nil {
		return err
	}
	if err := rules.EnforceBench(results); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stdout, "bench: %d benchmarks, all listed, ceilings respected\n", len(results))
	return nil
}
