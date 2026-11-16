// Command covergate enforces a minimum statement-coverage floor per package.
//
// Why this exists instead of a global threshold: a single total percentage is
// dominated by whichever package happens to have the most statements, so it
// hides regressions in small but security-critical packages. Floors are per
// package and only ever ratchet up.
//
// Usage:
//
//	go test -coverpkg=./... -coverprofile=coverage.out ./...
//	go run ./tools/covergate -profile coverage.out
//
// -coverpkg matters: without it, coverage exercised across package boundaries
// (for example the inspection pipeline driven from cmd/waffynx) is not counted.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

const modulePath = "github.com/jackby03/waffynx/"

// floors is the one-way ratchet. Set each value at or just below the current
// measured coverage; raise it when coverage improves, never lower it to make a
// build pass. A package listed here must appear in the profile — its absence
// means it was not built or tested, which is itself a failure.
var floors = map[string]float64{
	"internal/policy":    95,
	"internal/config":    95,
	"internal/learning":  95,
	"internal/audit":     88,
	"internal/plugin":    88,
	"internal/rules":     88,
	"internal/parsers":   80,
	"internal/events":    80,
	"internal/upstream":  72,
	"internal/appsec":    65,
	"internal/ratelimit": 55,
	"internal/firewall":  50,

	// Pure validation and text rendering: there is no excuse for gaps here, so the
	// floor is set high from the start.
	"internal/sites": 90,

	// `internal/engine` holds the inspection pipeline that decides whether an
	// attack is blocked. It was at 34.9% until Sidecar.Decide was extracted and the
	// HTTP handlers, PolicyStore and Engine wiring got direct tests.
	//
	// Note the floor is measured on Linux, which compiles engine_unix.go (the nginx
	// lifecycle) and therefore reports ~3 points less than a Windows run, where
	// that file is excluded by its build tag.
	"internal/engine": 75,

	// `internal/api` is the control plane, still the weakest of the gated set.
	// Raise it as handlers gain tests.
	"internal/api": 50,

	"minTotal": 41,
}

type pkgCoverage struct {
	stmts   int
	covered int
}

func (p pkgCoverage) percent() float64 {
	if p.stmts == 0 {
		return 0
	}
	return float64(p.covered) / float64(p.stmts) * 100
}

// parseProfile aggregates a Go coverage profile per package.
//
// With -coverpkg every test binary re-emits the same block, so the profile holds
// duplicates. Counting them naively inflates the denominator; blocks are keyed by
// file+range and the highest execution count wins.
func parseProfile(path string) (map[string]pkgCoverage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	type block struct {
		pkg   string
		stmts int
		count int
	}
	blocks := make(map[string]block)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		// <file>:<startLine>.<startCol>,<endLine>.<endCol> <numStmt> <count>
		colon := strings.LastIndex(line, ":")
		if colon < 0 {
			return nil, fmt.Errorf("malformed coverage line: %q", line)
		}
		file := line[:colon]
		fields := strings.Fields(line[colon+1:])
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed coverage line: %q", line)
		}
		// fields[0] is the line range (startLine.startCol,endLine.endCol).
		stmts, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, fmt.Errorf("bad statement count in %q: %w", line, err)
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("bad execution count in %q: %w", line, err)
		}

		key := file + ":" + fields[0]
		prev, seen := blocks[key]
		if !seen {
			prev = block{pkg: packageOf(file), stmts: stmts}
		}
		if count > prev.count {
			prev.count = count
		}
		blocks[key] = prev
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	perPkg := make(map[string]pkgCoverage)
	for _, b := range blocks {
		p := perPkg[b.pkg]
		p.stmts += b.stmts
		if b.count > 0 {
			p.covered += b.stmts
		}
		perPkg[b.pkg] = p
	}
	return perPkg, nil
}

// packageOf maps a profile file path to its package, relative to the module.
func packageOf(file string) string {
	file = strings.TrimPrefix(file, modulePath)
	idx := strings.LastIndex(file, "/")
	if idx < 0 {
		return "."
	}
	return file[:idx]
}

func main() {
	profile := flag.String("profile", "coverage.out", "coverage profile produced by go test -coverprofile")
	quiet := flag.Bool("quiet", false, "only print floor violations")
	flag.Parse()

	perPkg, err := parseProfile(*profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "covergate: %v\n", err)
		os.Exit(2)
	}

	names := make([]string, 0, len(perPkg))
	for name := range perPkg {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return perPkg[names[i]].percent() > perPkg[names[j]].percent()
	})

	var total pkgCoverage
	var violations []string

	if !*quiet {
		fmt.Printf("%-28s %8s %8s %s\n", "PACKAGE", "COVER", "FLOOR", "")
	}
	for _, name := range names {
		p := perPkg[name]
		total.stmts += p.stmts
		total.covered += p.covered

		floor, gated := floors[name]
		if !gated {
			if !*quiet {
				fmt.Printf("%-28s %7.1f%% %8s\n", name, p.percent(), "-")
			}
			continue
		}
		status := "ok"
		if p.percent() < floor {
			status = "BELOW FLOOR"
			violations = append(violations, fmt.Sprintf("%s: %.1f%% < %.0f%%", name, p.percent(), floor))
		}
		if !*quiet {
			fmt.Printf("%-28s %7.1f%% %7.0f%% %s\n", name, p.percent(), floor, status)
		}
	}

	// A gated package that never appears in the profile was not built or not
	// tested at all: that is a failure, not a pass.
	for name := range floors {
		if name == "minTotal" {
			continue
		}
		if _, ok := perPkg[name]; !ok {
			violations = append(violations, name+": missing from profile (package not built or tested)")
		}
	}

	totalPct := total.percent()
	if minTotal, ok := floors["minTotal"]; ok {
		if !*quiet {
			fmt.Printf("%-28s %7.1f%% %7.0f%%\n", "TOTAL", totalPct, minTotal)
		}
		if totalPct < minTotal {
			violations = append(violations, fmt.Sprintf("total: %.1f%% < %.0f%%", totalPct, minTotal))
		}
	}

	if len(violations) > 0 {
		fmt.Fprintln(os.Stderr, "\ncovergate: coverage floors not met:")
		for _, v := range violations {
			fmt.Fprintln(os.Stderr, "  - "+v)
		}
		fmt.Fprintln(os.Stderr, "\nFloors only ratchet up. If a floor is genuinely unreachable,")
		fmt.Fprintln(os.Stderr, "explain why in the PR instead of lowering it.")
		os.Exit(1)
	}

	if !*quiet {
		fmt.Printf("\ncovergate: all %d floors met\n", len(floors))
	}
}
