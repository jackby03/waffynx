// Command gatecheck enforces minimum inventories for this repository's CI gates.
//
// The problem it solves: "the command exited 0" and "the fact was observed" are
// different claims. A test run with an empty suite is green. A benchmark that was
// deleted is not slow. A fuzz target with no seeds proves nothing. A CI step whose
// output never reaches the gate leaves the gate green. Every one of those has
// happened in this repository.
//
// So each gate declares what must be *observed*, and absence is a failure:
//
//	tests  -> parsed from `go test -json`: floor, required tests, declared skips only
//	bench  -> parsed from `-benchmem`: required benchmarks, unlisted ones, alloc ceilings
//	fuzz   -> counted from the AST plus the corpus: seeds per target
//	report -> binds a result to the tree that produced it (tree sha + diff sha)
//	verify -> fails when a declared gate is missing from the report
//
// Rules live in .ci/gates.json. Unknown keys are rejected: a typo that silently
// disabled a rule would be the same failure one level down.
//
// Usage:
//
//	go test -race -json ./... > run.json && go run ./tools/gatecheck tests -json run.json
//	go test -run '^$' -bench . -benchmem ./... > bench.txt && go run ./tools/gatecheck bench -out bench.txt
//	go run ./tools/gatecheck fuzz -root .
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const usage = `gatecheck <command> [flags]

Commands:
  tests    -json FILE [-rules FILE]        enforce the test inventory
  bench    -out FILE  [-rules FILE]        enforce benchmark inventory and alloc ceilings
  fuzz     [-root DIR] [-rules FILE]       enforce the minimum seed count per fuzz target
  report   -out FILE -gate NAME=STATUS...  write a result bound to the checked-out tree
  verify   -report FILE -expect a,b        fail when a declared gate is absent
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "gatecheck:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return errors.New("no command given")
	}

	switch cmd, rest := args[0], args[1:]; cmd {
	case "tests":
		return runTests(rest, stdout)
	case "bench":
		return runBench(rest, stdout)
	case "fuzz":
		return runFuzz(rest, stdout)
	case "report":
		return runReport(rest, stdout)
	case "verify":
		return runVerify(rest, stdout)
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(stdout, usage)
		return nil
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// parseFlags parses a subcommand's flags, printing a consistent error and usage.
func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) error {
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return nil
}
