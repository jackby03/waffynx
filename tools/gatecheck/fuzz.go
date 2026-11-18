package main

import (
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// seedCounts maps a fuzz target to the number of seeds reachable for it: the
// `f.Add(...)` calls in the AST plus every file in testdata/fuzz/<Target>.
//
// Both are counted because either alone is a partial truth: a target with corpus
// files and no in-code seeds starts from an empty baseline in a fresh checkout,
// and a corpus added by the fuzzer over time is invisible to the AST.
func seedCounts(root string, targets []string) (map[string]int, error) {
	counts := map[string]int{}
	found := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "third_party", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}

		for name, n := range seedsInFile(path) {
			counts[name] += n
			found[name] = true
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}

	var missing []string
	for _, target := range targets {
		if !found[target] {
			missing = append(missing, target)
			continue
		}
		corpus, err := countCorpus(root, target)
		if err != nil {
			return nil, err
		}
		counts[target] += corpus
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("declared fuzz target not found in the tree: %s", strings.Join(missing, ", "))
	}
	return counts, nil
}

// seedsInFile counts `f.Add(...)` calls for every fuzz function in one file.
func seedsInFile(path string) map[string]int {
	out := map[string]int{}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return out // a file the parser rejects is not our business to report twice
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
			continue
		}
		receiver := fuzzReceiverName(fn)
		if receiver == "" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Add" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == receiver {
				out[fn.Name.Name]++
			}
			return true
		})
	}
	return out
}

// fuzzReceiverName returns the name of the `*testing.F` parameter, which is the
// only identifier a seed call can be attached to.
func fuzzReceiverName(fn *ast.FuncDecl) string {
	if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return ""
	}
	for _, field := range fn.Type.Params.List {
		if len(field.Names) != 1 {
			continue
		}
		star, ok := field.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if sel, ok := star.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "F" {
			return field.Names[0].Name
		}
	}
	return ""
}

// countCorpus counts files under any testdata/fuzz/<target> directory.
func countCorpus(root, target string) (int, error) {
	var total int
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		switch d.Name() {
		case ".git", "third_party", "node_modules", "vendor":
			return filepath.SkipDir
		}
		if d.Name() != "fuzz" {
			return nil
		}
		if filepath.Base(filepath.Dir(path)) != "testdata" {
			return nil
		}
		entries, readErr := os.ReadDir(filepath.Join(path, target))
		if readErr != nil {
			if os.IsNotExist(readErr) {
				return nil
			}
			return readErr
		}
		for _, e := range entries {
			if !e.IsDir() {
				total++
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("counting corpus for %s: %w", target, err)
	}
	return total, nil
}

// EnforceFuzz applies the seed floors.
func (r *Rules) EnforceFuzz(counts map[string]int) error {
	var problems []string
	for _, name := range sortedSeedTargets(r.Fuzz.MinSeeds) {
		min := r.Fuzz.MinSeeds[name]
		if got := counts[name]; got < min {
			problems = append(problems, fmt.Sprintf(
				"%s: %d seeds, floor is %d (a corpus with no seeds proves nothing)", name, got, min))
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n  "))
	}
	return nil
}

func sortedSeedTargets(m map[string]int) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func runFuzz(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	rulesPath := fs.String("rules", DefaultRulesPath, "rules file")
	if err := parseFlags(fs, args, os.Stderr); err != nil {
		return err
	}

	rules, err := LoadRules(*rulesPath)
	if err != nil {
		return err
	}
	if len(rules.Fuzz.MinSeeds) == 0 {
		return errors.New("fuzz: no targets declared, the gate would prove nothing")
	}

	targets := sortedSeedTargets(rules.Fuzz.MinSeeds)
	counts, err := seedCounts(*root, targets)
	if err != nil {
		return err
	}
	if err := rules.EnforceFuzz(counts); err != nil {
		return err
	}

	parts := make([]string, 0, len(targets))
	for _, t := range targets {
		parts = append(parts, fmt.Sprintf("%s=%d", t, counts[t]))
	}
	_, _ = fmt.Fprintf(stdout, "fuzz: %s\n", strings.Join(parts, " "))
	return nil
}
