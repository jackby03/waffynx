package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Report binds observed gate results to the tree that produced them. A report that
// only names a commit can attach to code that was never verified; the tree sha and
// the diff hash are what make "verified" mean the bytes on disk.
type Report struct {
	TreeSHA    string       `json:"tree_sha"`
	DiffSHA256 string       `json:"diff_sha256"`
	Gates      []GateResult `json:"gates"`
}

// GateResult is one gate's outcome.
type GateResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

const (
	statusPass = "pass"
	statusFail = "fail"
)

// gateFlags collects repeated -gate name=status flags.
type gateFlags []GateResult

func (g *gateFlags) String() string { return fmt.Sprint([]GateResult(*g)) }

func (g *gateFlags) Set(v string) error {
	name, status, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return fmt.Errorf("expected name=status, got %q", v)
	}
	if status != statusPass && status != statusFail {
		return fmt.Errorf("status must be %q or %q, got %q", statusPass, statusFail, status)
	}
	*g = append(*g, GateResult{Name: name, Status: status})
	return nil
}

// git runs a git command in root and returns its trimmed output.
func git(root string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// treeSHA returns the git tree hash of HEAD, which changes when any tracked byte
// changes and therefore identifies the content a gate ran against.
func treeSHA(root string) (string, error) {
	return git(root, "rev-parse", "HEAD^{tree}")
}

// diffSHA256 hashes the uncommitted diff. A clean checkout hashes the empty
// string, which is stable and comparable across jobs.
func diffSHA256(root string) (string, error) {
	diff, err := git(root, "diff", "HEAD")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(diff))
	return hex.EncodeToString(sum[:]), nil
}

func runReport(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	outPath := fs.String("out", "", "where to write the report (required)")
	root := fs.String("root", ".", "repository root")
	var gates gateFlags
	fs.Var(&gates, "gate", "gate result as name=pass|fail (repeatable)")

	if err := parseFlags(fs, args, os.Stderr); err != nil {
		return err
	}
	if *outPath == "" {
		return errors.New("report: -out is required")
	}
	if len(gates) == 0 {
		return errors.New("report: at least one -gate is required, otherwise the report proves nothing")
	}

	tree, err := treeSHA(*root)
	if err != nil {
		return err
	}
	diff, err := diffSHA256(*root)
	if err != nil {
		return err
	}

	rec := Report{TreeSHA: tree, DiffSHA256: diff, Gates: gates}
	sort.Slice(rec.Gates, func(i, j int) bool { return rec.Gates[i].Name < rec.Gates[j].Name })

	if err := os.MkdirAll(filepath.Dir(*outPath), 0o750); err != nil {
		return fmt.Errorf("creating report directory: %w", err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}
	if err := os.WriteFile(*outPath, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	_, _ = fmt.Fprintf(stdout, "report: %d gates for tree %s\n", len(rec.Gates), short(tree))
	return nil
}

func runVerify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	reportPath := fs.String("report", "", "report written by the report command (required)")
	expect := fs.String("expect", "", "comma-separated gate names that must be present and passing (required)")
	root := fs.String("root", ".", "repository root")
	rulesPath := fs.String("rules", DefaultRulesPath, "rules file, used only when -expect is empty")

	if err := parseFlags(fs, args, os.Stderr); err != nil {
		return err
	}
	if *reportPath == "" {
		return errors.New("verify: -report is required (a missing report is a failure, not a skip)")
	}

	want := splitList(*expect)
	if len(want) == 0 {
		rules, err := LoadRules(*rulesPath)
		if err != nil {
			return err
		}
		want = rules.Gates
	}
	if len(want) == 0 {
		return errors.New("verify: no gates expected, nothing would be checked")
	}

	f, err := os.Open(*reportPath)
	if err != nil {
		return fmt.Errorf("opening report (the gate that should have written it did not run): %w", err)
	}
	defer func() { _ = f.Close() }()

	var rec Report
	if err := json.NewDecoder(f).Decode(&rec); err != nil {
		return fmt.Errorf("parsing report: %w", err)
	}

	var problems []string
	got := map[string]string{}
	for _, g := range rec.Gates {
		got[g.Name] = g.Status
	}
	for _, name := range want {
		status, ok := got[name]
		switch {
		case !ok:
			problems = append(problems, "gate missing from the report: "+name+" (it did not run, or ran and vanished)")
		case status != statusPass:
			problems = append(problems, "gate reported "+status+": "+name)
		}
	}

	current, err := treeSHA(*root)
	if err != nil {
		return err
	}
	if rec.TreeSHA != current {
		problems = append(problems, fmt.Sprintf(
			"report describes tree %s but the checkout is %s: the gates ran against different code",
			short(rec.TreeSHA), short(current)))
	}

	diff, err := diffSHA256(*root)
	if err != nil {
		return err
	}
	if rec.DiffSHA256 != diff {
		problems = append(problems, "the working tree changed after the report was written")
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n  "))
	}

	_, _ = fmt.Fprintf(stdout, "verify: %d gates passed against tree %s\n", len(want), short(current))
	return nil
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
