// Package catalog is the managed ruleset: a declarative file of attack
// signatures, compiled once and evaluated per request.
//
// Why a separate package from internal/rules: those are operator-defined custom
// rules (IP bans, "block this host path"), evaluated in insertion order and
// edited at runtime. This is the shipped catalog: hundreds of signatures written
// by the project, validated at load time, immutable at runtime, and versioned
// with the binary. Mixing them made both harder to reason about.
//
// The matcher deliberately favours normalisation over regex. A signature like
// "union select" is compiled with the same transformations applied to the request,
// so it also catches "union/**/select", "union%20select" and "union+select"
// without a regex engine in the hot path.
package catalog

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed catalog.yaml
var embedded []byte

// Field is an input the matcher inspects.
type Field string

const (
	FieldMethod    Field = "method"
	FieldPath      Field = "path"
	FieldQuery     Field = "query"
	FieldBody      Field = "body"
	FieldHeaders   Field = "headers"
	FieldUserAgent Field = "user_agent"
	FieldReferer   Field = "referer"
)

var validFields = map[Field]bool{
	FieldMethod: true, FieldPath: true, FieldQuery: true, FieldBody: true,
	FieldHeaders: true, FieldUserAgent: true, FieldReferer: true,
}

// Severity orders a hit for events and logs.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

var severityRank = map[Severity]int{
	SeverityCritical: 4, SeverityHigh: 3, SeverityMedium: 2, SeverityLow: 1,
}

// Action is what a hit does. Only "block" denies; "log" records and continues,
// which is what makes a staged rollout possible.
type Action string

const (
	ActionBlock Action = "block"
	ActionLog   Action = "log"
)

// Rule is one signature as written in the catalog file.
type Rule struct {
	ID       string   `yaml:"id"`
	Name     string   `yaml:"name"`
	Severity Severity `yaml:"severity"`
	Action   Action   `yaml:"action"`
	Tags     []string `yaml:"tags,omitempty"`

	// Methods restricts the rule to some HTTP methods. Empty means any.
	Methods []string `yaml:"methods,omitempty"`
	// Fields lists the inputs to inspect. Empty means path, query and body.
	Fields []Field `yaml:"fields,omitempty"`
	// Decoded applies the normalisation pipeline (percent-decoding, HTML and JSON
	// escapes, lowercasing, whitespace and comment squashing) before matching.
	// Pointer so "not set" means true while an explicit false is preserved.
	Decoded *bool `yaml:"decoded,omitempty"`

	// AnyOf are substrings that indicate the rule fired.
	AnyOf []string `yaml:"any_of"`
	// NoneOf are substrings that suppress the rule when present in the same value.
	NoneOf []string `yaml:"none_of,omitempty"`

	// compiled forms, normalised exactly like the request is
	fields []Field
	method map[string]bool
	// anyOfIdx/noneOfIdx point into Catalog.patterns, which the shared automaton
	// indexes. Storing indices instead of strings is what makes one scan per field
	// possible regardless of how many rules exist.
	anyOfIdx  []int32
	noneOfIdx []int32
}

// Catalog is a loaded, validated ruleset.
type Catalog struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`

	// patterns is the deduplicated, normalised signature list the automaton is
	// built over; patternAt reverses an index to the text, for events.
	patterns  []string
	auto      *automaton
	hitsWords int
	// rawUsed/decUsed mark, per input, whether some rule inspects it raw or
	// decoded. Evaluation only normalises a field when a rule will read it.
	rawUsed [fieldCount]bool
	decUsed [fieldCount]bool
	// bodyCeiling sizes the scratch buffer: the largest input a rule can read.
	bodyCeiling int
}

// Load parses and compiles a catalog. Unknown keys are rejected: a typo in a
// signature field would otherwise silently narrow a rule to "match everything".
func Load(data []byte) (*Catalog, error) {
	var c Catalog
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing catalog: %w", err)
	}
	if err := c.compile(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Embedded returns the catalog shipped with the binary.
func Embedded() (*Catalog, error) {
	c, err := Load(embedded)
	if err != nil {
		return nil, fmt.Errorf("embedded catalog is invalid: %w", err)
	}
	return c, nil
}

// LoadFile reads a catalog from disk, for operators who pin their own ruleset.
func LoadFile(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading catalog %s: %w", path, err)
	}
	c, err := Load(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// compile validates every rule and precomputes its normalised patterns.
func (c *Catalog) compile() error {
	if c.Version == 0 {
		return errors.New("catalog: version is required")
	}
	if len(c.Rules) == 0 {
		return errors.New("catalog: no rules")
	}

	seen := make(map[string]bool, len(c.Rules))
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("catalog rule %d: id is required", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("catalog: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true

		if r.Name == "" {
			return fmt.Errorf("%s: name is required", r.ID)
		}
		if _, ok := severityRank[r.Severity]; !ok {
			return fmt.Errorf("%s: invalid severity %q", r.ID, r.Severity)
		}
		if r.Action != ActionBlock && r.Action != ActionLog {
			return fmt.Errorf("%s: invalid action %q (want block or log)", r.ID, r.Action)
		}
		if len(r.AnyOf) == 0 {
			return fmt.Errorf("%s: any_of must list at least one pattern", r.ID)
		}

		r.fields = r.Fields
		if len(r.fields) == 0 {
			r.fields = []Field{FieldPath, FieldQuery, FieldBody}
		}
		for _, f := range r.fields {
			if !validFields[f] {
				return fmt.Errorf("%s: invalid field %q", r.ID, f)
			}
		}

		if len(r.Methods) > 0 {
			r.method = make(map[string]bool, len(r.Methods))
			for _, m := range r.Methods {
				r.method[strings.ToUpper(m)] = true
			}
		}

		decoded := r.Decoded == nil || *r.Decoded
		for _, f := range r.fields {
			idx := fieldIndex(f)
			if idx < 0 {
				continue
			}
			if decoded {
				c.decUsed[idx] = true
			} else {
				c.rawUsed[idx] = true
			}
		}

		for _, p := range r.AnyOf {
			if p == "" {
				return fmt.Errorf("%s: empty pattern in any_of", r.ID)
			}
			r.anyOfIdx = append(r.anyOfIdx, c.patternIndex(Normalize(p, decoded)))
		}
		for _, p := range r.NoneOf {
			r.noneOfIdx = append(r.noneOfIdx, c.patternIndex(Normalize(p, decoded)))
		}
		if !decoded {
			r.Decoded = &decoded
		}
	}

	c.bodyCeiling = 64<<10 + 1 // body cap, plus one for safety
	c.auto = buildAutomaton(c.patterns)
	c.hitsWords = patternHitsWords(len(c.patterns))
	return nil
}

// patternIndex interns a normalised pattern and returns its automaton index.
func (c *Catalog) patternIndex(p string) int32 {
	for i, existing := range c.patterns {
		if existing == p {
			return int32(i)
		}
	}
	c.patterns = append(c.patterns, p)
	//nolint:gosec // G115: a catalog cannot hold 2^31 patterns; it is a checked-in file.
	return int32(len(c.patterns) - 1)
}

// Count returns the number of rules, for startup logs.
func (c *Catalog) Count() int { return len(c.Rules) }

// BySeverity returns how many rules exist per severity, for the startup log.
func (c *Catalog) BySeverity() map[Severity]int {
	out := map[Severity]int{}
	for _, r := range c.Rules {
		out[r.Severity]++
	}
	return out
}
