package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
)

type Backend interface {
	Initialize() error
	AddRule(rule Rule) error
	RemoveRule(rule Rule) error
	ListRules() ([]Rule, error)
	SetDefaultPolicy(chain string, policy string) error
	Flush() error
}

type Rule struct {
	Table    string
	Chain    string
	Protocol string
	Port     int
	Source   string
	Action   string
	Comment  string
}

type Manager struct {
	backend Backend
	cfg     config.FirewallConfig
}

func NewManager(cfg config.FirewallConfig) (*Manager, error) {
	m := &Manager{cfg: cfg}

	switch cfg.Backend {
	case "nftables":
		m.backend = &NFTablesBackend{}
	case "ufw":
		m.backend = &UFWBackend{}
	default:
		return nil, fmt.Errorf("unsupported firewall backend: %s", cfg.Backend)
	}

	return m, nil
}

func (m *Manager) Start() error {
	if !m.cfg.Enabled {
		logging.Info().Msg("firewall management disabled")
		return nil
	}

	if err := m.backend.Initialize(); err != nil {
		return fmt.Errorf("initializing firewall: %w", err)
	}

	if err := m.backend.SetDefaultPolicy("input", m.cfg.DefaultIn); err != nil {
		return fmt.Errorf("setting default input policy: %w", err)
	}
	if err := m.backend.SetDefaultPolicy("output", m.cfg.DefaultOut); err != nil {
		return fmt.Errorf("setting default output policy: %w", err)
	}

	for _, port := range m.cfg.ManagedPorts {
		rule := Rule{
			Table:    "filter",
			Chain:    "INPUT",
			Protocol: "tcp",
			Port:     port,
			Action:   "accept",
			Comment:  "Waffynx managed",
		}
		if err := m.backend.AddRule(rule); err != nil {
			logging.Warn().Err(err).Int("port", port).Msg("failed to add firewall rule")
		}
	}

	for _, ip := range m.cfg.BlockList {
		if err := m.BlockIP(ip); err != nil {
			logging.Warn().Err(err).Str("ip", ip).Msg("failed to block IP from blocklist")
		}
	}

	logging.Info().Str("backend", m.cfg.Backend).Msg("firewall initialized")
	return nil
}

func (m *Manager) BlockIP(ip string) error {
	rule := Rule{
		Table:    "filter",
		Chain:    "INPUT",
		Source:   ip,
		Action:   "drop",
		Comment:  "Waffynx block",
	}
	return m.backend.AddRule(rule)
}

func (m *Manager) UnblockIP(ip string) error {
	rule := Rule{
		Table:    "filter",
		Chain:    "INPUT",
		Source:   ip,
		Action:   "drop",
		Comment:  "Waffynx block",
	}
	return m.backend.RemoveRule(rule)
}

func (m *Manager) Rules() ([]Rule, error) {
	return m.backend.ListRules()
}

var runCmd = func(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func SetRunCmd(fn func(string, ...string) (string, error)) {
	runCmd = fn
}

// -- NFTables Backend --
type NFTablesBackend struct{}

func (n *NFTablesBackend) Initialize() error {
	cmds := [][]string{
		{"add", "table", "ip", "waffynx"},
		{"add", "chain", "ip", "waffynx", "input", "{ type filter hook input priority 0 ; }"},
	}
	for _, args := range cmds {
		if _, err := runCmd("nft", args...); err != nil {
			return fmt.Errorf("nft %v: %w", args, err)
		}
	}
	return nil
}

func (n *NFTablesBackend) AddRule(rule Rule) error {
	args := []string{"add", "rule", "ip", "waffynx", "input"}
	if rule.Protocol != "" {
		args = append(args, rule.Protocol, "dport", strconv.Itoa(rule.Port))
	}
	if rule.Source != "" {
		args = append(args, "ip", "saddr", rule.Source)
	}
	args = append(args, rule.Action)
	if rule.Comment != "" {
		args = append(args, "comment", fmt.Sprintf(`"%s"`, rule.Comment))
	}
	_, err := runCmd("nft", args...)
	return err
}

func (n *NFTablesBackend) RemoveRule(rule Rule) error {
	args := []string{"delete", "rule", "ip", "waffynx", "input"}
	if rule.Source != "" {
		args = append(args, "ip", "saddr", rule.Source, rule.Action)
	}
	_, err := runCmd("nft", args...)
	return err
}

func (n *NFTablesBackend) ListRules() ([]Rule, error) {
	out, err := runCmd("nft", "-a", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	return parseNFTRules(out), nil
}

func (n *NFTablesBackend) SetDefaultPolicy(chain string, policy string) error {
	_, err := runCmd("nft", "add", "rule", "ip", "waffynx", chain, "counter", policy)
	return err
}

func (n *NFTablesBackend) Flush() error {
	_, err := runCmd("nft", "flush", "ruleset")
	return err
}

// -- UFW Backend --
type UFWBackend struct{}

func (u *UFWBackend) Initialize() error {
	if _, err := runCmd("ufw", "--force", "enable"); err != nil {
		return fmt.Errorf("enabling ufw: %w", err)
	}
	return nil
}

func (u *UFWBackend) AddRule(rule Rule) error {
	args := []string{}
	switch rule.Action {
	case "accept":
		args = append(args, "allow")
	case "drop", "deny":
		args = append(args, "deny")
	}
	if rule.Port > 0 {
		args = append(args, strconv.Itoa(rule.Port))
		if rule.Protocol != "" {
			args = append(args, "/"+rule.Protocol)
		}
	}
	if rule.Source != "" {
		args = append(args, "from", rule.Source)
	}
	if rule.Comment != "" {
		args = append(args, "comment", rule.Comment)
	}
	_, err := runCmd("ufw", args...)
	return err
}

func (u *UFWBackend) RemoveRule(rule Rule) error {
	args := []string{"delete"}
	switch rule.Action {
	case "accept":
		args = append(args, "allow")
	case "drop", "deny":
		args = append(args, "deny")
	}
	if rule.Source != "" {
		args = append(args, "from", rule.Source)
	}
	if rule.Port > 0 {
		args = append(args, strconv.Itoa(rule.Port))
		if rule.Protocol != "" {
			args = append(args, "proto", rule.Protocol)
		}
	}
	if rule.Comment != "" {
		args = append(args, "comment", rule.Comment)
	}
	_, err := runCmd("ufw", args...)
	return err
}

func (u *UFWBackend) ListRules() ([]Rule, error) {
	out, err := runCmd("ufw", "status", "numbered")
	if err != nil {
		return nil, err
	}
	return parseUFWRules(out), nil
}

func (u *UFWBackend) SetDefaultPolicy(chain string, policy string) error {
	_, err := runCmd("ufw", "default", policy, chain)
	return err
}

func (u *UFWBackend) Flush() error {
	_, err := runCmd("ufw", "--force", "reset")
	return err
}

func parseNFTRules(output string) []Rule {
	var rules []Rule
	var currentTable string
	var currentChain string

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "table") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				currentTable = parts[1] + " " + parts[2]
			}
			continue
		}

		if strings.HasPrefix(trimmed, "chain") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				currentChain = parts[1]
			}
			continue
		}

		if trimmed == "{" || trimmed == "}" || trimmed == "" {
			continue
		}

		action := extractAction(trimmed)
		if action == "" {
			continue
		}

		rule := Rule{
			Table:  currentTable,
			Chain:  strings.ToUpper(currentChain),
			Action: action,
		}

		rule.Protocol = extractField(trimmed, "ip", "")
		if rule.Protocol == "" {
			rule.Protocol = extractField(trimmed, "tcp", "tcp")
			if rule.Protocol == "" {
				rule.Protocol = extractField(trimmed, "udp", "udp")
			}
		}

		rule.Port = extractPort(trimmed)
		rule.Source = extractSource(trimmed)
		rule.Comment = extractQuoted(trimmed)

		rules = append(rules, rule)
	}

	return rules
}

func parseUFWRules(output string) []Rule {
	var rules []Rule
	inRules := false

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)

		if !inRules {
			if strings.HasPrefix(trimmed, "--") {
				inRules = true
			}
			continue
		}

		trimmed = strings.TrimPrefix(trimmed, "[")
		if idx := strings.Index(trimmed, "]"); idx > 0 {
			trimmed = strings.TrimSpace(trimmed[idx+1:])
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}

		rule := Rule{
			Table: "filter",
			Chain: "INPUT",
		}

		portProto := fields[0]
		if portProto != "Anywhere" && portProto != "Anywhere(v6)" {
			if idx := strings.Index(portProto, "/"); idx > 0 {
				if p, err := strconv.Atoi(portProto[:idx]); err == nil {
					rule.Port = p
				}
				rule.Protocol = portProto[idx+1:]
			}
		}

		action := strings.ToLower(fields[1])
		if action == "allow" {
			rule.Action = "accept"
		} else if action == "deny" || action == "reject" {
			rule.Action = action
		}

		if len(fields) > 3 && fields[2] == "IN" && fields[3] != "Anywhere" && fields[3] != "Anywhere(v6)" {
			rule.Source = fields[3]
		}

		rules = append(rules, rule)
	}

	return rules
}

func extractAction(line string) string {
	for _, action := range []string{"accept", "drop", "deny", "reject", "log"} {
		if strings.Contains(line, " "+action) || strings.HasSuffix(line, " "+action) {
			return action
		}
	}
	return ""
}

func extractField(line, key, defaultValue string) string {
	words := strings.Fields(line)
	for i, w := range words {
		if w == key && i+1 < len(words) &&
			words[i+1] != "accept" && words[i+1] != "drop" &&
			words[i+1] != "deny" && words[i+1] != "reject" {
			return words[i+1]
		}
	}
	return defaultValue
}

func extractPort(line string) int {
	words := strings.Fields(line)
	for i, w := range words {
		if w == "dport" && i+1 < len(words) {
			if port, err := strconv.Atoi(words[i+1]); err == nil {
				return port
			}
		}
	}
	return 0
}

func extractSource(line string) string {
	words := strings.Fields(line)
	for i, w := range words {
		if w == "saddr" && i+1 < len(words) {
			return words[i+1]
		}
	}
	return ""
}

func extractQuoted(line string) string {
	start := strings.Index(line, "\"")
	if start < 0 {
		return ""
	}
	end := strings.Index(line[start+1:], "\"")
	if end < 0 {
		return ""
	}
	return line[start+1 : start+1+end]
}
