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

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
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
	out, err := runCmd("nft", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	_ = out
	return nil, nil
}

func (n *NFTablesBackend) SetDefaultPolicy(chain string, policy string) error {
	return nil
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
	if rule.Port > 0 {
		args = append(args, strconv.Itoa(rule.Port))
	}
	_, err := runCmd("ufw", args...)
	return err
}

func (u *UFWBackend) ListRules() ([]Rule, error) {
	out, err := runCmd("ufw", "status", "numbered")
	if err != nil {
		return nil, err
	}
	_ = out
	return nil, nil
}

func (u *UFWBackend) SetDefaultPolicy(chain string, policy string) error {
	_, err := runCmd("ufw", "default", policy, chain)
	return err
}

func (u *UFWBackend) Flush() error {
	_, err := runCmd("ufw", "--force", "reset")
	return err
}
