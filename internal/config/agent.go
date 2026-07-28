package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type AgentConfig struct {
	Name     string         `yaml:"name"`
	Listen   string         `yaml:"listen"`
	APIKey   string         `yaml:"api_key"`
	Firewall FirewallConfig `yaml:"firewall"`
}

func LoadAgent(path string) (*AgentConfig, error) {
	cfg := &AgentConfig{
		Name:   "waf-agent",
		Listen: ":9099",
		Firewall: FirewallConfig{
			Enabled:    true,
			Backend:    "nftables",
			DefaultIn:  "deny",
			DefaultOut: "allow",
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
