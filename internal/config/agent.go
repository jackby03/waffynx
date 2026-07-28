package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type EventBrokerConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Address        string `yaml:"address"`
	BlockThreshold int    `yaml:"block_threshold"`
	WindowSeconds  int    `yaml:"window_seconds"`
}

type AgentConfig struct {
	Name        string            `yaml:"name"`
	Listen      string            `yaml:"listen"`
	APIKey      string            `yaml:"api_key"`
	EventBroker EventBrokerConfig `yaml:"event_broker"`
	Firewall    FirewallConfig    `yaml:"firewall"`
}

func LoadAgent(path string) (*AgentConfig, error) {
	cfg := &AgentConfig{
		Name:   "waf-agent",
		Listen: ":9099",
		EventBroker: EventBrokerConfig{
			Address:        "http://localhost:9090",
			BlockThreshold: 10,
			WindowSeconds:  60,
		},
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
