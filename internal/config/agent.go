package config

type AgentConfig struct {
	Name     string         `yaml:"name"`
	Firewall FirewallConfig `yaml:"firewall"`
}

func LoadAgent(path string) (*AgentConfig, error) {
	cfg := &AgentConfig{
		Name: "waf-agent",
		Firewall: FirewallConfig{
			Enabled:    true,
			Backend:    "nftables",
			DefaultIn:  "deny",
			DefaultOut: "allow",
		},
	}
	return cfg, nil
}
