package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse_DefaultValues(t *testing.T) {
	// Parsing empty YAML should result in default configuration
	yamlData := []byte(``)

	cfg, err := Parse(yamlData)
	if err != nil {
		t.Fatalf("unexpected error parsing empty YAML: %v", err)
	}

	if cfg.Name != "waffynx" {
		t.Errorf("expected default Name 'waffynx', got %q", cfg.Name)
	}
	if cfg.Listen != ":8443" {
		t.Errorf("expected default Listen ':8443', got %q", cfg.Listen)
	}
	if cfg.Logging.Level != "info" || cfg.Logging.Format != "json" {
		t.Errorf("unexpected default Logging config: %+v", cfg.Logging)
	}
	if cfg.Sidecar.SocketPath != "/var/run/waffynx.sock" || !cfg.Sidecar.FailOpen {
		t.Errorf("unexpected default Sidecar config: %+v", cfg.Sidecar)
	}
	if cfg.Firewall.Backend != "nftables" {
		t.Errorf("expected default Firewall Backend 'nftables', got %q", cfg.Firewall.Backend)
	}
	if cfg.API.Listen != ":9090" || cfg.API.Auth.TokenTTL != 3600 {
		t.Errorf("unexpected default API config: %+v", cfg.API)
	}
}

func TestParse_CustomYAML(t *testing.T) {
	yamlData := []byte(`
name: custom-waf
version: "2"
listen: ":443"
logging:
  level: debug
  format: console
  output: /var/log/waffynx.log
sidecar:
  socket_path: /tmp/test.sock
  fail_open: false
  timeout_ms: 50
firewall:
  backend: ufw
  default_in: deny
  default_out: allow
  block_list:
    - 1.2.3.4
api:
  enabled: true
  listen: ":9091"
  allowed_origins:
    - "http://localhost:3000"
`)

	cfg, err := Parse(yamlData)
	if err != nil {
		t.Fatalf("unexpected error parsing custom YAML: %v", err)
	}

	if cfg.Name != "custom-waf" {
		t.Errorf("expected Name 'custom-waf', got %q", cfg.Name)
	}
	if cfg.Listen != ":443" {
		t.Errorf("expected Listen ':443', got %q", cfg.Listen)
	}
	if cfg.Logging.Level != "debug" || cfg.Logging.Format != "console" {
		t.Errorf("unexpected Logging config: %+v", cfg.Logging)
	}
	if cfg.Sidecar.SocketPath != "/tmp/test.sock" || cfg.Sidecar.FailOpen != false {
		t.Errorf("unexpected Sidecar config: %+v", cfg.Sidecar)
	}
	if cfg.Firewall.Backend != "ufw" || len(cfg.Firewall.BlockList) != 1 || cfg.Firewall.BlockList[0] != "1.2.3.4" {
		t.Errorf("unexpected Firewall config: %+v", cfg.Firewall)
	}
	if !cfg.API.Enabled || cfg.API.Listen != ":9091" {
		t.Errorf("unexpected API config: %+v", cfg.API)
	}
}

func TestParse_Errors(t *testing.T) {
	tests := []struct {
		name      string
		yamlData  string
		errSubstr string
	}{
		{
			name:      "invalid yaml syntax",
			yamlData:  "name: [invalid yaml syntax",
			errSubstr: "parsing config file",
		},
		{
			name:      "empty listen address",
			yamlData:  "listen: ''",
			errSubstr: "listen address is required",
		},
		{
			name: "invalid firewall backend",
			yamlData: `
firewall:
  backend: iptables
`,
			errSubstr: "firewall backend must be 'ufw' or 'nftables'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tt.yamlData))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil (cfg: %+v)", tt.errSubstr, cfg)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("valid config file", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "config.yaml")
		content := []byte(`
name: test-load
listen: ":8080"
firewall:
  backend: ufw
`)
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		cfg, err := Load(filePath)
		if err != nil {
			t.Fatalf("unexpected error loading config: %v", err)
		}
		if cfg.Name != "test-load" || cfg.Listen != ":8080" || cfg.Firewall.Backend != "ufw" {
			t.Errorf("loaded config values mismatch: %+v", cfg)
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := Load(filepath.Join(tempDir, "non_existent.yaml"))
		if err == nil {
			t.Error("expected error for non-existent file, got nil")
		}
	})
}

func TestLoadAgent(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("valid agent config file", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "agent.yaml")
		content := []byte(`
name: custom-agent
listen: ":9100"
api_key: secret123
event_broker:
  enabled: true
  address: "http://localhost:9090"
firewall:
  backend: ufw
`)
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		cfg, err := LoadAgent(filePath)
		if err != nil {
			t.Fatalf("unexpected error loading agent config: %v", err)
		}
		if cfg.Name != "custom-agent" || cfg.Listen != ":9100" || cfg.APIKey != "secret123" {
			t.Errorf("loaded agent config values mismatch: %+v", cfg)
		}
		if !cfg.EventBroker.Enabled || cfg.Firewall.Backend != "ufw" {
			t.Errorf("loaded agent nested config values mismatch: %+v", cfg)
		}
	})

	t.Run("non-existent agent file", func(t *testing.T) {
		_, err := LoadAgent(filepath.Join(tempDir, "non_existent_agent.yaml"))
		if err == nil {
			t.Error("expected error for non-existent agent file, got nil")
		}
	})

	t.Run("invalid agent yaml syntax", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "invalid_agent.yaml")
		if err := os.WriteFile(filePath, []byte("name: [invalid"), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, err := LoadAgent(filePath)
		if err == nil {
			t.Error("expected error for invalid agent yaml, got nil")
		}
	})
}
