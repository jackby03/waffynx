package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Name     string          `yaml:"name"`
	Version  string          `yaml:"version"`
	Listen   string          `yaml:"listen"`
	Logging  LoggingConfig   `yaml:"logging"`
	Sidecar  SidecarConfig   `yaml:"sidecar"`
	Nginx    NginxConfig     `yaml:"nginx"`
	AppSec   AppSecConfig    `yaml:"appsec"`
	Gateway  GatewayConfig   `yaml:"gateway"`
	TLS      TLSGlobalConfig `yaml:"tls"`
	Routes   []RouteConfig   `yaml:"routes"`
	Plugins  []PluginConfig  `yaml:"plugins"`
	Firewall FirewallConfig  `yaml:"firewall"`
	API      APIConfig       `yaml:"api"`
}

type SidecarConfig struct {
	SocketPath  string `yaml:"socket_path"`
	FailOpen    bool   `yaml:"fail_open"`
	TimeoutMs   int    `yaml:"timeout_ms"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

type NginxConfig struct {
	BinaryPath     string `yaml:"binary_path"`
	ConfigPath     string `yaml:"config_path"`
	WorkerProcesses int  `yaml:"worker_processes"`
	WorkerConnections int `yaml:"worker_connections"`
	EnableHTTP2    bool   `yaml:"enable_http2"`
	EnableHTTP3    bool   `yaml:"enable_http3"`
}

type AppSecConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Engine       string `yaml:"engine"`        // "basic-go" or "open-appsec"
	RulesPath    string `yaml:"rules_path"`
	MLModelPath  string `yaml:"ml_model_path"`
	LearningMode bool   `yaml:"learning_mode"`
	BridgeSocket string `yaml:"bridge_socket"` // Unix socket for open-appsec bridge
	TimeoutMs    int    `yaml:"timeout_ms"`    // bridge timeout
}

type GatewayConfig struct {
	MaxConnections     int  `yaml:"max_connections"`
	ReadTimeout        int  `yaml:"read_timeout"`
	WriteTimeout       int  `yaml:"write_timeout"`
	IdleTimeout        int  `yaml:"idle_timeout"`
	EnableRateLimiting bool `yaml:"enable_rate_limiting"`
}

type RouteConfig struct {
	Name       string            `yaml:"name"`
	Host       string            `yaml:"host"`
	Path       string            `yaml:"path"`
	Methods    []string          `yaml:"methods"`
	Upstream   string            `yaml:"upstream"`
	TLS        *TLSConfig        `yaml:"tls,omitempty"`
	Plugins    []string          `yaml:"plugins"`
	Headers    map[string]string `yaml:"headers,omitempty"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type TLSGlobalConfig struct {
	StaticCert string `yaml:"static_cert"`
	StaticKey  string `yaml:"static_key"`
	ACME       struct {
		Enabled  bool     `yaml:"enabled"`
		Domains  []string `yaml:"domains"`
		Email    string   `yaml:"email"`
		CacheDir string   `yaml:"cache_dir"`
		Staging  bool     `yaml:"staging"`
	} `yaml:"acme"`
}

type PluginConfig struct {
	Name    string                 `yaml:"name"`
	Enabled bool                   `yaml:"enabled"`
	Config  map[string]interface{} `yaml:"config"`
}

type FirewallConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Backend      string   `yaml:"backend"`       // ufw, nftables
	DefaultIn    string   `yaml:"default_in"`    // deny, allow
	DefaultOut   string   `yaml:"default_out"`   // deny, allow
	ManagedPorts []int    `yaml:"managed_ports"`
	BlockList    []string `yaml:"block_list"`    // IPs to block at startup
}

type APIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Auth    AuthConfig `yaml:"auth"`
}

type AuthConfig struct {
	JWTSecret string `yaml:"jwt_secret"`
	TokenTTL  int    `yaml:"token_ttl"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{
		Name:    "waffynx",
		Version: "1",
		Listen:  ":8443",
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Sidecar: SidecarConfig{
			SocketPath: "/var/run/waffynx.sock",
			FailOpen:   true,
			TimeoutMs:  100,
		},
		Nginx: NginxConfig{
			BinaryPath:        "/opt/waffynx/nginx/sbin/nginx",
			ConfigPath:        "/opt/waffynx/nginx/conf",
			WorkerProcesses:   0,
			WorkerConnections: 65535,
			EnableHTTP2:       true,
		},
		Gateway: GatewayConfig{
			MaxConnections: 65535,
			ReadTimeout:    60,
			WriteTimeout:   60,
			IdleTimeout:    120,
		},
		AppSec: AppSecConfig{
			Enabled:      false,
			Engine:       "basic-go",
			BridgeSocket: "/var/run/open-appsec.sock",
			TimeoutMs:    200,
		},
		Firewall: FirewallConfig{
			Backend:    "nftables",
			DefaultIn:  "deny",
			DefaultOut: "allow",
		},
		API: APIConfig{
			Listen: ":9090",
			Auth: AuthConfig{
				TokenTTL: 3600,
			},
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.Firewall.Backend != "ufw" && c.Firewall.Backend != "nftables" {
		return fmt.Errorf("firewall backend must be 'ufw' or 'nftables', got: %s", c.Firewall.Backend)
	}
	return nil
}
