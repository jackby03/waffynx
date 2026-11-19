package config

import (
	"strconv"
	"strings"
)

// DistributedConfig holds optional multi-container orchestration settings for
// Docker Compose and Kubernetes deployments (Constitution §1.3 & §2.1).
// Zero values keep single-container / standalone behavior unchanged.
type DistributedConfig struct {
	Postgres   PostgresConfig   `yaml:"postgres"`
	Redis      RedisConfig      `yaml:"redis"`
	NATS       NATSConfig       `yaml:"nats"`
	ClickHouse ClickHouseConfig `yaml:"clickhouse"`
	XDS        XDSConfig        `yaml:"xds"`
	MTLS       MTLSConfig       `yaml:"mtls"`
	Engine     EngineGRPCConfig `yaml:"engine"`
}

type PostgresConfig struct {
	Enabled bool   `yaml:"enabled"`
	DSN     string `yaml:"dsn"`
}

type RedisConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Addr      string `yaml:"addr"`
	Password  string `yaml:"password"`
	DB        int    `yaml:"db"`
	TimeoutMs int    `yaml:"timeout_ms"`
	FailOpen  bool   `yaml:"fail_open"`
}

type NATSConfig struct {
	Enabled       bool   `yaml:"enabled"`
	URL           string `yaml:"url"`
	Token         string `yaml:"token"`
	StreamName    string `yaml:"stream_name"`
	SubjectPrefix string `yaml:"subject_prefix"`
	BufferSize    int    `yaml:"buffer_size"`
}

type ClickHouseConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	Database string `yaml:"database"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type XDSConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Listen           string `yaml:"listen"`
	HTTPPort         uint32 `yaml:"http_port"`
	HTTPSPort        uint32 `yaml:"https_port"`
	WAFEngineHost    string `yaml:"waf_engine_host"`
	WAFEnginePort    uint32 `yaml:"waf_engine_port"`
	EnableExtAuthz   bool   `yaml:"enable_ext_authz"`
	EnableExtProc    bool   `yaml:"enable_ext_proc"`
	FailureModeAllow bool   `yaml:"failure_mode_allow"`
	EdgeTLS          bool   `yaml:"edge_tls"`
	UpstreamMTLS     bool   `yaml:"upstream_mtls"`
}

type MTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertDir  string `yaml:"cert_dir"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

type EngineGRPCConfig struct {
	GRPCListen       string `yaml:"grpc_listen"`
	HealthListen     string `yaml:"health_listen"`
	NodeID           string `yaml:"node_id"`
	MaxBodyBytes     int    `yaml:"max_body_bytes"`
	ShadowMode       bool   `yaml:"shadow_mode"`
	RateLimitEnabled bool   `yaml:"rate_limit_enabled"`
	RateLimitRPS     int    `yaml:"rate_limit_rps"`
	GeoIPDBPath      string `yaml:"geoip_db_path"`
}

// ApplyDistributedEnv overlays multi-container environment variables onto cfg.Distributed.
func ApplyDistributedEnv(cfg *Config, getenv func(string) string) {
	if cfg == nil {
		return
	}
	getenv = envLookup(getenv)
	d := &cfg.Distributed

	if v := envValue(getenv, "WAFFYNX_POSTGRES_DSN"); v != "" {
		d.Postgres.Enabled = true
		d.Postgres.DSN = v
	}
	if v := envValue(getenv, "WAFFYNX_REDIS_ADDR"); v != "" {
		d.Redis.Enabled = true
		d.Redis.Addr = v
	}
	if v := envValue(getenv, "WAFFYNX_REDIS_PASSWORD"); v != "" {
		d.Redis.Password = v
	}
	if v := envValue(getenv, "WAFFYNX_REDIS_TIMEOUT_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			d.Redis.TimeoutMs = n
		}
	}
	if parseBoolEnv(getenv("WAFFYNX_RATE_LIMIT_FAIL_OPEN")) {
		d.Redis.FailOpen = true
	}
	if v := envValue(getenv, "WAFFYNX_NATS_URL"); v != "" {
		d.NATS.Enabled = true
		d.NATS.URL = v
	}
	if v := envValue(getenv, "WAFFYNX_NATS_TOKEN"); v != "" {
		d.NATS.Token = v
	}
	if v := envValue(getenv, "WAFFYNX_CLICKHOUSE_URL"); v != "" {
		d.ClickHouse.Enabled = true
		d.ClickHouse.URL = v
	}
	if v := envValue(getenv, "WAFFYNX_CLICKHOUSE_DB"); v != "" {
		d.ClickHouse.Database = v
	}
	if v := envValue(getenv, "WAFFYNX_CLICKHOUSE_USER"); v != "" {
		d.ClickHouse.Username = v
	}
	if v := envValue(getenv, "WAFFYNX_CLICKHOUSE_PASSWORD"); v != "" {
		d.ClickHouse.Password = v
	}
	if v := envValue(getenv, "WAFFYNX_XDS_LISTEN"); v != "" {
		d.XDS.Enabled = true
		d.XDS.Listen = v
		d.XDS.EnableExtAuthz = true
		d.XDS.EnableExtProc = true
	}
	if v := envValue(getenv, "WAFFYNX_WAF_ENGINE_HOST"); v != "" {
		d.XDS.WAFEngineHost = v
	}
	if v := envValue(getenv, "WAFFYNX_WAF_ENGINE_PORT"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil && n > 0 && n <= 65535 {
			d.XDS.WAFEnginePort = uint32(n)
		}
	}
	if parseBoolEnv(getenv("WAFFYNX_EDGE_TLS")) {
		d.XDS.EdgeTLS = true
	}
	if parseBoolEnv(getenv("WAFFYNX_UPSTREAM_MTLS")) {
		d.XDS.UpstreamMTLS = true
	}
	if parseBoolEnv(getenv("WAFFYNX_MTLS_ENABLED")) {
		d.MTLS.Enabled = true
	}
	if v := envValue(getenv, "WAFFYNX_CERT_DIR"); v != "" {
		d.MTLS.CertDir = v
	}
	if v := envValue(getenv, "WAFFYNX_ENGINE_GRPC_LISTEN"); v != "" {
		d.Engine.GRPCListen = v
	}
	if v := envValue(getenv, "WAFFYNX_ENGINE_HEALTH_LISTEN"); v != "" {
		d.Engine.HealthListen = v
	}
	if v := envValue(getenv, "WAFFYNX_NODE_ID"); v != "" {
		d.Engine.NodeID = v
	}
	if v := envValue(getenv, "WAFFYNX_MAX_BODY_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			d.Engine.MaxBodyBytes = n
		}
	}
	if parseBoolEnv(getenv("WAFFYNX_SHADOW_MODE")) {
		d.Engine.ShadowMode = true
	}
	if parseBoolEnv(getenv("WAFFYNX_RATE_LIMIT_ENABLED")) {
		d.Engine.RateLimitEnabled = true
	}
	if v := envValue(getenv, "WAFFYNX_RATE_LIMIT_RPS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			d.Engine.RateLimitRPS = n
		}
	}
	if v := envValue(getenv, "WAFFYNX_GEOIP_DB"); v != "" {
		d.Engine.GeoIPDBPath = v
	}
}

func parseBoolEnv(raw string) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	return s == "1" || s == "true" || s == "yes"
}
