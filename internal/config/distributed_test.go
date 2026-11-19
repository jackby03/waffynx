package config

import "testing"

func TestApplyDistributedEnv(t *testing.T) {
	// Nil safety.
	ApplyDistributedEnv(nil, nil)

	env := map[string]string{
		"WAFFYNX_POSTGRES_DSN":         "postgres://postgres:5432/waffynx",
		"WAFFYNX_REDIS_ADDR":           "redis:6379",
		"WAFFYNX_REDIS_PASSWORD":       "rpass",
		"WAFFYNX_REDIS_TIMEOUT_MS":     "8",
		"WAFFYNX_RATE_LIMIT_FAIL_OPEN": "true",
		"WAFFYNX_NATS_URL":             "nats://nats:4222",
		"WAFFYNX_NATS_TOKEN":           "ntok",
		"WAFFYNX_CLICKHOUSE_URL":       "http://clickhouse:8123",
		"WAFFYNX_CLICKHOUSE_DB":        "waffynx",
		"WAFFYNX_CLICKHOUSE_USER":      "default",
		"WAFFYNX_CLICKHOUSE_PASSWORD":  "chpass",
		"WAFFYNX_XDS_LISTEN":           ":18000",
		"WAFFYNX_WAF_ENGINE_HOST":      "waf-engine",
		"WAFFYNX_WAF_ENGINE_PORT":      "50051",
		"WAFFYNX_EDGE_TLS":             "1",
		"WAFFYNX_UPSTREAM_MTLS":        "yes",
		"WAFFYNX_MTLS_ENABLED":         "true",
		"WAFFYNX_CERT_DIR":             "/etc/waffynx/certs",
		"WAFFYNX_ENGINE_GRPC_LISTEN":   ":50051",
		"WAFFYNX_ENGINE_HEALTH_LISTEN": ":8081",
		"WAFFYNX_NODE_ID":              "waf-engine-1",
		"WAFFYNX_MAX_BODY_BYTES":       "1048576",
		"WAFFYNX_SHADOW_MODE":          "true",
		"WAFFYNX_RATE_LIMIT_ENABLED":   "true",
		"WAFFYNX_RATE_LIMIT_RPS":       "120",
		"WAFFYNX_GEOIP_DB":             "/data/GeoLite2-Country.mmdb",
	}

	cfg := defaultConfig()
	ApplyDistributedEnv(cfg, func(k string) string { return env[k] })

	d := cfg.Distributed
	if !d.Postgres.Enabled || d.Postgres.DSN != env["WAFFYNX_POSTGRES_DSN"] {
		t.Fatalf("postgres env mismatch: %+v", d.Postgres)
	}
	if !d.Redis.Enabled || d.Redis.TimeoutMs != 8 || !d.Redis.FailOpen || d.Redis.Password != "rpass" {
		t.Fatalf("redis env mismatch: %+v", d.Redis)
	}
	if !d.NATS.Enabled || d.NATS.Token != "ntok" {
		t.Fatalf("nats env mismatch: %+v", d.NATS)
	}
	if !d.ClickHouse.Enabled || d.ClickHouse.Database != "waffynx" || d.ClickHouse.Password != "chpass" {
		t.Fatalf("clickhouse env mismatch: %+v", d.ClickHouse)
	}
	if !d.XDS.Enabled || d.XDS.Listen != ":18000" || d.XDS.WAFEnginePort != 50051 || !d.XDS.EdgeTLS || !d.XDS.UpstreamMTLS {
		t.Fatalf("xds env mismatch: %+v", d.XDS)
	}
	if !d.MTLS.Enabled || d.MTLS.CertDir != "/etc/waffynx/certs" {
		t.Fatalf("mtls env mismatch: %+v", d.MTLS)
	}
	if d.Engine.GRPCListen != ":50051" || d.Engine.HealthListen != ":8081" || d.Engine.NodeID != "waf-engine-1" ||
		d.Engine.MaxBodyBytes != 1048576 || !d.Engine.ShadowMode || !d.Engine.RateLimitEnabled ||
		d.Engine.RateLimitRPS != 120 || d.Engine.GeoIPDBPath != "/data/GeoLite2-Country.mmdb" {
		t.Fatalf("engine env mismatch: %+v", d.Engine)
	}
}
