-- Waffynx Control Plane PostgreSQL Schema (Phase 1 & Phase 3 Zero Trust)
-- Executed idempotently on startup by PostgresStore.Migrate.

CREATE TABLE IF NOT EXISTS sites (
    host        TEXT PRIMARY KEY,
    upstream    TEXT NOT NULL,
    tls_cert    TEXT NOT NULL DEFAULT '',
    tls_key     TEXT NOT NULL DEFAULT '',
    paths_json  JSONB NOT NULL DEFAULT '[]'::jsonb,
    plugins_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    headers_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS custom_rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    priority    INTEGER NOT NULL DEFAULT 100,
    action      TEXT NOT NULL DEFAULT 'block',
    spec_json   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_custom_rules_priority ON custom_rules (priority, id);

CREATE TABLE IF NOT EXISTS exclusions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    host        TEXT NOT NULL DEFAULT '',
    path_exact  TEXT NOT NULL DEFAULT '',
    path_prefix TEXT NOT NULL DEFAULT '',
    param       TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_exclusions_rule_id ON exclusions (rule_id);

CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    scopes        TEXT[] NOT NULL DEFAULT ARRAY['read']::TEXT[],
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_bans (
    ip          TEXT PRIMARY KEY,
    reason      TEXT NOT NULL DEFAULT '',
    ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_bans_expires ON ip_bans (expires_at);

CREATE TABLE IF NOT EXISTS zt_policies (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    host                  TEXT NOT NULL DEFAULT '',
    path_prefix           TEXT NOT NULL DEFAULT '/',
    enabled               BOOLEAN NOT NULL DEFAULT TRUE,
    priority              INTEGER NOT NULL DEFAULT 100,
    require_jwt           BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_issuers       TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    required_scopes       TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    allowed_cidrs         TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    blocked_countries     TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    require_device_header TEXT NOT NULL DEFAULT '',
    shadow_mode           BOOLEAN NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_zt_policies_priority ON zt_policies (priority, id);

CREATE TABLE IF NOT EXISTS config_revisions (
    revision   BIGSERIAL PRIMARY KEY,
    kind       TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
