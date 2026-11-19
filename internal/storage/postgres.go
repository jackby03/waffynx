package storage

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/sites"
)

//go:embed migrations/001_init.sql
var initialMigrationSQL string

// PostgresStore implements Store on PostgreSQL via pgxpool (pure Go, CGO_ENABLED=0).
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects to PostgreSQL, verifies reachability, and applies
// idempotent schema migrations.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("postgres DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing postgres DSN: %w", err)
	}
	cfg.MaxConns = 16
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating postgres pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}

	ps := &PostgresStore{pool: pool}
	if err := ps.Migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("applying postgres schema: %w", err)
	}
	return ps, nil
}

// Migrate runs the embedded idempotent DDL migrations.
func (p *PostgresStore) Migrate(ctx context.Context) error {
	opCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := p.pool.Exec(opCtx, initialMigrationSQL)
	return err
}

func (p *PostgresStore) Ping(ctx context.Context) error {
	opCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return p.pool.Ping(opCtx)
}

func (p *PostgresStore) Close() error {
	if p.pool != nil {
		p.pool.Close()
	}
	return nil
}

// --- Sites ---

func (p *PostgresStore) ListSites(ctx context.Context) ([]sites.Site, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT host, upstream, tls_cert, tls_key, paths_json, plugins_json, headers_json
		FROM sites ORDER BY host ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]sites.Site, 0)
	for rows.Next() {
		s, scanErr := scanSite(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *PostgresStore) GetSite(ctx context.Context, host string) (sites.Site, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT host, upstream, tls_cert, tls_key, paths_json, plugins_json, headers_json
		FROM sites WHERE LOWER(host) = LOWER($1)`, sites.NormalizeHost(host))
	s, err := scanSite(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return sites.Site{}, ErrNotFound
	}
	return s, err
}

type siteScanner interface {
	Scan(dest ...any) error
}

func scanSite(sc siteScanner) (sites.Site, error) {
	var (
		s          sites.Site
		tlsCert    string
		tlsKey     string
		pathsRaw   []byte
		pluginsRaw []byte
		headersRaw []byte
	)
	if err := sc.Scan(&s.Host, &s.Upstream, &tlsCert, &tlsKey, &pathsRaw, &pluginsRaw, &headersRaw); err != nil {
		return sites.Site{}, err
	}
	if tlsCert != "" || tlsKey != "" {
		s.TLS = &sites.TLSPair{CertFile: tlsCert, KeyFile: tlsKey}
	}
	if len(pathsRaw) > 0 {
		_ = json.Unmarshal(pathsRaw, &s.Paths)
	}
	if len(pluginsRaw) > 0 {
		_ = json.Unmarshal(pluginsRaw, &s.Plugins)
	}
	if len(headersRaw) > 0 {
		_ = json.Unmarshal(headersRaw, &s.Headers)
	}
	return s, nil
}

func (p *PostgresStore) UpsertSite(ctx context.Context, site sites.Site, replace bool) error {
	host := sites.NormalizeHost(site.Host)
	tlsCert, tlsKey := "", ""
	if site.TLS != nil {
		tlsCert = site.TLS.CertFile
		tlsKey = site.TLS.KeyFile
	}
	pathsJSON, _ := json.Marshal(site.Paths)
	if len(site.Paths) == 0 {
		pathsJSON = []byte("[]")
	}
	pluginsJSON, _ := json.Marshal(site.Plugins)
	if len(site.Plugins) == 0 {
		pluginsJSON = []byte("[]")
	}
	headersJSON, _ := json.Marshal(site.Headers)
	if len(site.Headers) == 0 {
		headersJSON = []byte("{}")
	}

	if !replace {
		tag, err := p.pool.Exec(ctx, `
			INSERT INTO sites (host, upstream, tls_cert, tls_key, paths_json, plugins_json, headers_json)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (host) DO NOTHING`,
			host, site.Upstream, tlsCert, tlsKey, pathsJSON, pluginsJSON, headersJSON)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrConflict
		}
		return nil
	}

	_, err := p.pool.Exec(ctx, `
		INSERT INTO sites (host, upstream, tls_cert, tls_key, paths_json, plugins_json, headers_json, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (host) DO UPDATE SET
			upstream = EXCLUDED.upstream,
			tls_cert = EXCLUDED.tls_cert,
			tls_key = EXCLUDED.tls_key,
			paths_json = EXCLUDED.paths_json,
			plugins_json = EXCLUDED.plugins_json,
			headers_json = EXCLUDED.headers_json,
			updated_at = NOW()`,
		host, site.Upstream, tlsCert, tlsKey, pathsJSON, pluginsJSON, headersJSON)
	return err
}

func (p *PostgresStore) DeleteSite(ctx context.Context, host string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM sites WHERE LOWER(host) = LOWER($1)`, sites.NormalizeHost(host))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Custom Rules ---

func (p *PostgresStore) ListCustomRules(ctx context.Context) ([]rules.CustomRule, error) {
	rows, err := p.pool.Query(ctx, `SELECT spec_json FROM custom_rules ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]rules.CustomRule, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r rules.CustomRule
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *PostgresStore) UpsertCustomRule(ctx context.Context, rule rules.CustomRule) (rules.CustomRule, error) {
	if rule.ID == "" {
		rule.ID = "rule-" + uuid.NewString()[:8]
	}
	raw, err := json.Marshal(rule)
	if err != nil {
		return rules.CustomRule{}, err
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO custom_rules (id, name, description, enabled, priority, action, spec_json, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			enabled = EXCLUDED.enabled,
			priority = EXCLUDED.priority,
			action = EXCLUDED.action,
			spec_json = EXCLUDED.spec_json,
			updated_at = NOW()`,
		rule.ID, rule.Name, rule.Description, rule.Enabled, rule.Priority, string(rule.Action), raw)
	return rule, err
}

func (p *PostgresStore) DeleteCustomRule(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM custom_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Exclusions ---

func (p *PostgresStore) ListExclusions(ctx context.Context) ([]rules.Exclusion, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, name, rule_id, host, path_exact, path_prefix, param, reason, enabled, created_at
		FROM exclusions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]rules.Exclusion, 0)
	for rows.Next() {
		var ex rules.Exclusion
		if err := rows.Scan(&ex.ID, &ex.Name, &ex.RuleID, &ex.Host, &ex.PathExact, &ex.PathPrefix, &ex.Param, &ex.Reason, &ex.Enabled, &ex.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, ex)
	}
	return out, rows.Err()
}

func (p *PostgresStore) CreateExclusion(ctx context.Context, ex rules.Exclusion) (rules.Exclusion, error) {
	if ex.ID == "" {
		ex.ID = "ex-" + uuid.NewString()[:8]
	}
	if ex.CreatedAt.IsZero() {
		ex.CreatedAt = time.Now().UTC()
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO exclusions (id, name, rule_id, host, path_exact, path_prefix, param, reason, enabled, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			rule_id = EXCLUDED.rule_id,
			host = EXCLUDED.host,
			path_exact = EXCLUDED.path_exact,
			path_prefix = EXCLUDED.path_prefix,
			param = EXCLUDED.param,
			reason = EXCLUDED.reason,
			enabled = EXCLUDED.enabled`,
		ex.ID, ex.Name, ex.RuleID, ex.Host, ex.PathExact, ex.PathPrefix, ex.Param, ex.Reason, ex.Enabled, ex.CreatedAt)
	return ex, err
}

func (p *PostgresStore) DeleteExclusion(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM exclusions WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Zero-Trust Policies ---

func (p *PostgresStore) ListZTPolicies(ctx context.Context) ([]ZeroTrustPolicy, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, name, host, path_prefix, enabled, priority, require_jwt,
		       allowed_issuers, required_scopes, allowed_cidrs, blocked_countries,
		       require_device_header, shadow_mode, created_at, updated_at
		FROM zt_policies ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ZeroTrustPolicy, 0)
	for rows.Next() {
		var z ZeroTrustPolicy
		if err := rows.Scan(
			&z.ID, &z.Name, &z.Host, &z.PathPrefix, &z.Enabled, &z.Priority, &z.RequireJWT,
			&z.AllowedIssuers, &z.RequiredScopes, &z.AllowedCIDRs, &z.BlockedCountries,
			&z.RequireDeviceHeader, &z.ShadowMode, &z.CreatedAt, &z.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

func (p *PostgresStore) UpsertZTPolicy(ctx context.Context, z ZeroTrustPolicy) (ZeroTrustPolicy, error) {
	now := time.Now().UTC()
	if z.ID == "" {
		z.ID = "zt-" + uuid.NewString()[:8]
	}
	if z.PathPrefix == "" {
		z.PathPrefix = "/"
	}
	if z.CreatedAt.IsZero() {
		z.CreatedAt = now
	}
	z.UpdatedAt = now
	if z.AllowedIssuers == nil {
		z.AllowedIssuers = []string{}
	}
	if z.RequiredScopes == nil {
		z.RequiredScopes = []string{}
	}
	if z.AllowedCIDRs == nil {
		z.AllowedCIDRs = []string{}
	}
	if z.BlockedCountries == nil {
		z.BlockedCountries = []string{}
	}

	_, err := p.pool.Exec(ctx, `
		INSERT INTO zt_policies (
			id, name, host, path_prefix, enabled, priority, require_jwt,
			allowed_issuers, required_scopes, allowed_cidrs, blocked_countries,
			require_device_header, shadow_mode, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			host = EXCLUDED.host,
			path_prefix = EXCLUDED.path_prefix,
			enabled = EXCLUDED.enabled,
			priority = EXCLUDED.priority,
			require_jwt = EXCLUDED.require_jwt,
			allowed_issuers = EXCLUDED.allowed_issuers,
			required_scopes = EXCLUDED.required_scopes,
			allowed_cidrs = EXCLUDED.allowed_cidrs,
			blocked_countries = EXCLUDED.blocked_countries,
			require_device_header = EXCLUDED.require_device_header,
			shadow_mode = EXCLUDED.shadow_mode,
			updated_at = NOW()`,
		z.ID, z.Name, z.Host, z.PathPrefix, z.Enabled, z.Priority, z.RequireJWT,
		z.AllowedIssuers, z.RequiredScopes, z.AllowedCIDRs, z.BlockedCountries,
		z.RequireDeviceHeader, z.ShadowMode, z.CreatedAt, z.UpdatedAt)
	return z, err
}

func (p *PostgresStore) DeleteZTPolicy(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM zt_policies WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Users ---

func (p *PostgresStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT username, password_hash, role, scopes, enabled, created_at, updated_at
		FROM users ORDER BY username ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.PasswordHash, &u.Role, &u.Scopes, &u.Enabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (p *PostgresStore) GetUser(ctx context.Context, username string) (User, error) {
	var u User
	err := p.pool.QueryRow(ctx, `
		SELECT username, password_hash, role, scopes, enabled, created_at, updated_at
		FROM users WHERE username = $1`, username).
		Scan(&u.Username, &u.PasswordHash, &u.Role, &u.Scopes, &u.Enabled, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (p *PostgresStore) UpsertUser(ctx context.Context, user User) error {
	if user.Role == "" {
		user.Role = "viewer"
	}
	if user.Scopes == nil {
		user.Scopes = []string{"read"}
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO users (username, password_hash, role, scopes, enabled, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (username) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			role = EXCLUDED.role,
			scopes = EXCLUDED.scopes,
			enabled = EXCLUDED.enabled,
			updated_at = NOW()`,
		user.Username, user.PasswordHash, user.Role, user.Scopes, user.Enabled)
	return err
}

func (p *PostgresStore) DeleteUser(ctx context.Context, username string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM users WHERE username = $1`, username)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- IP Bans ---

func (p *PostgresStore) ListActiveIPBans(ctx context.Context) ([]IPBan, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT ip, reason, ttl_seconds, created_at, expires_at
		FROM ip_bans WHERE expires_at > NOW() ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]IPBan, 0)
	for rows.Next() {
		var b IPBan
		if err := rows.Scan(&b.IP, &b.Reason, &b.TTLSeconds, &b.CreatedAt, &b.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (p *PostgresStore) UpsertIPBan(ctx context.Context, ban IPBan) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO ip_bans (ip, reason, ttl_seconds, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (ip) DO UPDATE SET
			reason = EXCLUDED.reason,
			ttl_seconds = EXCLUDED.ttl_seconds,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at`,
		ban.IP, ban.Reason, ban.TTLSeconds, ban.CreatedAt, ban.ExpiresAt)
	return err
}

func (p *PostgresStore) DeleteIPBan(ctx context.Context, ip string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM ip_bans WHERE ip = $1`, ip)
	return err
}

// --- Revisions ---

func (p *PostgresStore) NextRevision(ctx context.Context, kind, actor string) (int64, error) {
	if actor == "" {
		actor = "system"
	}
	var rev int64
	err := p.pool.QueryRow(ctx, `
		INSERT INTO config_revisions (kind, actor) VALUES ($1, $2) RETURNING revision`,
		kind, actor).Scan(&rev)
	return rev, err
}

func (p *PostgresStore) LatestRevision(ctx context.Context) (int64, error) {
	var rev int64
	err := p.pool.QueryRow(ctx, `SELECT COALESCE(MAX(revision), 0) FROM config_revisions`).Scan(&rev)
	return rev, err
}
