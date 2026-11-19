// Package storage defines the Control Plane persistence contract behind a clean
// interface (Constitution §2.3) with PostgreSQL and in-memory implementations.
// Data Plane components never import or query this store directly (Constitution §1.3).
package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/sites"
)

var (
	ErrNotFound = errors.New("record not found")
	ErrConflict = errors.New("record already exists")
)

// User represents a Control Plane RBAC principal persisted in PostgreSQL.
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"` // admin | operator | viewer
	Scopes       []string  `json:"scopes"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// IPBan represents a persisted IP jail / block entry.
type IPBan struct {
	IP         string    `json:"ip"`
	Reason     string    `json:"reason"`
	TTLSeconds int       `json:"ttl"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ZeroTrustPolicy defines per-route continuous authorization rules enforced by
// Envoy ext_authz in the Data Plane (Phase 3 / NIST SP 800-207).
type ZeroTrustPolicy struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Host                string    `json:"host,omitempty"`
	PathPrefix          string    `json:"path_prefix"`
	Enabled             bool      `json:"enabled"`
	Priority            int       `json:"priority"`
	RequireJWT          bool      `json:"require_jwt"`
	AllowedIssuers      []string  `json:"allowed_issuers,omitempty"`
	RequiredScopes      []string  `json:"required_scopes,omitempty"`
	AllowedCIDRs        []string  `json:"allowed_cidrs,omitempty"`
	BlockedCountries    []string  `json:"blocked_countries,omitempty"`
	RequireDeviceHeader string    `json:"require_device_header,omitempty"`
	ShadowMode          bool      `json:"shadow_mode,omitempty"`
	CreatedAt           time.Time `json:"created_at,omitempty"`
	UpdatedAt           time.Time `json:"updated_at,omitempty"`
}

// Store is the Control Plane persistence contract for durable configuration.
type Store interface {
	Ping(ctx context.Context) error
	Close() error

	// Sites
	ListSites(ctx context.Context) ([]sites.Site, error)
	GetSite(ctx context.Context, host string) (sites.Site, error)
	UpsertSite(ctx context.Context, site sites.Site, replace bool) error
	DeleteSite(ctx context.Context, host string) error

	// Custom Rules
	ListCustomRules(ctx context.Context) ([]rules.CustomRule, error)
	UpsertCustomRule(ctx context.Context, rule rules.CustomRule) (rules.CustomRule, error)
	DeleteCustomRule(ctx context.Context, id string) error

	// Exclusions (false-positive tuning)
	ListExclusions(ctx context.Context) ([]rules.Exclusion, error)
	CreateExclusion(ctx context.Context, ex rules.Exclusion) (rules.Exclusion, error)
	DeleteExclusion(ctx context.Context, id string) error

	// Zero-Trust Policies
	ListZTPolicies(ctx context.Context) ([]ZeroTrustPolicy, error)
	UpsertZTPolicy(ctx context.Context, p ZeroTrustPolicy) (ZeroTrustPolicy, error)
	DeleteZTPolicy(ctx context.Context, id string) error

	// Users (RBAC)
	ListUsers(ctx context.Context) ([]User, error)
	GetUser(ctx context.Context, username string) (User, error)
	UpsertUser(ctx context.Context, user User) error
	DeleteUser(ctx context.Context, username string) error

	// IP Bans
	ListActiveIPBans(ctx context.Context) ([]IPBan, error)
	UpsertIPBan(ctx context.Context, ban IPBan) error
	DeleteIPBan(ctx context.Context, ip string) error

	// Monotonic snapshot revisions
	NextRevision(ctx context.Context, kind, actor string) (int64, error)
	LatestRevision(ctx context.Context) (int64, error)
}
