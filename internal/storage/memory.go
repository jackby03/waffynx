package storage

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/sites"
)

// MemoryStore implements Store in memory for unit tests and single-node fallback.
type MemoryStore struct {
	mu         sync.RWMutex
	sites      map[string]sites.Site
	rules      map[string]rules.CustomRule
	exclusions map[string]rules.Exclusion
	ztPolicies map[string]ZeroTrustPolicy
	users      map[string]User
	ipBans     map[string]IPBan
	revision   int64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sites:      make(map[string]sites.Site),
		rules:      make(map[string]rules.CustomRule),
		exclusions: make(map[string]rules.Exclusion),
		ztPolicies: make(map[string]ZeroTrustPolicy),
		users:      make(map[string]User),
		ipBans:     make(map[string]IPBan),
	}
}

func (m *MemoryStore) Ping(context.Context) error { return nil }
func (m *MemoryStore) Close() error               { return nil }

func (m *MemoryStore) ListSites(context.Context) ([]sites.Site, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]sites.Site, 0, len(m.sites))
	for _, s := range m.sites {
		out = append(out, s)
	}
	return sites.SortByHost(out), nil
}

func (m *MemoryStore) GetSite(_ context.Context, host string) (sites.Site, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sites[sites.NormalizeHost(host)]
	if !ok {
		return sites.Site{}, ErrNotFound
	}
	return s, nil
}

func (m *MemoryStore) UpsertSite(_ context.Context, site sites.Site, replace bool) error {
	key := sites.NormalizeHost(site.Host)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sites[key]; exists && !replace {
		return ErrConflict
	}
	m.sites[key] = site
	return nil
}

func (m *MemoryStore) DeleteSite(_ context.Context, host string) error {
	key := sites.NormalizeHost(host)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sites[key]; !exists {
		return ErrNotFound
	}
	delete(m.sites, key)
	return nil
}

func (m *MemoryStore) ListCustomRules(context.Context) ([]rules.CustomRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]rules.CustomRule, 0, len(m.rules))
	for _, r := range m.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (m *MemoryStore) UpsertCustomRule(_ context.Context, rule rules.CustomRule) (rules.CustomRule, error) {
	if rule.ID == "" {
		rule.ID = "rule-" + uuid.NewString()[:8]
	}
	m.mu.Lock()
	m.rules[rule.ID] = rule
	m.mu.Unlock()
	return rule, nil
}

func (m *MemoryStore) DeleteCustomRule(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rules[id]; !ok {
		return ErrNotFound
	}
	delete(m.rules, id)
	return nil
}

func (m *MemoryStore) ListExclusions(context.Context) ([]rules.Exclusion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]rules.Exclusion, 0, len(m.exclusions))
	for _, ex := range m.exclusions {
		out = append(out, ex)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (m *MemoryStore) CreateExclusion(_ context.Context, ex rules.Exclusion) (rules.Exclusion, error) {
	if ex.ID == "" {
		ex.ID = "ex-" + uuid.NewString()[:8]
	}
	if ex.CreatedAt.IsZero() {
		ex.CreatedAt = time.Now().UTC()
	}
	m.mu.Lock()
	m.exclusions[ex.ID] = ex
	m.mu.Unlock()
	return ex, nil
}

func (m *MemoryStore) DeleteExclusion(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.exclusions[id]; !ok {
		return ErrNotFound
	}
	delete(m.exclusions, id)
	return nil
}

func (m *MemoryStore) ListZTPolicies(context.Context) ([]ZeroTrustPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ZeroTrustPolicy, 0, len(m.ztPolicies))
	for _, p := range m.ztPolicies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (m *MemoryStore) UpsertZTPolicy(_ context.Context, p ZeroTrustPolicy) (ZeroTrustPolicy, error) {
	now := time.Now().UTC()
	if p.ID == "" {
		p.ID = "zt-" + uuid.NewString()[:8]
	}
	if p.PathPrefix == "" {
		p.PathPrefix = "/"
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	m.mu.Lock()
	m.ztPolicies[p.ID] = p
	m.mu.Unlock()
	return p, nil
}

func (m *MemoryStore) DeleteZTPolicy(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ztPolicies[id]; !ok {
		return ErrNotFound
	}
	delete(m.ztPolicies, id)
	return nil
}

func (m *MemoryStore) ListUsers(context.Context) ([]User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Username < out[j].Username
	})
	return out, nil
}

func (m *MemoryStore) GetUser(_ context.Context, username string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[username]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *MemoryStore) UpsertUser(_ context.Context, user User) error {
	now := time.Now().UTC()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	user.UpdatedAt = now
	m.mu.Lock()
	m.users[user.Username] = user
	m.mu.Unlock()
	return nil
}

func (m *MemoryStore) DeleteUser(_ context.Context, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[username]; !ok {
		return ErrNotFound
	}
	delete(m.users, username)
	return nil
}

func (m *MemoryStore) ListActiveIPBans(context.Context) ([]IPBan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now().UTC()
	out := make([]IPBan, 0, len(m.ipBans))
	for _, b := range m.ipBans {
		if b.ExpiresAt.After(now) {
			out = append(out, b)
		}
	}
	return out, nil
}

func (m *MemoryStore) UpsertIPBan(_ context.Context, ban IPBan) error {
	m.mu.Lock()
	m.ipBans[ban.IP] = ban
	m.mu.Unlock()
	return nil
}

func (m *MemoryStore) DeleteIPBan(_ context.Context, ip string) error {
	m.mu.Lock()
	delete(m.ipBans, ip)
	m.mu.Unlock()
	return nil
}

func (m *MemoryStore) NextRevision(_ context.Context, _, _ string) (int64, error) {
	m.mu.Lock()
	m.revision++
	rev := m.revision
	m.mu.Unlock()
	return rev, nil
}

func (m *MemoryStore) LatestRevision(context.Context) (int64, error) {
	m.mu.RLock()
	rev := m.revision
	m.mu.RUnlock()
	return rev, nil
}
