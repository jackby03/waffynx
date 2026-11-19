package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/sites"
)

func TestMemoryStore_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	defer st.Close()

	if err := st.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// Sites CRUD + conflict semantics.
	if err := st.UpsertSite(ctx, sites.Site{Host: "app.example.test", Upstream: "backend:80"}, false); err != nil {
		t.Fatalf("UpsertSite create: %v", err)
	}
	if err := st.UpsertSite(ctx, sites.Site{Host: "APP.EXAMPLE.TEST", Upstream: "backend:80"}, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	if err := st.UpsertSite(ctx, sites.Site{Host: "app.example.test", Upstream: "backend:8080"}, true); err != nil {
		t.Fatalf("UpsertSite replace: %v", err)
	}
	gotSite, err := st.GetSite(ctx, "app.example.test")
	if err != nil || gotSite.Upstream != "backend:8080" {
		t.Fatalf("GetSite: %+v err=%v", gotSite, err)
	}
	listSites, _ := st.ListSites(ctx)
	if len(listSites) != 1 {
		t.Fatalf("expected 1 site, got %d", len(listSites))
	}
	if err := st.DeleteSite(ctx, "app.example.test"); err != nil {
		t.Fatalf("DeleteSite: %v", err)
	}
	if err := st.DeleteSite(ctx, "missing.test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Custom Rules CRUD.
	r1, err := st.UpsertCustomRule(ctx, rules.CustomRule{Name: "Block admin", Enabled: true, Priority: 20, Action: rules.ActionBlock})
	if err != nil || r1.ID == "" {
		t.Fatalf("UpsertCustomRule: %+v err=%v", r1, err)
	}
	_, _ = st.UpsertCustomRule(ctx, rules.CustomRule{ID: "r-high", Name: "High prio", Enabled: true, Priority: 5, Action: rules.ActionDeny})
	ruleList, _ := st.ListCustomRules(ctx)
	if len(ruleList) != 2 || ruleList[0].ID != "r-high" {
		t.Fatalf("unexpected rule ordering: %+v", ruleList)
	}
	if err := st.DeleteCustomRule(ctx, r1.ID); err != nil {
		t.Fatalf("DeleteCustomRule: %v", err)
	}

	// Exclusions CRUD.
	ex, err := st.CreateExclusion(ctx, rules.Exclusion{Name: "WP FP", RuleID: "sqli-001", PathPrefix: "/wp-json", Enabled: true})
	if err != nil || ex.ID == "" {
		t.Fatalf("CreateExclusion: %+v err=%v", ex, err)
	}
	exList, _ := st.ListExclusions(ctx)
	if len(exList) != 1 {
		t.Fatalf("expected 1 exclusion, got %d", len(exList))
	}
	if err := st.DeleteExclusion(ctx, ex.ID); err != nil {
		t.Fatalf("DeleteExclusion: %v", err)
	}

	// Zero-Trust Policies CRUD.
	zt, err := st.UpsertZTPolicy(ctx, ZeroTrustPolicy{Name: "Admin JWT", PathPrefix: "/admin", Enabled: true, RequireJWT: true, RequiredScopes: []string{"admin"}})
	if err != nil || zt.ID == "" {
		t.Fatalf("UpsertZTPolicy: %+v err=%v", zt, err)
	}
	zts, _ := st.ListZTPolicies(ctx)
	if len(zts) != 1 {
		t.Fatalf("expected 1 zt policy, got %d", len(zts))
	}
	if err := st.DeleteZTPolicy(ctx, zt.ID); err != nil {
		t.Fatalf("DeleteZTPolicy: %v", err)
	}

	// Users RBAC CRUD.
	if err := st.UpsertUser(ctx, User{Username: "alice", PasswordHash: "hash", Role: "admin", Scopes: []string{"read", "write"}, Enabled: true}); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	u, err := st.GetUser(ctx, "alice")
	if err != nil || u.Role != "admin" {
		t.Fatalf("GetUser: %+v err=%v", u, err)
	}
	users, _ := st.ListUsers(ctx)
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if err := st.DeleteUser(ctx, "alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// IP Bans active filter.
	now := time.Now().UTC()
	_ = st.UpsertIPBan(ctx, IPBan{IP: "198.51.100.1", Reason: "active", TTLSeconds: 300, CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	_ = st.UpsertIPBan(ctx, IPBan{IP: "198.51.100.2", Reason: "expired", TTLSeconds: 1, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Second)})
	bans, _ := st.ListActiveIPBans(ctx)
	if len(bans) != 1 || bans[0].IP != "198.51.100.1" {
		t.Fatalf("expected 1 active ban, got %+v", bans)
	}
	_ = st.DeleteIPBan(ctx, "198.51.100.1")

	// Revisions.
	rev1, _ := st.NextRevision(ctx, "sites", "alice")
	rev2, _ := st.NextRevision(ctx, "rules", "alice")
	latest, _ := st.LatestRevision(ctx)
	if rev1 != 1 || rev2 != 2 || latest != 2 {
		t.Fatalf("unexpected revisions: %d %d %d", rev1, rev2, latest)
	}
}

func TestEmbeddedMigrationSQL(t *testing.T) {
	for _, table := range []string{"sites", "custom_rules", "exclusions", "users", "ip_bans", "zt_policies", "config_revisions"} {
		if !strings.Contains(initialMigrationSQL, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Errorf("migration missing table %s", table)
		}
	}
	if _, err := NewPostgresStore(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty DSN")
	}
}
