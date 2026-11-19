package hotreload

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/sites"
	"github.com/jackby03/waffynx/internal/storage"
)

func TestBuildSnapshotAndMemoryBus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st := storage.NewMemoryStore()
	_ = st.UpsertSite(ctx, sites.Site{Host: "app.example.test", Upstream: "backend:80"}, false)
	_, _ = st.UpsertCustomRule(ctx, rules.CustomRule{ID: "r1", Name: "Block", Enabled: true, Action: rules.ActionBlock})
	_, _ = st.CreateExclusion(ctx, rules.Exclusion{ID: "e1", RuleID: "sqli-001", PathPrefix: "/ok", Enabled: true})
	_, _ = st.UpsertZTPolicy(ctx, storage.ZeroTrustPolicy{ID: "zt1", Name: "Admin", PathPrefix: "/admin", Enabled: true, RequireJWT: true})
	_ = st.UpsertIPBan(ctx, storage.IPBan{IP: "203.0.113.4", Reason: "scan", TTLSeconds: 60, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})

	snap, err := BuildSnapshot(ctx, st, 7)
	if err != nil {
		t.Fatalf("BuildSnapshot: %v", err)
	}
	if snap.Revision != 7 || len(snap.Sites) != 1 || len(snap.CustomRules) != 1 || len(snap.Exclusions) != 1 || len(snap.ZTPolicies) != 1 || len(snap.BannedIPs) != 1 {
		t.Fatalf("unexpected snapshot contents: %+v", snap)
	}

	bus := NewMemoryBus()
	defer bus.Close()

	if latest, err := bus.LatestSnapshot(ctx); err != nil || latest != nil {
		t.Fatalf("expected nil initial snapshot, got %v err=%v", latest, err)
	}

	var received atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = bus.Subscribe(ctx, func(s PolicySnapshot) {
			received.Store(s.Revision)
		})
	}()

	time.Sleep(20 * time.Millisecond)
	if err := bus.PublishSnapshot(ctx, snap); err != nil {
		t.Fatalf("PublishSnapshot: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for received.Load() != 7 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if received.Load() != 7 {
		t.Fatalf("expected subscriber to receive revision 7, got %d", received.Load())
	}

	latest, err := bus.LatestSnapshot(ctx)
	if err != nil || latest == nil || latest.Revision != 7 {
		t.Fatalf("LatestSnapshot mismatch: %+v err=%v", latest, err)
	}

	cancel()
	<-done
}

func TestNewRedisBus_InvalidAddr(t *testing.T) {
	if _, err := NewRedisBus("", "", 0); err == nil {
		t.Fatal("expected error for empty addr")
	}
}
