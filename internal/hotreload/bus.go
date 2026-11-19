// Package hotreload distributes compiled policy snapshots from the Control Plane
// to stateless Data Plane replicas over Redis Pub/Sub without giving the Data
// Plane direct access to PostgreSQL (Constitution §1.2 & §1.3).
package hotreload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/sites"
	"github.com/jackby03/waffynx/internal/storage"
)

const (
	DefaultChannel     = "waffynx:hotreload"
	DefaultSnapshotKey = "waffynx:snapshot:latest"
)

// PolicySnapshot is the immutable versioned bundle pushed to every waf-engine
// replica and installed atomically via atomic.Pointer.
type PolicySnapshot struct {
	Revision    int64                     `json:"revision"`
	GeneratedAt time.Time                 `json:"generated_at"`
	CustomRules []rules.CustomRule        `json:"custom_rules"`
	Exclusions  []rules.Exclusion         `json:"exclusions"`
	ZTPolicies  []storage.ZeroTrustPolicy `json:"zt_policies"`
	Sites       []sites.Site              `json:"sites"`
	BannedIPs   []storage.IPBan           `json:"banned_ips"`
}

// Bus distributes PolicySnapshots from Control Plane writers to Data Plane subscribers.
type Bus interface {
	PublishSnapshot(ctx context.Context, snap PolicySnapshot) error
	LatestSnapshot(ctx context.Context) (*PolicySnapshot, error)
	Subscribe(ctx context.Context, onSnapshot func(PolicySnapshot)) error
	Close() error
}

// BuildSnapshot assembles a complete immutable PolicySnapshot from a Control Plane Store.
func BuildSnapshot(ctx context.Context, st storage.Store, revision int64) (PolicySnapshot, error) {
	customRules, err := st.ListCustomRules(ctx)
	if err != nil {
		return PolicySnapshot{}, fmt.Errorf("listing custom rules: %w", err)
	}
	exclusions, err := st.ListExclusions(ctx)
	if err != nil {
		return PolicySnapshot{}, fmt.Errorf("listing exclusions: %w", err)
	}
	ztPolicies, err := st.ListZTPolicies(ctx)
	if err != nil {
		return PolicySnapshot{}, fmt.Errorf("listing zt policies: %w", err)
	}
	siteList, err := st.ListSites(ctx)
	if err != nil {
		return PolicySnapshot{}, fmt.Errorf("listing sites: %w", err)
	}
	bans, err := st.ListActiveIPBans(ctx)
	if err != nil {
		return PolicySnapshot{}, fmt.Errorf("listing ip bans: %w", err)
	}
	return PolicySnapshot{
		Revision:    revision,
		GeneratedAt: time.Now().UTC(),
		CustomRules: customRules,
		Exclusions:  exclusions,
		ZTPolicies:  ztPolicies,
		Sites:       siteList,
		BannedIPs:   bans,
	}, nil
}

// RedisBus implements Bus via Redis SET (latest durable snapshot for cold boots)
// plus Redis Pub/Sub (instant push to running replicas).
type RedisBus struct {
	client      *redis.Client
	channel     string
	snapshotKey string
	ownedClient bool
}

// NewRedisBus connects to Redis and verifies reachability.
func NewRedisBus(addr, password string, db int) (*RedisBus, error) {
	if addr == "" {
		return nil, fmt.Errorf("redis address is required")
	}
	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		Password:    password,
		DB:          db,
		DialTimeout: 3 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connecting hot-reload redis at %s: %w", addr, err)
	}
	return &RedisBus{
		client:      client,
		channel:     DefaultChannel,
		snapshotKey: DefaultSnapshotKey,
		ownedClient: true,
	}, nil
}

// NewRedisBusWithClient wraps an existing redis.Client.
func NewRedisBusWithClient(client *redis.Client) *RedisBus {
	return &RedisBus{
		client:      client,
		channel:     DefaultChannel,
		snapshotKey: DefaultSnapshotKey,
	}
}

func (b *RedisBus) PublishSnapshot(ctx context.Context, snap PolicySnapshot) error {
	payload, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshaling policy snapshot: %w", err)
	}
	opCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Persist latest snapshot first so freshly scaled pods hydrate immediately.
	if err := b.client.Set(opCtx, b.snapshotKey, payload, 0).Err(); err != nil {
		return fmt.Errorf("storing latest snapshot in redis: %w", err)
	}
	if err := b.client.Publish(opCtx, b.channel, payload).Err(); err != nil {
		return fmt.Errorf("publishing hot-reload notification: %w", err)
	}
	return nil
}

func (b *RedisBus) LatestSnapshot(ctx context.Context) (*PolicySnapshot, error) {
	opCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	raw, err := b.client.Get(opCtx, b.snapshotKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fetching latest snapshot: %w", err)
	}
	var snap PolicySnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, fmt.Errorf("decoding latest snapshot: %w", err)
	}
	return &snap, nil
}

// Subscribe listens for hot-reload snapshots until ctx is cancelled, automatically
// reconnecting with exponential backoff if Redis restarts. Existing in-memory
// snapshots remain enforced during any outage (Constitution §3.4).
func (b *RedisBus) Subscribe(ctx context.Context, onSnapshot func(PolicySnapshot)) error {
	backoff := time.Second
	for ctx.Err() == nil {
		pubsub := b.client.Subscribe(ctx, b.channel)
		ch := pubsub.Channel()
		// Re-fetch latest snapshot upon (re)subscribe so no update during a brief disconnect is missed.
		if latest, err := b.LatestSnapshot(ctx); err == nil && latest != nil {
			onSnapshot(*latest)
			backoff = time.Second
		}

		disconnected := false
		for !disconnected {
			select {
			case <-ctx.Done():
				_ = pubsub.Close()
				return nil
			case msg, ok := <-ch:
				if !ok {
					disconnected = true
					break
				}
				var snap PolicySnapshot
				if err := json.Unmarshal([]byte(msg.Payload), &snap); err != nil {
					logging.Warn().Err(err).Msg("ignoring malformed hot-reload snapshot payload")
					continue
				}
				onSnapshot(snap)
			}
		}
		_ = pubsub.Close()

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
	return nil
}

func (b *RedisBus) Close() error {
	if b.ownedClient && b.client != nil {
		return b.client.Close()
	}
	return nil
}

// MemoryBus is an in-process Bus for unit tests and single-node operation.
type MemoryBus struct {
	mu     sync.RWMutex
	latest *PolicySnapshot
	subs   map[chan PolicySnapshot]struct{}
}

func NewMemoryBus() *MemoryBus {
	return &MemoryBus{
		subs: make(map[chan PolicySnapshot]struct{}),
	}
}

func (m *MemoryBus) PublishSnapshot(_ context.Context, snap PolicySnapshot) error {
	cp := snap
	m.mu.Lock()
	m.latest = &cp
	for ch := range m.subs {
		select {
		case ch <- cp:
		default:
		}
	}
	m.mu.Unlock()
	return nil
}

func (m *MemoryBus) LatestSnapshot(context.Context) (*PolicySnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.latest == nil {
		return nil, nil
	}
	cp := *m.latest
	return &cp, nil
}

func (m *MemoryBus) Subscribe(ctx context.Context, onSnapshot func(PolicySnapshot)) error {
	ch := make(chan PolicySnapshot, 16)
	m.mu.Lock()
	m.subs[ch] = struct{}{}
	latest := m.latest
	m.mu.Unlock()

	if latest != nil {
		onSnapshot(*latest)
	}

	defer func() {
		m.mu.Lock()
		delete(m.subs, ch)
		m.mu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case snap := <-ch:
			onSnapshot(snap)
		}
	}
}

func (m *MemoryBus) Close() error { return nil }
