package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type EventType string

const (
	TypeBlocked    EventType = "blocked"
	TypeAllowed    EventType = "allowed"
	TypeStats      EventType = "stats"
	TypeSuggestion EventType = "suggestion"
)

type WafEvent struct {
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	RemoteIP  string    `json:"remote_ip,omitempty"`
	RuleID    string    `json:"rule_id,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Payload   any       `json:"payload,omitempty"`
}

const MaxEventBodyBytes = 64 * 1024

func (e WafEvent) Validate() error {
	if e.Type != TypeBlocked {
		return fmt.Errorf("unsupported event type %q", e.Type)
	}
	if len(e.Path) > 8192 || len(e.Reason) > 4096 || len(e.RuleID) > 256 || len(e.RemoteIP) > 256 || len(e.Method) > 32 {
		return fmt.Errorf("event field exceeds maximum length")
	}
	if e.Path == "" || e.RuleID == "" {
		return fmt.Errorf("blocked event requires path and rule_id")
	}
	return nil
}

type Publisher struct {
	url    string
	token  string
	client *http.Client
}

func NewPublisher(url, token string, timeout time.Duration) *Publisher {
	if timeout <= 0 {
		timeout = 200 * time.Millisecond
	}
	return &Publisher{
		url:    url,
		token:  token,
		client: &http.Client{Timeout: timeout},
	}
}

func (p *Publisher) Publish(event WafEvent) error {
	if p == nil || p.url == "" || p.token == "" {
		return nil
	}
	if err := event.Validate(); err != nil {
		return fmt.Errorf("validating event: %w", err)
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encoding event: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating event request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting event: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("event API returned %s", resp.Status)
	}
	return nil
}

// maxHistory bounds the event history served by GET /api/v1/events/history.
//
// The broker is a live feed, not an audit log: the dashboard asks "what just
// happened", so a fixed ring is enough. Growing it with traffic would turn
// attack volume into a memory leak in the control-plane process.
const maxHistory = 1000

type subscriber chan []byte

type Broker struct {
	mu          sync.RWMutex
	subscribers map[subscriber]struct{}
	// history is a fixed-size ring of the most recent events. next is the slot
	// the next event overwrites and count saturates at maxHistory.
	history []WafEvent
	next    int
	count   int
}

func NewBroker() *Broker {
	return &Broker{
		subscribers: make(map[subscriber]struct{}),
		history:     make([]WafEvent, maxHistory),
	}
}

func (b *Broker) Subscribe() subscriber {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(subscriber, 64)
	b.subscribers[ch] = struct{}{}
	return ch
}

func (b *Broker) Unsubscribe(ch subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subscribers, ch)
	close(ch)
}

func (b *Broker) Publish(event WafEvent) {
	event.Timestamp = time.Now()
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	// History and fan-out share the write lock so a reader can never observe an
	// event in the history that was not also offered to the live subscribers.
	// Delivery is non-blocking, so the lock is held only for pointer copies.
	b.mu.Lock()
	defer b.mu.Unlock()

	b.history[b.next] = event
	b.next = (b.next + 1) % maxHistory
	if b.count < maxHistory {
		b.count++
	}

	for ch := range b.subscribers {
		select {
		case ch <- data:
		default:
		}
	}
}

// History returns the most recent events, newest first.
//
// The limit is clamped to [1, maxHistory] defensively: the HTTP layer rejects
// out-of-range values with 400, and a caller that bypasses it still cannot ask
// for an unbounded slice. The result is never nil, so it encodes as [] rather
// than null.
func (b *Broker) History(limit int) []WafEvent {
	if limit < 1 {
		limit = 1
	}
	if limit > maxHistory {
		limit = maxHistory
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	n := b.count
	if n > limit {
		n = limit
	}

	out := make([]WafEvent, 0, n)
	for i := 1; i <= n; i++ {
		idx := (b.next - i + maxHistory) % maxHistory
		out = append(out, b.history[idx])
	}
	return out
}
