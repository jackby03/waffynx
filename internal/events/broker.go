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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("event API returned %s", resp.Status)
	}
	return nil
}

type subscriber chan []byte

type Broker struct {
	mu          sync.RWMutex
	subscribers map[subscriber]struct{}
}

func NewBroker() *Broker {
	return &Broker{
		subscribers: make(map[subscriber]struct{}),
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

	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.subscribers {
		select {
		case ch <- data:
		default:
		}
	}
}
