package events

import (
	"encoding/json"
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
