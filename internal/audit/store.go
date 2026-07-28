package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jackby03/waffynx/internal/logging"
)

type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	ActorIP   string    `json:"actor_ip"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Result    string    `json:"result"`
	Details   string    `json:"details,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
}

type Store struct {
	mu      sync.RWMutex
	events  []Event
	maxSize int
	pos     int
	file    *os.File
	fileMu  sync.Mutex
}

func NewStore(maxSize int, filePath string) (*Store, error) {
	s := &Store{
		events:  make([]Event, 0, maxSize),
		maxSize: maxSize,
	}

	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening audit log: %w", err)
		}
		s.file = f
		logging.Info().Str("path", filePath).Msg("audit log file opened")
	}

	return s, nil
}

func (s *Store) Record(e Event) {
	e.Timestamp = time.Now()

	s.mu.Lock()
	if len(s.events) < s.maxSize {
		s.events = append(s.events, e)
	} else {
		s.events[s.pos] = e
		s.pos = (s.pos + 1) % s.maxSize
	}
	s.mu.Unlock()

	if s.file != nil {
		data, err := json.Marshal(e)
		if err != nil {
			return
		}
		s.fileMu.Lock()
		s.file.Write(data)
		s.file.Write([]byte("\n"))
		s.fileMu.Unlock()
	}
}

type QueryFilter struct {
	Limit  int    `json:"limit"`
	Actor  string `json:"actor,omitempty"`
	Action string `json:"action,omitempty"`
	Result string `json:"result,omitempty"`
}

func (s *Store) Query(f QueryFilter) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}

	var result []Event
	for i := len(s.events) - 1; i >= 0 && len(result) < f.Limit; i-- {
		e := s.events[i]
		if f.Actor != "" && e.Actor != f.Actor {
			continue
		}
		if f.Action != "" && e.Action != f.Action {
			continue
		}
		if f.Result != "" && e.Result != f.Result {
			continue
		}
		result = append(result, e)
	}

	return result
}

func (s *Store) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.events)
	var allowed, blocked int
	actors := make(map[string]int)
	actions := make(map[string]int)

	for _, e := range s.events {
		if e.Result == "allowed" {
			allowed++
		} else {
			blocked++
		}
		actors[e.Actor]++
		actions[e.Action]++
	}

	return map[string]interface{}{
		"total":   total,
		"allowed": allowed,
		"blocked": blocked,
	}
}

func (s *Store) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}
