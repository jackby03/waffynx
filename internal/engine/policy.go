package engine

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
)

type PolicyAction string

const (
	ActionAllow PolicyAction = "allow"
	ActionDeny  PolicyAction = "deny"
	ActionLog   PolicyAction = "log"
	ActionBlock PolicyAction = "block"
	ActionRedirect PolicyAction = "redirect"
)

type PolicyPhase string

const (
	PhaseRequest  PolicyPhase = "request"
	PhaseResponse PolicyPhase = "response"
	PhaseConnect  PolicyPhase = "connect"
)

type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Phase       PolicyPhase            `json:"phase"`
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	Conditions  []Condition            `json:"conditions"`
	Action      PolicyAction           `json:"action"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

type PolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*Policy
	order    []string
}

func NewPolicyStore() *PolicyStore {
	return &PolicyStore{
		policies: make(map[string]*Policy),
	}
}

func (ps *PolicyStore) Add(p *Policy) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if p.ID == "" {
		p.ID = uuid.New().String()
	}

	if _, exists := ps.policies[p.ID]; exists {
		return fmt.Errorf("policy %s already exists", p.ID)
	}

	ps.policies[p.ID] = p
	ps.order = append(ps.order, p.ID)
	return nil
}

func (ps *PolicyStore) Remove(id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, exists := ps.policies[id]; !exists {
		return fmt.Errorf("policy %s not found", id)
	}

	delete(ps.policies, id)
	for i, pid := range ps.order {
		if pid == id {
			ps.order = append(ps.order[:i], ps.order[i+1:]...)
			break
		}
	}
	return nil
}

func (ps *PolicyStore) Get(id string) (*Policy, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	p, exists := ps.policies[id]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", id)
	}
	return p, nil
}

func (ps *PolicyStore) List() []*Policy {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	policies := make([]*Policy, 0, len(ps.order))
	for _, id := range ps.order {
		if p, ok := ps.policies[id]; ok {
			policies = append(policies, p)
		}
	}
	return policies
}
