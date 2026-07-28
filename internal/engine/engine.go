package engine

import (
	"os/exec"
	"sync"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/learning"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
	wrules "github.com/jackby03/waffynx/internal/rules"
)

// Engine orchestrates the WAF runtime:
//   - Sidecar: Unix socket HTTP server that nginx calls to evaluate requests
//   - nginx:   Forked nginx subprocess with ngx_waffynx module compiled in
//   - Chain:   Plugin execution pipeline
//   - Policy:  WAF rule evaluator
//   - AppSec:  ML-based anomaly scorer (basic-go or open-appsec bridge)
type Engine struct {
	mu       sync.RWMutex
	cfg      *config.Config
	running  bool
	cmd      *exec.Cmd

	sidecar  *Sidecar
	chain    *plugin.Chain
	policy   policy.Evaluator
	scorer   appsec.Scorer
	learning *learning.Engine
	audit    *audit.Store
	rules    *wrules.Engine
	broker   *events.Broker

	policies *PolicyStore
}

func New(cfg *config.Config) *Engine {
	a, _ := audit.NewStore(5000, "/opt/waffynx/logs/waf-audit.jsonl")
	return &Engine{
		cfg:      cfg,
		chain:    plugin.NewChain(),
		policy:   policy.NewRuleEngine(),
		policies: NewPolicyStore(),
		learning: learning.NewEngine(2000),
		audit:    a,
		rules:    wrules.NewEngine(),
		broker:   events.NewBroker(),
	}
}

func (e *Engine) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

func (e *Engine) AddPolicy(p *Policy) error {
	return e.policies.Add(p)
}

func (e *Engine) RemovePolicy(id string) error {
	return e.policies.Remove(id)
}

func (e *Engine) Policies() []*Policy {
	return e.policies.List()
}

func (e *Engine) AddPlugin(p plugin.Plugin) {
	e.chain.Add(p)
}

func (e *Engine) PolicyEngine() policy.Evaluator {
	return e.policy
}

// SetAppSecScorer sets the ML anomaly scorer. Call before Start().
// Use NewBasicScorer() for development or NewBridgeScorer() for open-appsec.
func (e *Engine) SetAppSecScorer(s appsec.Scorer) {
	e.scorer = s
}

func (e *Engine) AppSecScorer() appsec.Scorer {
	return e.scorer
}

func (e *Engine) Learning() *learning.Engine {
	return e.learning
}

func (e *Engine) PluginChain() *plugin.Chain {
	return e.chain
}

func (e *Engine) Events() *events.Broker {
	return e.broker
}

// GetPluginRegistry returns the global plugin registry so the CLI
// can instantiate plugins from the config file.
func GetPluginRegistry() *plugin.Registry {
	return plugin.GetRegistry()
}
