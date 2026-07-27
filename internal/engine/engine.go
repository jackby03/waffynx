package engine

import (
	"os/exec"
	"sync"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
)

// Engine orchestrates the WAF runtime:
//   - Sidecar: Unix socket HTTP server that nginx calls to evaluate requests
//   - nginx:   Forked nginx subprocess with ngx_waffynx module compiled in
//   - Chain:   Plugin execution pipeline
//   - Policy:  WAF rule evaluator
type Engine struct {
	mu       sync.RWMutex
	cfg      *config.Config
	running  bool
	cmd      *exec.Cmd

	sidecar  *Sidecar
	chain    *plugin.Chain
	policy   policy.Evaluator

	policies *PolicyStore
}

func New(cfg *config.Config) *Engine {
	return &Engine{
		cfg:      cfg,
		chain:    plugin.NewChain(),
		policy:   policy.NewRuleEngine(),
		policies: NewPolicyStore(),
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

func (e *Engine) PluginChain() *plugin.Chain {
	return e.chain
}

// GetPluginRegistry returns the global plugin registry so the CLI
// can instantiate plugins from the config file.
func GetPluginRegistry() *plugin.Registry {
	return plugin.GetRegistry()
}
