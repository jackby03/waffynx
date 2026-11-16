package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/plugin"
)

// stubPlugin is the minimum implementation of plugin.Plugin, so the chain and
// registry tests do not depend on any shipped plugin's configuration.
type stubPlugin struct {
	name string
	ran  bool
}

func (p *stubPlugin) Name() string                      { return p.name }
func (p *stubPlugin) Version() string                   { return "test" }
func (p *stubPlugin) Description() string               { return "stub" }
func (p *stubPlugin) Phase() plugin.Phase               { return plugin.PhasePreRequest }
func (p *stubPlugin) Priority() int                     { return 0 }
func (p *stubPlugin) Init(map[string]interface{}) error { return nil }
func (p *stubPlugin) Close() error                      { return nil }
func (p *stubPlugin) Execute(ctx *plugin.Context) (*plugin.Context, error) {
	p.ran = true
	return ctx, nil
}

func testConfig() *config.Config {
	return &config.Config{Name: "engine-test"}
}

func TestNewEngineWiring(t *testing.T) {
	e := New(testConfig())
	if e == nil {
		t.Fatal("New returned nil")
	}
	if e.IsRunning() {
		t.Error("a freshly built engine must not report itself as running")
	}
	if e.PolicyEngine() == nil {
		t.Error("expected a non-nil policy evaluator")
	}
	if e.Learning() == nil {
		t.Error("expected a non-nil learning engine")
	}
	if e.Events() == nil {
		t.Error("expected a non-nil event broker")
	}
	if e.PluginChain() == nil {
		t.Error("expected a non-nil plugin chain")
	}
}

// TestEnginePolicyDelegation checks that Engine forwards to its PolicyStore
// rather than keeping a second copy of the policy set.
func TestEnginePolicyDelegation(t *testing.T) {
	e := New(testConfig())

	if err := e.AddPolicy(&Policy{ID: "p1", Name: "block-admin", Phase: PhaseRequest}); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if got := e.Policies(); len(got) != 1 || got[0].ID != "p1" {
		t.Fatalf("expected the policy to be listed, got %v", got)
	}
	if err := e.RemovePolicy("p1"); err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}
	if got := e.Policies(); len(got) != 0 {
		t.Errorf("expected no policies after removal, got %d", len(got))
	}
	if err := e.RemovePolicy("missing"); err == nil {
		t.Error("expected removing an unknown policy to fail")
	}
}

func TestEngineAddPluginRegistersInChain(t *testing.T) {
	e := New(testConfig())

	p := &stubPlugin{name: "stub"}
	e.AddPlugin(p)

	ctx := plugin.NewContext(context.Background(), &recordingWriter{}, nil)
	if _, err := e.PluginChain().Execute(ctx, plugin.PhasePreRequest); err != nil {
		t.Fatalf("chain execution: %v", err)
	}
	if !p.ran {
		t.Error("expected the added plugin to be executed by the chain")
	}
}

func TestEngineAppSecScorerAccessors(t *testing.T) {
	e := New(testConfig())
	if e.AppSecScorer() != nil {
		t.Error("expected no scorer before it is set")
	}

	scorer := appsec.NewBasicScorer()
	e.SetAppSecScorer(scorer)
	if e.AppSecScorer() != scorer {
		t.Error("expected the set scorer to be returned unchanged")
	}
}

func TestGetPluginRegistryIsStable(t *testing.T) {
	reg := GetPluginRegistry()
	if reg == nil {
		t.Fatal("expected a non-nil registry")
	}
	if GetPluginRegistry() != reg {
		t.Error("expected the process-wide registry to be returned consistently")
	}
}

// recordingWriter is a minimal http.ResponseWriter for plugin contexts.
type recordingWriter struct {
	header http.Header
	status int
}

func (w *recordingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *recordingWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *recordingWriter) WriteHeader(status int)      { w.status = status }
