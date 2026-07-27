package plugin

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
)

type testPlugin struct {
	name     string
	version  string
	phase    Phase
	priority int
	initErr  error
	execErr  error
}

func (p *testPlugin) Name() string        { return p.name }
func (p *testPlugin) Version() string     { return p.version }
func (p *testPlugin) Description() string { return "test plugin" }
func (p *testPlugin) Phase() Phase        { return p.phase }
func (p *testPlugin) Priority() int       { return p.priority }

func (p *testPlugin) Init(map[string]interface{}) error { return p.initErr }
func (p *testPlugin) Close() error                      { return nil }

func (p *testPlugin) Execute(ctx *Context) (*Context, error) {
	if p.execErr != nil {
		return ctx, p.execErr
	}
	ctx.Tags["ran_"+p.name] = "true"
	return ctx, nil
}

func TestChain_ExecutesPluginsInPriorityOrder(t *testing.T) {
	chain := NewChain()

	p3 := &testPlugin{name: "third", phase: PhasePreRequest, priority: 10}
	p1 := &testPlugin{name: "first", phase: PhasePreRequest, priority: 1}
	p2 := &testPlugin{name: "second", phase: PhasePreRequest, priority: 5}

	chain.Add(p3)
	chain.Add(p1)
	chain.Add(p2)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	ctx := NewContext(context.Background(), w, req)

	_, err := chain.Execute(ctx, PhasePreRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := ctx.Tags["ran_first"]; !ok {
		t.Error("first plugin did not run")
	}
	if _, ok := ctx.Tags["ran_second"]; !ok {
		t.Error("second plugin did not run")
	}
	if _, ok := ctx.Tags["ran_third"]; !ok {
		t.Error("third plugin did not run")
	}
}

func TestChain_OnlyExecutesMatchingPhase(t *testing.T) {
	chain := NewChain()

	chain.Add(&testPlugin{name: "pre-req", phase: PhasePreRequest, priority: 1})
	chain.Add(&testPlugin{name: "post-req", phase: PhasePostRequest, priority: 1})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	ctx := NewContext(context.Background(), w, req)

	_, err := chain.Execute(ctx, PhasePreRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := ctx.Tags["ran_pre-req"]; !ok {
		t.Error("pre-req plugin should have run")
	}
	if _, ok := ctx.Tags["ran_post-req"]; ok {
		t.Error("post-req plugin should NOT have run in pre_request phase")
	}
}

func TestChain_ErrorStopsExecution(t *testing.T) {
	chain := NewChain()

	chain.Add(&testPlugin{name: "will-fail", phase: PhasePreRequest, priority: 1,
		execErr: fmt.Errorf("blocked")})
	chain.Add(&testPlugin{name: "should-not-run", phase: PhasePreRequest, priority: 2})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	ctx := NewContext(context.Background(), w, req)

	_, err := chain.Execute(ctx, PhasePreRequest)
	if err == nil {
		t.Fatal("expected error")
	}

	if _, ok := ctx.Tags["ran_should-not-run"]; ok {
		t.Error("plugin after error should not have run")
	}
}

func TestChain_EmptyPhase(t *testing.T) {
	chain := NewChain()

	chain.Add(&testPlugin{name: "pre-req", phase: PhasePreRequest, priority: 1})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	ctx := NewContext(context.Background(), w, req)

	_, err := chain.Execute(ctx, PhasePostRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := ctx.Tags["ran_pre-req"]; ok {
		t.Error("pre-req plugin should NOT run in post_request phase")
	}
}

func TestRegistry_RegisterAndList(t *testing.T) {
	reg := &Registry{
		plugins: make(map[string]PluginConstructor),
		meta:    make(map[string]*Metadata),
	}

	reg.plugins["test-plugin"] = func() Plugin { return &testPlugin{name: "test-plugin"} }
	reg.meta["test-plugin"] = &Metadata{
		Name:    "test-plugin",
		Version: "1.0.0",
	}

	list := reg.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(list))
	}
	if list[0].Name != "test-plugin" {
		t.Errorf("expected 'test-plugin', got '%s'", list[0].Name)
	}
}

func TestRegistry_Create(t *testing.T) {
	reg := &Registry{
		plugins: make(map[string]PluginConstructor),
		meta:    make(map[string]*Metadata),
	}

	reg.plugins["test-plugin"] = func() Plugin {
		return &testPlugin{name: "test-plugin", version: "1.0.0"}
	}

	p, err := reg.Create("test-plugin", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "test-plugin" {
		t.Errorf("expected 'test-plugin', got '%s'", p.Name())
	}
}

func TestRegistry_CreateNonexistent(t *testing.T) {
	reg := &Registry{
		plugins: make(map[string]PluginConstructor),
	}

	_, err := reg.Create("nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent plugin")
	}
}

func TestRegistry_Get(t *testing.T) {
	reg := &Registry{
		plugins: make(map[string]PluginConstructor),
		meta:    make(map[string]*Metadata),
	}

	reg.meta["test-plugin"] = &Metadata{Name: "test-plugin", Version: "1.0.0"}

	meta, err := reg.Get("test-plugin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Name != "test-plugin" {
		t.Errorf("expected 'test-plugin', got '%s'", meta.Name)
	}
}

func TestRegistry_GetNotFound(t *testing.T) {
	reg := &Registry{
		meta: make(map[string]*Metadata),
	}

	_, err := reg.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent plugin")
	}
}

func TestChain_Close(t *testing.T) {
	chain := NewChain()
	chain.Add(&testPlugin{name: "p1", phase: PhasePreRequest, priority: 1})
	chain.Add(&testPlugin{name: "p2", phase: PhasePreRequest, priority: 2})

	err := chain.Close()
	if err != nil {
		t.Fatalf("unexpected error during close: %v", err)
	}
}

func TestNewContext(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	ctx := NewContext(context.Background(), w, req)

	if ctx.Request != req {
		t.Error("request not set")
	}
	if ctx.Values == nil {
		t.Error("values map not initialized")
	}
	if ctx.Tags == nil {
		t.Error("tags map not initialized")
	}
}

func TestGlobalRegistry(t *testing.T) {
	reg := GetRegistry()
	if reg == nil {
		t.Fatal("global registry is nil")
	}

	initialCount := len(reg.List())

	Register("test-global", func() Plugin {
		return &testPlugin{name: "test-global"}
	}, &Metadata{
		Name:        "test-global",
		Version:     "1.0.0",
		Description: "test",
		Phase:       PhasePreRequest,
		Priority:    50,
	})

	defer func() {
		delete(reg.plugins, "test-global")
		delete(reg.meta, "test-global")
	}()

	if len(reg.List()) != initialCount+1 {
		t.Errorf("expected %d plugins after register, got %d", initialCount+1, len(reg.List()))
	}
}
