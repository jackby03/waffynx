package plugin

import (
	"fmt"
)

type Phase string

const (
	PhasePreRequest  Phase = "pre_request"
	PhasePostRequest Phase = "post_request"
	PhasePreResponse Phase = "pre_response"
	PhasePostResponse Phase = "post_response"
	PhaseLog         Phase = "log"
)

type Plugin interface {
	Name() string
	Version() string
	Description() string
	Phase() Phase
	Priority() int

	Init(config map[string]interface{}) error
	Execute(ctx *Context) (*Context, error)
	Close() error
}

type Metadata struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Author      string `json:"author"`
	License     string `json:"license"`
	Phase       Phase  `json:"phase"`
	Priority    int    `json:"priority"`
	Tags        []string `json:"tags,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
}

type PluginConstructor func() Plugin

type Registry struct {
	plugins map[string]PluginConstructor
	meta    map[string]*Metadata
}

var globalRegistry = &Registry{
	plugins: make(map[string]PluginConstructor),
	meta:    make(map[string]*Metadata),
}

func Register(name string, constructor PluginConstructor, meta *Metadata) {
	globalRegistry.plugins[name] = constructor
	globalRegistry.meta[name] = meta
}

func GetRegistry() *Registry {
	return globalRegistry
}

func (r *Registry) Create(name string, config map[string]interface{}) (Plugin, error) {
	constructor, ok := r.plugins[name]
	if !ok {
		return nil, fmt.Errorf("plugin %s not registered", name)
	}

	p := constructor()
	if err := p.Init(config); err != nil {
		return nil, fmt.Errorf("initializing plugin %s: %w", name, err)
	}

	return p, nil
}

func (r *Registry) List() []*Metadata {
	meta := make([]*Metadata, 0, len(r.meta))
	for _, m := range r.meta {
		meta = append(meta, m)
	}
	return meta
}

func (r *Registry) Get(name string) (*Metadata, error) {
	m, ok := r.meta[name]
	if !ok {
		return nil, fmt.Errorf("plugin %s not found", name)
	}
	return m, nil
}
