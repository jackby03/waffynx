package plugin

import (
	"context"
	"fmt"
	"net/http"
	"sort"
)

type Context struct {
	context.Context
	Request        *http.Request
	ResponseWriter http.ResponseWriter
	Values         map[string]interface{}
	Tags           map[string]string
	StatusCode     int
	BodySize       int64
}

func NewContext(ctx context.Context, w http.ResponseWriter, r *http.Request) *Context {
	return &Context{
		Context:        ctx,
		Request:        r,
		ResponseWriter: w,
		Values:         make(map[string]interface{}),
		Tags:           make(map[string]string),
	}
}

type Chain struct {
	plugins []Plugin
	byPhase map[Phase][]Plugin
}

func NewChain() *Chain {
	return &Chain{
		byPhase: make(map[Phase][]Plugin),
	}
}

func (c *Chain) Add(p Plugin) {
	c.plugins = append(c.plugins, p)
	c.byPhase[p.Phase()] = append(c.byPhase[p.Phase()], p)
	sort.SliceStable(c.byPhase[p.Phase()], func(i, j int) bool {
		return c.byPhase[p.Phase()][i].Priority() < c.byPhase[p.Phase()][j].Priority()
	})
}

func (c *Chain) Execute(ctx *Context, phase Phase) (*Context, error) {
	plugins, ok := c.byPhase[phase]
	if !ok {
		return ctx, nil
	}

	for _, p := range plugins {
		var err error
		ctx, err = p.Execute(ctx)
		if err != nil {
			return ctx, fmt.Errorf("plugin %s error: %w", p.Name(), err)
		}
	}

	return ctx, nil
}

func (c *Chain) Close() error {
	var errs []error
	for _, p := range c.plugins {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing %s: %w", p.Name(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("plugin close errors: %v", errs)
	}
	return nil
}
