//go:build windows

package engine

import (
	"context"
	"fmt"
)

// Windows stubs -- development only, Waffynx runs on Linux.
func (e *Engine) Start(ctx context.Context) error {
	return fmt.Errorf("waffynx engine requires Linux (nginx + unix sockets)")
}

func (e *Engine) Stop() error {
	return nil
}

func (e *Engine) Reload() error {
	return fmt.Errorf("reload not supported on Windows")
}
