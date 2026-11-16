//go:build windows

package engine

import (
	"context"
	"fmt"

	"github.com/jackby03/waffynx/internal/sites"
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

// ApplySites is a no-op on Windows: the reverse proxy only exists on Linux.
func (e *Engine) ApplySites(ctx context.Context, fragments map[string]string) (sites.ApplyResult, error) {
	return sites.ApplyResult{}, fmt.Errorf("applying site configuration requires Linux (nginx)")
}
