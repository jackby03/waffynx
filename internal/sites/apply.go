package sites

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Validator checks that a rendered configuration is acceptable to the proxy
// before it goes live. The production implementation runs `nginx -t`.
type Validator interface {
	ValidateConfig(ctx context.Context, dir string) error
}

// Reloader asks the running proxy to pick up the configuration on disk.
type Reloader interface {
	Reload(ctx context.Context) error
}

// ApplyResult reports what an Apply changed.
type ApplyResult struct {
	// Written lists fragment files created or modified, sorted.
	Written []string
	// Removed lists fragment files deleted, sorted.
	Removed []string
	// Restored is true when the apply failed and the previous configuration was
	// put back.
	Restored bool
}

// Applier writes rendered fragments into a directory and makes them live.
//
// The order is deliberate and is the whole point of this type: write, validate,
// reload, and roll back on any failure. A proxy left holding a configuration that
// failed validation is worse than a failed apply.
type Applier struct {
	// Dir is the directory nginx includes, e.g. /opt/waffynx/nginx/conf/sites.
	Dir       string
	Validator Validator
	Reloader  Reloader

	mu sync.Mutex
}

// Apply makes fragments the live configuration.
//
// It is serialised: concurrent callers queue rather than interleave writes, so a
// reload can never be triggered while another apply is mid-write.
func (a *Applier) Apply(ctx context.Context, fragments map[string]string) (ApplyResult, error) {
	if a.Dir == "" {
		return ApplyResult{}, errors.New("sites: applier has no target directory")
	}
	if a.Validator == nil {
		return ApplyResult{}, errors.New("sites: applier has no validator")
	}
	if a.Reloader == nil {
		return ApplyResult{}, errors.New("sites: applier has no reloader")
	}
	for name := range fragments {
		if err := checkFragmentName(name); err != nil {
			return ApplyResult{}, err
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	previous, err := readFragments(a.Dir)
	if err != nil {
		return ApplyResult{}, err
	}

	written, removed, err := a.write(a.Dir, previous, fragments)
	if err != nil {
		return ApplyResult{}, err
	}
	result := ApplyResult{Written: written, Removed: removed}

	if err := a.Validator.ValidateConfig(ctx, a.Dir); err != nil {
		restoreErr := a.restore(a.Dir, fragments, previous)
		result.Restored = true
		return result, fallbackError(
			fmt.Errorf("sites: rendered configuration rejected: %w", err),
			"restoring the previous fragments failed", restoreErr)
	}

	if err := a.Reloader.Reload(ctx); err != nil {
		restoreErr := a.restore(a.Dir, fragments, previous)
		result.Restored = true
		// The running proxy may have partially loaded the bad config; ask it to
		// reload the restored one. Best effort: the original error is the headline.
		_ = a.Reloader.Reload(ctx)
		return result, fallbackError(
			fmt.Errorf("sites: reload failed: %w", err),
			"restoring the previous fragments failed", restoreErr)
	}

	return result, nil
}

// write applies the desired set to dir, returning what changed. Content that is
// already identical is left untouched so the reload has nothing to do.
func (a *Applier) write(dir string, previous, desired map[string]string) (written, removed []string, err error) {
	for _, name := range sortedKeys(desired) {
		if prev, ok := previous[name]; ok && prev == desired[name] {
			continue
		}
		if wErr := writeFragment(dir, name, desired[name]); wErr != nil {
			return nil, nil, wErr
		}
		written = append(written, name)
	}

	for _, name := range sortedKeys(previous) {
		if _, keep := desired[name]; keep {
			continue
		}
		if rErr := os.Remove(filepath.Join(dir, name)); rErr != nil && !os.IsNotExist(rErr) {
			return written, removed, fmt.Errorf("sites: removing stale fragment %s: %w", name, rErr)
		}
		removed = append(removed, name)
	}

	return written, removed, nil
}

// restore puts dir back to the previous state, removing anything that was not
// there before.
func (a *Applier) restore(dir string, attempted, previous map[string]string) error {
	current, err := readFragments(dir)
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(current) {
		if _, wasThere := previous[name]; !wasThere {
			if rErr := os.Remove(filepath.Join(dir, name)); rErr != nil && !os.IsNotExist(rErr) {
				return fmt.Errorf("removing %s: %w", name, rErr)
			}
		}
	}
	for _, name := range sortedKeys(previous) {
		if cur, ok := current[name]; ok && cur == previous[name] {
			continue
		}
		if wErr := writeFragment(dir, name, previous[name]); wErr != nil {
			return wErr
		}
	}
	_ = attempted
	return nil
}

// writeFragment writes one file atomically: a temp file in the same directory,
// then a rename, so nginx never reads a half-written fragment.
func writeFragment(dir, name, content string) error {
	tmp, err := os.CreateTemp(dir, ".tmp-"+name+"-*")
	if err != nil {
		return fmt.Errorf("sites: creating temp file for %s: %w", name, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sites: writing %s: %w", name, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sites: setting mode on %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("sites: closing %s: %w", name, err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("sites: moving %s into place: %w", name, err)
	}
	tmpName = ""
	return nil
}

// readFragments loads every *.conf file in dir.
func readFragments(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("sites: reading %s: %w", dir, err)
	}

	out := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		data, rErr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rErr != nil {
			return nil, fmt.Errorf("sites: reading %s: %w", e.Name(), rErr)
		}
		out[e.Name()] = string(data)
	}
	return out, nil
}

// checkFragmentName rejects anything that could escape the fragment directory.
func checkFragmentName(name string) error {
	if name == "" {
		return errors.New("sites: empty fragment name")
	}
	if strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return fmt.Errorf("sites: fragment name %q is not a plain filename", name)
	}
	if !strings.HasSuffix(name, ".conf") {
		return fmt.Errorf("sites: fragment name %q must end in .conf", name)
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// fallbackError keeps the primary cause in front and appends the cleanup failure,
// so a rollback problem is never silently dropped.
func fallbackError(primary error, msg string, cleanup error) error {
	if cleanup == nil {
		return primary
	}
	return fmt.Errorf("%w (additionally: %s: %w)", primary, msg, cleanup)
}
