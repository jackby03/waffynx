package main

import (
	"io"
	"testing"

	"github.com/jackby03/waffynx/internal/config"
)

// verifyConfig is a minimal configuration that mirrors the shipped defaults for
// the plugins the corpus depends on: request validation must block, bot
// protection stays in log mode (which is why the sqlmap case is skipped).
func verifyConfig() *config.Config {
	return &config.Config{
		Name: "waffynx-verify-test",
		// The command-injection cases are caught by the ML scorer, not by the
		// request-validation patterns, so the self-test needs it enabled.
		AppSec: config.AppSecConfig{Enabled: true},
		Plugins: []config.PluginConfig{
			{Name: "request-validation", Enabled: true, Config: map[string]interface{}{}},
			{Name: "bot-protection", Enabled: true, Config: map[string]interface{}{"mode": "log"}},
		},
	}
}

// TestVerifyCorpus exercises the CLI's self-test through the same pipeline that
// serves live traffic. It is the regression guard for two things at once:
//
//   - the corpus expectations stay honest (benign allowed, attacks blocked);
//   - the SQLi comment-terminator gap stays fixed ("admin'--" used to pass).
func TestVerifyCorpus(t *testing.T) {
	cfg := verifyConfig()

	if err := runVerify(cfg, true, io.Discard); err != nil {
		t.Fatalf("self-test reported failures: %v", err)
	}
}

// TestVerifyCorpusCatchesMissingPatterns proves the tool actually detects a
// regression rather than always passing: with request validation disabled,
// attacks get through and verify must fail.
func TestVerifyCorpusCatchesMissingPatterns(t *testing.T) {
	cfg := &config.Config{
		Name: "waffynx-verify-test-no-plugins",
		Plugins: []config.PluginConfig{
			{Name: "request-validation", Enabled: false},
		},
	}

	if err := runVerify(cfg, true, io.Discard); err == nil {
		t.Fatal("expected the self-test to fail when request validation is disabled, got success")
	}
}
