//go:build !linux || !cgo

package appsec

import (
	"context"
	"fmt"
)

type CPPBridgeScorer struct {
	enabled bool
}

func NewCPPBridgeScorer(waapDataPath string) (*CPPBridgeScorer, error) {
	return &CPPBridgeScorer{enabled: false}, nil
}

func (s *CPPBridgeScorer) Name() string     { return "open-appsec-cpp (stub)" }
func (s *CPPBridgeScorer) Health(ctx context.Context) error { return fmt.Errorf("CGo bridge unavailable on this platform") }
func (s *CPPBridgeScorer) Close() error     { return nil }
func (s *CPPBridgeScorer) Evaluate(ctx context.Context, features *Features) (*Result, error) {
	return &Result{Verdict: VerdictAllow, Score: 0, Confidence: 1.0, ModelName: s.Name()}, nil
}
