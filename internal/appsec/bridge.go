package appsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// BridgeScorer connects to the open-appsec engine daemon via Unix socket.
//
// The open-appsec daemon must be running as a separate process listening
// on a Unix socket. This client sends request features and receives
// an ML-based verdict + confidence score.
//
// Protocol:
//
//	POST /evaluate HTTP/1.1
//	Content-Type: application/json
//	{ "method": "GET", "uri": "/api/users", ... }
//
//	Response:
//	{ "verdict": "block", "score": 0.92, "confidence": 0.95, ... }
type BridgeScorer struct {
	socketPath string
	client     *http.Client
	enabled    bool
	timeout    time.Duration
}

func NewBridgeScorer(socketPath string, timeout time.Duration) *BridgeScorer {
	return &BridgeScorer{
		socketPath: socketPath,
		enabled:    true,
		timeout:    timeout,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.DialTimeout("unix", socketPath, timeout)
				},
				MaxIdleConns:    100,
				IdleConnTimeout: 90 * time.Second,
			},
			Timeout: timeout,
		},
	}
}

func (b *BridgeScorer) Name() string { return "open-appsec" }

func (b *BridgeScorer) Health(ctx context.Context) error {
	resp, err := b.client.Get("http://unix/health")
	if err != nil {
		return fmt.Errorf("open-appsec bridge unreachable: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("open-appsec bridge unhealthy: status %d", resp.StatusCode)
	}
	return nil
}

func (b *BridgeScorer) Evaluate(ctx context.Context, features *Features) (*Result, error) {
	if !b.enabled {
		return &Result{Verdict: VerdictAllow, Score: 0, ModelName: b.Name()}, nil
	}

	body, err := json.Marshal(features)
	if err != nil {
		return nil, fmt.Errorf("marshal features: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "http://unix/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		// Report the failure; do not invent a verdict. Whether an unreachable
		// scorer allows or denies is policy, and policy lives in one place: the
		// sidecar's appsec.fail_open. Silently returning "allow" here meant an
		// engine outage stopped scoring without anyone noticing.
		return nil, fmt.Errorf("scorer unreachable at %s: %w", b.socketPath, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// A 500 from the engine is not a verdict. Parsing it would attach a zero score
	// and an empty verdict to a request nobody scored.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scorer returned status %d", resp.StatusCode)
	}

	var result Result
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	result.ModelName = b.Name()

	return &result, nil
}

func (b *BridgeScorer) Close() error {
	b.client.CloseIdleConnections()
	return nil
}
