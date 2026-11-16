package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jackby03/waffynx/internal/rules"
)

// ruleInjector pushes enforcement decisions into the data plane.
//
// The sidecar is the only enforcement point that works without privileges: it
// evaluates custom rules on every request (internal/engine/sidecar.go, stage 1)
// and a rule matching RemoteIP denies the request outright. Kernel-level
// filtering (nftables) is an enhancement available only in system mode.
type ruleInjector interface {
	AddRule(ctx context.Context, rule rules.CustomRule) error
	DeleteRule(ctx context.Context, id string) error
}

// ruleIDForIP is deterministic so a ban can be lifted without keeping server
// state in sync with the sidecar.
func ruleIDForIP(ip string) string {
	return "ip-ban-" + ip
}

// sidecarClient talks to the sidecar over its Unix domain socket.
type sidecarClient struct {
	http *http.Client
}

func newSidecarClient(socketPath string, timeout time.Duration) *sidecarClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &sidecarClient{http: &http.Client{Transport: transport, Timeout: timeout}}
}

func (c *sidecarClient) AddRule(ctx context.Context, rule rules.CustomRule) error {
	body, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("encoding rule: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://sidecar/rules/add", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building rule request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reaching sidecar: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("sidecar rejected rule: status %d", resp.StatusCode)
	}
	return nil
}

func (c *sidecarClient) DeleteRule(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://sidecar/rules/delete?id="+id, nil)
	if err != nil {
		return fmt.Errorf("building rule request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reaching sidecar: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("sidecar rejected rule deletion: status %d", resp.StatusCode)
	}
	return nil
}
