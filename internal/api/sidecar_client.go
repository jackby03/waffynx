package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/jackby03/waffynx/internal/rules"
)

// maxSidecarResponseBytes bounds a proxied sidecar response. Rules and learning
// records are small; the limit keeps a compromised or broken sidecar from
// forcing the API to allocate an unbounded buffer.
const maxSidecarResponseBytes = 4 << 20

// sidecarResponseError reports a non-success status from the sidecar. It is
// kept distinct from a transport error so handlers can answer 400 when the data
// plane refused a payload, and 503 only when it could not be asked at all.
type sidecarResponseError struct {
	StatusCode int
}

func (e *sidecarResponseError) Error() string {
	return fmt.Sprintf("sidecar returned status %d", e.StatusCode)
}

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

// sidecarControl is the control-plane view of the data plane: the custom-rule
// catalogue and the learning engine it owns. It is a separate interface from
// ruleInjector so a test double used to assert enforcement stays minimal.
type sidecarControl interface {
	ListRules(ctx context.Context) ([]rules.CustomRule, error)
	CreateRule(ctx context.Context, rule rules.CustomRule) (rules.CustomRule, error)
	DeleteRule(ctx context.Context, id string) error
	LearningSuggestions(ctx context.Context) (json.RawMessage, error)
	LearningStats(ctx context.Context) (json.RawMessage, error)
}

// sidecar returns the control-plane client, or nil when no sidecar is wired.
//
// The API keeps a single client per configured socket (Server.wafRules, built in
// NewServer). The assertion is deliberate: when no socket is configured there is
// no client and every proxy endpoint answers 503, rather than pretending the
// data plane has no rules. A fake injector likewise has no control surface.
func (s *Server) sidecar() sidecarControl {
	client, ok := s.wafRules.(sidecarControl)
	if !ok {
		return nil
	}
	return client
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
	// The id is escaped rather than concatenated: a caller-supplied value with
	// '&' or '#' would otherwise rewrite the sidecar's query string.
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://sidecar/rules/delete?id="+url.QueryEscape(id), nil)
	if err != nil {
		return fmt.Errorf("building rule request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reaching sidecar: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		return &sidecarResponseError{StatusCode: resp.StatusCode}
	}
	return nil
}

// getRaw fetches a JSON document from the sidecar.
func (c *sidecarClient) getRaw(ctx context.Context, path string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sidecar"+path, nil)
	if err != nil {
		return nil, fmt.Errorf("building sidecar request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching sidecar: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &sidecarResponseError{StatusCode: resp.StatusCode}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSidecarResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading sidecar response: %w", err)
	}
	return json.RawMessage(body), nil
}

// ListRules returns the custom rules the data plane is enforcing.
func (c *sidecarClient) ListRules(ctx context.Context) ([]rules.CustomRule, error) {
	raw, err := c.getRaw(ctx, "/rules")
	if err != nil {
		return nil, err
	}

	var list []rules.CustomRule
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decoding sidecar rules: %w", err)
	}
	if list == nil {
		list = []rules.CustomRule{}
	}
	return list, nil
}

// CreateRule adds a rule and returns the copy the sidecar stored, which carries
// the generated id when the caller did not supply one.
func (c *sidecarClient) CreateRule(ctx context.Context, rule rules.CustomRule) (rules.CustomRule, error) {
	body, err := json.Marshal(rule)
	if err != nil {
		return rules.CustomRule{}, fmt.Errorf("encoding rule: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://sidecar/rules/add", bytes.NewReader(body))
	if err != nil {
		return rules.CustomRule{}, fmt.Errorf("building rule request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return rules.CustomRule{}, fmt.Errorf("reaching sidecar: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return rules.CustomRule{}, &sidecarResponseError{StatusCode: resp.StatusCode}
	}

	createdBody, err := io.ReadAll(io.LimitReader(resp.Body, maxSidecarResponseBytes))
	if err != nil {
		return rules.CustomRule{}, fmt.Errorf("reading sidecar response: %w", err)
	}
	var created rules.CustomRule
	if err := json.Unmarshal(createdBody, &created); err != nil {
		return rules.CustomRule{}, fmt.Errorf("decoding created rule: %w", err)
	}
	return created, nil
}

// LearningSuggestions returns the sidecar's suggestion list verbatim so field
// names and ordering are owned by the data plane, not duplicated here.
func (c *sidecarClient) LearningSuggestions(ctx context.Context) (json.RawMessage, error) {
	raw, err := c.getRaw(ctx, "/learning/suggestions")
	if err != nil {
		return nil, err
	}

	// Validate the shape: the API wraps this value as {"suggestions": ...}, and
	// an object there would hand the dashboard something it cannot iterate.
	var probe []json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("sidecar suggestions are not a JSON array: %w", err)
	}
	if probe == nil {
		return json.RawMessage("[]"), nil
	}
	return raw, nil
}

// LearningStats returns the sidecar's stats object verbatim.
func (c *sidecarClient) LearningStats(ctx context.Context) (json.RawMessage, error) {
	raw, err := c.getRaw(ctx, "/learning/stats")
	if err != nil {
		return nil, err
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("sidecar stats are not a JSON object: %w", err)
	}
	if probe == nil {
		return json.RawMessage("{}"), nil
	}
	return raw, nil
}
