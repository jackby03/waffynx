package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackby03/waffynx/internal/rules"
)

// fakeRuleInjector records what the API asked the data plane to enforce.
type fakeRuleInjector struct {
	added   []rules.CustomRule
	deleted []string
	addErr  error
	delErr  error
}

func (f *fakeRuleInjector) AddRule(_ context.Context, rule rules.CustomRule) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, rule)
	return nil
}

func (f *fakeRuleInjector) DeleteRule(_ context.Context, id string) error {
	if f.delErr != nil {
		return f.delErr
	}
	f.deleted = append(f.deleted, id)
	return nil
}

func newFirewallTestServer(t *testing.T, injector *fakeRuleInjector) (*Server, http.Handler, string) {
	t.Helper()

	srv, handler := newTestAPIServer(t, nil)
	srv.wafRules = injector

	token, err := srv.authMgr.GenerateToken("admin", "admin", []string{"read", "write"})
	if err != nil {
		t.Fatalf("failed to generate admin token: %v", err)
	}
	return srv, handler, token
}

// TestAPI_FirewallBanEnforcedAtWAFLayer is the regression guard for the
// fail-open ban: the handler used to call `_ = firewall.BlockIP(ip)`, which
// shells out to host nftables/ufw. In a container that either fails or only
// affects the container's own network namespace, and the API returned
// 201 Created regardless — telling the user an IP was blocked when nothing was.
func TestAPI_FirewallBanEnforcedAtWAFLayer(t *testing.T) {
	injector := &fakeRuleInjector{}
	srv, handler, token := newFirewallTestServer(t, injector)

	body, _ := json.Marshal(map[string]any{"ip": "203.0.113.7", "reason": "manual", "ttl": 60})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/block", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	if len(injector.added) != 1 {
		t.Fatalf("expected exactly one WAF rule pushed, got %d", len(injector.added))
	}
	rule := injector.added[0]
	if rule.ID != ruleIDForIP("203.0.113.7") {
		t.Errorf("expected deterministic rule id %q, got %q", ruleIDForIP("203.0.113.7"), rule.ID)
	}
	if len(rule.IPs) != 1 || rule.IPs[0] != "203.0.113.7" {
		t.Errorf("expected rule scoped to the banned IP, got %v", rule.IPs)
	}
	if rule.Action != rules.ActionBlock || !rule.Enabled {
		t.Errorf("expected an enabled block rule, got action=%q enabled=%v", rule.Action, rule.Enabled)
	}

	srv.firewallMu.RLock()
	_, recorded := srv.bannedIPs["203.0.113.7"]
	srv.firewallMu.RUnlock()
	if !recorded {
		t.Error("expected the ban to be recorded after a successful WAF rule push")
	}
}

// TestAPI_FirewallBanRefusesToClaimSuccess covers the case where no layer can
// enforce. Reporting 201 here is the fail-open defect; the API must refuse.
func TestAPI_FirewallBanRefusesToClaimSuccess(t *testing.T) {
	injector := &fakeRuleInjector{addErr: errors.New("sidecar unreachable")}
	srv, handler, token := newFirewallTestServer(t, injector)

	body, _ := json.Marshal(map[string]any{"ip": "198.51.100.9", "reason": "manual"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/block", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no layer can enforce, got %d: %s", rec.Code, rec.Body.String())
	}

	srv.firewallMu.RLock()
	_, recorded := srv.bannedIPs["198.51.100.9"]
	srv.firewallMu.RUnlock()
	if recorded {
		t.Error("ban must not be recorded when it was not enforced")
	}
}

func TestAPI_FirewallUnbanRemovesWAFLayerRule(t *testing.T) {
	injector := &fakeRuleInjector{}
	srv, handler, token := newFirewallTestServer(t, injector)

	srv.bannedIPs["203.0.113.8"] = BannedIP{IP: "203.0.113.8"}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/firewall/unblock/203.0.113.8", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(injector.deleted) != 1 || injector.deleted[0] != ruleIDForIP("203.0.113.8") {
		t.Fatalf("expected the IP ban rule to be deleted, got %v", injector.deleted)
	}

	srv.firewallMu.RLock()
	_, stillBanned := srv.bannedIPs["203.0.113.8"]
	srv.firewallMu.RUnlock()
	if stillBanned {
		t.Error("expected the ban record to be removed")
	}
}
