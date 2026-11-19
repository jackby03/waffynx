package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/rules"
)

// fakeSidecar stands in for the Unix-socket client. It implements ruleInjector
// as well as sidecarControl because the API holds one client for both roles.
type fakeSidecar struct {
	rules       []rules.CustomRule
	created     []rules.CustomRule
	deleted     []string
	suggestions json.RawMessage
	stats       json.RawMessage

	listErr     error
	createErr   error
	deleteErr   error
	learningErr error
}

func (f *fakeSidecar) AddRule(_ context.Context, _ rules.CustomRule) error {
	return nil
}

func (f *fakeSidecar) ListRules(_ context.Context) ([]rules.CustomRule, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.rules, nil
}

func (f *fakeSidecar) CreateRule(_ context.Context, rule rules.CustomRule) (rules.CustomRule, error) {
	if f.createErr != nil {
		return rules.CustomRule{}, f.createErr
	}
	if rule.ID == "" {
		rule.ID = "generated-1"
	}
	f.created = append(f.created, rule)
	return rule, nil
}

func (f *fakeSidecar) DeleteRule(_ context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeSidecar) LearningSuggestions(_ context.Context) (json.RawMessage, error) {
	if f.learningErr != nil {
		return nil, f.learningErr
	}
	return f.suggestions, nil
}

func (f *fakeSidecar) LearningStats(_ context.Context) (json.RawMessage, error) {
	if f.learningErr != nil {
		return nil, f.learningErr
	}
	return f.stats, nil
}

func newSidecarTestServer(t *testing.T, sidecar *fakeSidecar) (*Server, http.Handler, string) {
	t.Helper()

	srv, handler := newTestAPIServer(t, nil)
	srv.wafRules = sidecar

	token, err := srv.authMgr.GenerateToken("admin", "admin", []string{"read", "write"})
	if err != nil {
		t.Fatalf("generating admin token: %v", err)
	}
	return srv, handler, token
}

func serveTestRequest(handler http.Handler, method, target, token, body string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// waffEvent builds the minimal valid blocked event for history assertions.
func waffEvent(t *testing.T, path string) events.WafEvent {
	t.Helper()
	return events.WafEvent{Type: events.TypeBlocked, Path: path, RuleID: "rule-1"}
}

func decodeErrorBody(t *testing.T, rec *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body %q: %v", rec.Body.String(), err)
	}
	return body.Error, body.Message
}

func TestAPI_CustomRuleListReturnsEnforcedRules(t *testing.T) {
	sidecar := &fakeSidecar{rules: []rules.CustomRule{{
		ID: "rule-1", Name: "block login", Enabled: true, Action: rules.ActionBlock,
	}}}
	_, handler, token := newSidecarTestServer(t, sidecar)

	rec := serveTestRequest(handler, http.MethodGet, "/api/v1/custom-rules", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Rules []rules.CustomRule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Rules) != 1 || body.Rules[0].ID != "rule-1" {
		t.Fatalf("rules = %+v, want the sidecar rule", body.Rules)
	}
}

// TestAPI_CustomRuleListWithoutSidecarIs503 is the regression guard for the
// fail-open shape: an unreachable data plane must never look like "there are no
// custom rules", because an operator would then believe nothing is enforced.
func TestAPI_CustomRuleListWithoutSidecarIs503(t *testing.T) {
	srv, handler := newTestAPIServer(t, nil)
	token := rulesTestToken(t, srv)

	rec := serveTestRequest(handler, http.MethodGet, "/api/v1/custom-rules", token, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %q)", rec.Code, rec.Body.String())
	}
	apiErr, message := decodeErrorBody(t, rec)
	if apiErr != http.StatusText(http.StatusServiceUnavailable) {
		t.Errorf("error = %q, want %q", apiErr, http.StatusText(http.StatusServiceUnavailable))
	}
	if message == "" {
		t.Error("message is empty")
	}
}

func TestAPI_CustomRuleCreateRequiresAdmin(t *testing.T) {
	sidecar := &fakeSidecar{}
	srv, handler, _ := newSidecarTestServer(t, sidecar)

	token, err := srv.authMgr.GenerateToken("viewer", "viewer", []string{"read"})
	if err != nil {
		t.Fatalf("generating viewer token: %v", err)
	}

	rec := serveTestRequest(handler, http.MethodPost, "/api/v1/custom-rules", token, `{"name":"nope"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if len(sidecar.created) != 0 {
		t.Fatalf("sidecar received %d rules, want none", len(sidecar.created))
	}
}

func TestAPI_CustomRuleCreateProxiesAndAudits(t *testing.T) {
	sidecar := &fakeSidecar{}
	srv, handler, token := newSidecarTestServer(t, sidecar)

	rec := serveTestRequest(handler, http.MethodPost, "/api/v1/custom-rules", token,
		`{"id":"rule-1","name":"block login","enabled":true,"action":"block"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	var created rules.CustomRule
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.ID != "rule-1" {
		t.Errorf("created id = %q, want rule-1", created.ID)
	}
	if len(sidecar.created) != 1 {
		t.Fatalf("sidecar received %d rules, want 1", len(sidecar.created))
	}

	events := srv.audit.Query(audit.QueryFilter{Limit: 10, Action: "custom_rule_create"})
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].Actor != "admin" || events[0].Resource != "rule-1" {
		t.Errorf("audit event = %+v, want actor admin and resource rule-1", events[0])
	}
}

func TestAPI_CustomRuleCreateRejectsInvalidID(t *testing.T) {
	for _, id := range []string{"bad/id", "bad id"} {
		sidecar := &fakeSidecar{}
		_, handler, token := newSidecarTestServer(t, sidecar)

		rec := serveTestRequest(handler, http.MethodPost, "/api/v1/custom-rules", token,
			`{"id":"`+id+`","name":"unsafe"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("id %q: status = %d, want 400: %s", id, rec.Code, rec.Body.String())
		}
		if len(sidecar.created) != 0 {
			t.Fatalf("id %q reached the sidecar", id)
		}
	}
}

func TestAPI_CustomRuleDeleteProxiesAndAudits(t *testing.T) {
	sidecar := &fakeSidecar{}
	srv, handler, token := newSidecarTestServer(t, sidecar)

	rec := serveTestRequest(handler, http.MethodDelete, "/api/v1/custom-rules/rule-1", token, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", rec.Code, rec.Body.String())
	}
	if len(sidecar.deleted) != 1 || sidecar.deleted[0] != "rule-1" {
		t.Fatalf("deleted = %v, want [rule-1]", sidecar.deleted)
	}

	events := srv.audit.Query(audit.QueryFilter{Limit: 10, Action: "custom_rule_delete"})
	if len(events) != 1 || events[0].Resource != "rule-1" {
		t.Fatalf("audit events = %+v, want one for rule-1", events)
	}
}

func TestAPI_CustomRuleDeleteRejectsInvalidID(t *testing.T) {
	sidecar := &fakeSidecar{}
	_, handler, token := newSidecarTestServer(t, sidecar)

	rec := serveTestRequest(handler, http.MethodDelete, "/api/v1/custom-rules/bad%20id", token, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if len(sidecar.deleted) != 0 {
		t.Fatalf("invalid id reached the sidecar: %v", sidecar.deleted)
	}
}

func TestAPI_CustomRuleDeleteSidecarFailureIs503(t *testing.T) {
	sidecar := &fakeSidecar{deleteErr: errors.New("dial unix /run/waffynx.sock: connect: no such file")}
	_, handler, token := newSidecarTestServer(t, sidecar)

	rec := serveTestRequest(handler, http.MethodDelete, "/api/v1/custom-rules/rule-1", token, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "waffynx.sock") {
		t.Errorf("response leaked the socket path: %s", rec.Body.String())
	}
}

// A sidecar that actively rejects the payload is not "unavailable": the request
// is bad, and the operator needs to see that instead of a 503.
func TestAPI_CustomRuleDeleteSidecarRejectionIs400(t *testing.T) {
	sidecar := &fakeSidecar{deleteErr: &sidecarResponseError{StatusCode: http.StatusBadRequest}}
	_, handler, token := newSidecarTestServer(t, sidecar)

	rec := serveTestRequest(handler, http.MethodDelete, "/api/v1/custom-rules/rule-1", token, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestAPI_EventHistoryNewestFirst(t *testing.T) {
	srv, handler, token := newSidecarTestServer(t, &fakeSidecar{})

	for _, path := range []string{"/a", "/b", "/c"} {
		srv.broker.Publish(waffEvent(t, path))
	}

	rec := serveTestRequest(handler, http.MethodGet, "/api/v1/events/history?limit=2", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Events []struct {
			Path string `json:"path"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Events) != 2 || body.Events[0].Path != "/c" || body.Events[1].Path != "/b" {
		t.Fatalf("events = %+v, want [/c /b] newest first", body.Events)
	}
}

func TestAPI_EventHistoryRejectsInvalidLimit(t *testing.T) {
	srv, handler, token := newSidecarTestServer(t, &fakeSidecar{})
	srv.broker.Publish(waffEvent(t, "/a"))

	for _, limit := range []string{"abc", "0", "-1", "1001"} {
		rec := serveTestRequest(handler, http.MethodGet, "/api/v1/events/history?limit="+limit, token, "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("limit %q: status = %d, want 400", limit, rec.Code)
		}
	}
}

func TestAPI_EventHistoryWithoutBrokerIsEmpty(t *testing.T) {
	srv, handler, token := newSidecarTestServer(t, &fakeSidecar{})
	srv.broker = nil

	rec := serveTestRequest(handler, http.MethodGet, "/api/v1/events/history", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"events":[]`) {
		t.Fatalf("body = %q, want an empty events array", rec.Body.String())
	}
}

func TestAPI_MeReturnsValidatedClaims(t *testing.T) {
	_, handler, token := newSidecarTestServer(t, &fakeSidecar{})

	rec := serveTestRequest(handler, http.MethodGet, "/api/v1/auth/me", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Username string   `json:"username"`
		Role     string   `json:"role"`
		Scopes   []string `json:"scopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Username != "admin" || body.Role != "admin" {
		t.Errorf("identity = %+v, want admin/admin", body)
	}
	if len(body.Scopes) != 2 || body.Scopes[0] != "read" {
		t.Errorf("scopes = %v, want [read write]", body.Scopes)
	}
}

func TestAPI_MeRequiresAuth(t *testing.T) {
	_, handler, _ := newSidecarTestServer(t, &fakeSidecar{})

	rec := serveTestRequest(handler, http.MethodGet, "/api/v1/auth/me", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rec.Code, rec.Body.String())
	}
}
