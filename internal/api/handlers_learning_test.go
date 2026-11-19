package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestAPI_LearningSuggestionsProxiesSidecar(t *testing.T) {
	sidecar := &fakeSidecar{suggestions: json.RawMessage(`[{"rule_id":"rule-1","reason":"repeated blocks"}]`)}
	_, handler, token := newSidecarTestServer(t, sidecar)

	rec := serveTestRequest(handler, http.MethodGet, "/api/v1/learning/suggestions", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Suggestions []map[string]interface{} `json:"suggestions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Suggestions) != 1 || body.Suggestions[0]["rule_id"] != "rule-1" {
		t.Fatalf("suggestions = %+v, want the sidecar payload", body.Suggestions)
	}
}

func TestAPI_LearningStatsPassesThrough(t *testing.T) {
	sidecar := &fakeSidecar{stats: json.RawMessage(`{"total":3,"allowed":2,"blocked":1}`)}
	_, handler, token := newSidecarTestServer(t, sidecar)

	rec := serveTestRequest(handler, http.MethodGet, "/api/v1/learning/stats", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["total"] != float64(3) || body["blocked"] != float64(1) {
		t.Fatalf("stats = %+v, want the sidecar object unchanged", body)
	}
}

func TestAPI_LearningWithoutSidecarIs503(t *testing.T) {
	srv, handler := newTestAPIServer(t, nil)
	token := rulesTestToken(t, srv)

	for _, path := range []string{"/api/v1/learning/suggestions", "/api/v1/learning/stats"} {
		rec := serveTestRequest(handler, http.MethodGet, path, token, "")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, want 503 (body %q)", path, rec.Code, rec.Body.String())
		}
		apiErr, message := decodeErrorBody(t, rec)
		if apiErr != http.StatusText(http.StatusServiceUnavailable) || message == "" {
			t.Errorf("%s: error = %q message = %q, want a populated 503", path, apiErr, message)
		}
	}
}

func TestAPI_LearningSidecarFailureIs503(t *testing.T) {
	sidecar := &fakeSidecar{learningErr: errors.New("dial unix: connection refused")}
	_, handler, token := newSidecarTestServer(t, sidecar)

	for _, path := range []string{"/api/v1/learning/suggestions", "/api/v1/learning/stats"} {
		rec := serveTestRequest(handler, http.MethodGet, path, token, "")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, want 503 (body %q)", path, rec.Code, rec.Body.String())
		}
	}
}
