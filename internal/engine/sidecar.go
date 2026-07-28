package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/learning"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
	wrules "github.com/jackby03/waffynx/internal/rules"
)

// Sidecar is the Unix socket HTTP server that nginx's waffynx module
// calls to evaluate every request against the WAF policy engine.
//
// Evaluation pipeline (in order):
//   1. Plugin chain (pattern matching: SQLi, XSS, rate-limit, bots...)
//   2. Policy engine (custom WAF rules)
//   3. Appsec scorer (ML-based anomaly detection: basic-go or open-appsec)
//
// Protocol:
//
//	nginx  -->  GET /evaluate HTTP/1.0
//	           X-WN-M: GET
//	           X-WN-U: /api/users
//	           X-WN-H: example.com
//	           X-WN-IP: 192.168.1.1
//	           X-WN-UA: curl/7.68.0
//
//	sidecar -->  HTTP/1.0 204 No Content        (allow)
//	sidecar -->  HTTP/1.0 403 Forbidden          (deny)
//	             X-WN-Rule: sql-001
type Sidecar struct {
	socketPath string
	listener   net.Listener
	server     *http.Server
	chain      *plugin.Chain
	engine     policy.Evaluator
	scorer     appsec.Scorer
	learning   *learning.Engine
	audit      *audit.Store
	rules      *wrules.Engine
	broker     *events.Broker
}

func NewSidecar(socketPath string, eval policy.Evaluator, chain *plugin.Chain, scorer appsec.Scorer, learn *learning.Engine, a *audit.Store, r *wrules.Engine, b *events.Broker) *Sidecar {
	return &Sidecar{
		socketPath: socketPath,
		chain:      chain,
		engine:     eval,
		scorer:     scorer,
		learning:   learn,
		audit:      a,
		rules:      r,
		broker:     b,
	}
}

func (s *Sidecar) Start() error {
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing old socket: %w", err)
	}

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("unix listen on %s: %w", s.socketPath, err)
	}
	s.listener = ln

	if err := os.Chmod(s.socketPath, 0666); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/evaluate", s.handleEvaluate)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/learning/suggestions", s.handleLearningSuggestions)
	mux.HandleFunc("/learning/stats", s.handleLearningStats)
	mux.HandleFunc("/learning/dataset", s.handleLearningDataset)
	mux.HandleFunc("/rules", s.handleRulesList)
	mux.HandleFunc("/rules/add", s.handleRulesAdd)
	mux.HandleFunc("/rules/delete", s.handleRulesDelete)
	mux.HandleFunc("/events", s.handleSSE)

	s.server = &http.Server{Handler: mux}

	go func() {
		logging.Info().
			Str("socket", s.socketPath).
			Msg("sidecar listening for nginx module")
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			logging.Error().Err(err).Msg("sidecar serve error")
		}
	}()

	return nil
}

func (s *Sidecar) Stop() error {
	logging.Info().Msg("stopping sidecar")
	if err := s.server.Close(); err != nil {
		return err
	}
	os.Remove(s.socketPath)
	return nil
}

func (s *Sidecar) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","service":"waffynx-sidecar"}`))
}

func (s *Sidecar) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	req := &policy.Request{
		Method:   r.Header.Get("X-WN-M"),
		Host:     r.Header.Get("X-WN-H"),
		Path:     r.Header.Get("X-WN-U"),
		RemoteIP: r.Header.Get("X-WN-IP"),
		Headers: map[string][]string{
			"User-Agent":  {r.Header.Get("X-WN-UA")},
			"Content-Type": {r.Header.Get("X-WN-CT")},
			"Referer":     {r.Header.Get("X-WN-Ref")},
		},
	}

	const maxBodyRead = 65536
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBodyRead))
	if err == nil && len(bodyBytes) > 0 {
		req.Body = bodyBytes
	}

	start := time.Now()

	logging.Debug().
		Str("method", req.Method).
		Str("host", req.Host).
		Str("path", req.Path).
		Str("ip", req.RemoteIP).
		Int("body_len", len(bodyBytes)).
		Msg("evaluating request")

	// Plugins look at ctx.Request which is the SIDECAR request (/evaluate),
	// not the ORIGINAL. We inject the original request data into ctx.Values
	// so plugins can access it.
	ctx := plugin.NewContext(context.Background(), w, r)
	ctx.Values["wn_method"]   = req.Method
	ctx.Values["wn_uri"]      = req.Path
	ctx.Values["wn_host"]     = req.Host
	ctx.Values["wn_ip"]       = req.RemoteIP
	ctx.Values["wn_ua"]       = r.Header.Get("X-WN-UA")
	ctx.Values["wn_ct"]       = r.Header.Get("X-WN-CT")
	ctx.Values["wn_ref"]      = r.Header.Get("X-WN-Ref")
	if len(bodyBytes) > 0 {
		ctx.Values["wn_body"] = string(bodyBytes)
	}
	ctx, err = s.chain.Execute(ctx, plugin.PhasePreRequest)
	if err != nil {
		logging.Warn().Err(err).Msg("plugin chain blocked request")
		if ctx.StatusCode == 0 {
			s.respondDeny(w, "plugin-chain", err.Error())
		}
		s.recordLearning(req, "block", "plugin-chain", err.Error(), start)
		return
	}

	if s.rules != nil {
		rulesResult := s.rules.Evaluate(req)
		if rulesResult.Action != wrules.ActionAllow && rulesResult.Action != wrules.ActionLog {
			logging.Warn().Str("rule_id", rulesResult.RuleID).Msg("custom rule blocked request")
			s.respondDeny(w, rulesResult.RuleID, rulesResult.Reason)
			s.recordLearning(req, "block", rulesResult.RuleID, rulesResult.Reason, start)
			return
		}
	}

	// Stage 2: Run through policy engine
	policyResult := s.engine.Evaluate(ctx, policy.PhaseRequest, req)

	if policyResult.Action != policy.ActionAllow && policyResult.Action != policy.ActionLog {
		logging.Warn().
			Str("action", string(policyResult.Action)).
			Str("rule_id", policyResult.RuleID).
			Str("reason", policyResult.Reason).
			Msg("policy blocked request")
		s.respondDeny(w, policyResult.RuleID, policyResult.Reason)
		s.recordLearning(req, "block", policyResult.RuleID, policyResult.Reason, start)
		return
	}

	// Stage 3: ML-based anomaly detection
	if s.scorer != nil {
		appsecResult, err := s.scorer.Evaluate(ctx, &appsec.Features{
			Method:       req.Method,
			URI:          req.Path,
			Host:         req.Host,
			ClientIP:     req.RemoteIP,
			UserAgent:    r.Header.Get("X-WN-UA"),
			ContentType:  r.Header.Get("X-WN-CT"),
			Referer:      r.Header.Get("X-WN-Ref"),
			Body:         bodyBytes,
			URILength:    len(req.Path),
			PayloadSize:  int64(len(bodyBytes)),
			HasPayload:   len(bodyBytes) > 0,
			QueryParams:  parseQueryParams(req.Path),
		})
		if err != nil {
			logging.Warn().Err(err).Msg("appsec scorer error, allowing request")
		} else {
			logging.Debug().
				Str("model", appsecResult.ModelName).
				Float64("score", appsecResult.Score).
				Float64("confidence", appsecResult.Confidence).
				Str("verdict", string(appsecResult.Verdict)).
				Strs("anomalies", appsecResult.Anomalies).
				Msg("appsec evaluation")

			if appsecResult.Verdict == appsec.VerdictBlock {
				logging.Warn().
					Float64("score", appsecResult.Score).
					Strs("reasons", appsecResult.Reasons).
					Msg("appsec blocked request")
				reason := fmt.Sprintf("ML anomaly: %s", strings.Join(appsecResult.Reasons, "; "))
				s.respondDeny(w, "appsec-"+appsecResult.ModelName, reason)
				s.recordLearning(req, "block", "appsec-"+appsecResult.ModelName, reason, start)
				return
			}

			if appsecResult.Verdict == appsec.VerdictSuspicious {
				logging.Warn().
					Float64("score", appsecResult.Score).
					Strs("reasons", appsecResult.Reasons).
					Msg("appsec suspicious request (allowing)")
			}
		}
	}

	// All stages passed: allow
	s.respondAllow(w)
	s.recordLearning(req, "allow", "", "", start)
}

// parseQueryParams extracts query parameters from a URI string.
func parseQueryParams(rawURI string) map[string]string {
	params := make(map[string]string)

	idx := strings.Index(rawURI, "?")
	if idx < 0 || idx == len(rawURI)-1 {
		return params
	}

	queryStr := rawURI[idx+1:]

	// URL decode first
	decoded, err := url.QueryUnescape(queryStr)
	if err != nil {
		decoded = queryStr
	}
	// Also handle + as space
	decoded = strings.ReplaceAll(decoded, "+", " ")

	for _, pair := range strings.Split(decoded, "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = kv[1]
		} else if len(kv) == 1 && kv[0] != "" {
			params[kv[0]] = ""
		}
	}

	return params
}

func (s *Sidecar) respondAllow(w http.ResponseWriter) {
	w.Header().Set("X-WN-Verdict", "allow")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Sidecar) respondDeny(w http.ResponseWriter, ruleID, reason string) {
	w.Header().Set("X-WN-Verdict", "deny")
	w.Header().Set("X-WN-Rule", ruleID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	fmt.Fprintf(w, `{"error":"blocked by WAF","rule_id":"%s","reason":"%s"}`, ruleID, reason)
}

func (s *Sidecar) handleLearningSuggestions(w http.ResponseWriter, r *http.Request) {
	if s.learning == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
		return
	}
	suggestions := s.learning.Suggestions()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(suggestions)
}

func (s *Sidecar) handleLearningStats(w http.ResponseWriter, r *http.Request) {
	if s.learning == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
		return
	}
	stats := s.learning.Stats()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

func (s *Sidecar) handleRulesList(w http.ResponseWriter, r *http.Request) {
	if s.rules == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
		return
	}
	rules := s.rules.List()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(rules)
}

func (s *Sidecar) handleRulesAdd(w http.ResponseWriter, r *http.Request) {
	if s.rules == nil {
		s.writeSidecarError(w, "rules engine not available", http.StatusServiceUnavailable)
		return
	}
	var rule wrules.CustomRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		s.writeSidecarError(w, "invalid rule JSON", http.StatusBadRequest)
		return
	}
	rule.ID = fmt.Sprintf("custom-%d", time.Now().UnixNano())
	s.rules.AddRule(rule)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}

func (s *Sidecar) handleRulesDelete(w http.ResponseWriter, r *http.Request) {
	if s.rules == nil {
		s.writeSidecarError(w, "rules engine not available", http.StatusServiceUnavailable)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		s.writeSidecarError(w, "missing id parameter", http.StatusBadRequest)
		return
	}
	s.rules.RemoveRule(id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Sidecar) handleSSE(w http.ResponseWriter, r *http.Request) {
	if s.broker == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := s.broker.Subscribe()
	defer s.broker.Unsubscribe(ch)

	w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			w.Write([]byte("data: "))
			w.Write(data)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}

func (s *Sidecar) writeSidecarError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Sidecar) handleLearningDataset(w http.ResponseWriter, r *http.Request) {
	if s.learning == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
		return
	}
	dataset := s.learning.ExportDataset()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(dataset)
}

func (s *Sidecar) recordLearning(req *policy.Request, verdict, ruleID, reason string, start time.Time) {
	if s.learning == nil {
		return
	}

	bodySnippet := ""
	if len(req.Body) > 0 {
		body := string(req.Body)
		if len(body) > 100 {
			bodySnippet = body[:100]
		} else {
			bodySnippet = body
		}
	}

	s.learning.Record(learning.Record{
		Method:      req.Method,
		Path:        req.Path,
		Host:        req.Host,
		RemoteIP:    req.RemoteIP,
		BodySnippet: bodySnippet,
		Verdict:     learning.Verdict(verdict),
		RuleID:      ruleID,
		Reason:      reason,
		Duration:    time.Since(start),
	})

	if s.audit != nil && verdict == "block" {
		s.audit.Record(audit.Event{
			Actor:   req.RemoteIP,
			ActorIP: req.RemoteIP,
			Action:  req.Method + " " + req.Path,
			Resource: req.Host,
			Result:  "blocked",
			Details: fmt.Sprintf("rule=%s reason=%s", ruleID, reason),
		})
	}

	if s.broker != nil && verdict == "block" {
		s.broker.Publish(events.WafEvent{
			Type:     events.TypeBlocked,
			Method:   req.Method,
			Path:     req.Path,
			RemoteIP: req.RemoteIP,
			RuleID:   ruleID,
			Reason:   reason,
		})
	}
}
