package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
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
	scorer     appsec.Scorer // ML anomaly scorer (may be nil)
}

func NewSidecar(socketPath string, eval policy.Evaluator, chain *plugin.Chain, scorer appsec.Scorer) *Sidecar {
	return &Sidecar{
		socketPath: socketPath,
		chain:      chain,
		engine:     eval,
		scorer:     scorer,
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

	logging.Debug().
		Str("method", req.Method).
		Str("host", req.Host).
		Str("path", req.Path).
		Str("ip", req.RemoteIP).
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
	ctx, err := s.chain.Execute(ctx, plugin.PhasePreRequest)
	if err != nil {
		logging.Warn().Err(err).Msg("plugin chain blocked request")
		s.respondDeny(w, "plugin-chain", err.Error())
		return
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
		return
	}

	// Stage 3: ML-based anomaly detection
	if s.scorer != nil {
		appsecResult, err := s.scorer.Evaluate(ctx, &appsec.Features{
			Method:      req.Method,
			URI:         req.Path,
			Host:        req.Host,
			ClientIP:    req.RemoteIP,
			UserAgent:   r.Header.Get("X-WN-UA"),
			ContentType: r.Header.Get("X-WN-CT"),
			Referer:     r.Header.Get("X-WN-Ref"),
			URILength:   len(req.Path),
			QueryParams: parseQueryParams(req.Path),
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
