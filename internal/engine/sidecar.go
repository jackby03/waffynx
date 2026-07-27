package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
)

// Sidecar is the Unix socket HTTP server that nginx's waffynx module
// calls to evaluate every request against the WAF policy engine.
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
}

func NewSidecar(socketPath string, eval policy.Evaluator, chain *plugin.Chain) *Sidecar {
	return &Sidecar{
		socketPath: socketPath,
		chain:      chain,
		engine:     eval,
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
		Method:  r.Header.Get("X-WN-M"),
		Host:    r.Header.Get("X-WN-H"),
		Path:    r.Header.Get("X-WN-U"),
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

	// Run through plugin chain first
	ctx := plugin.NewContext(context.Background(), w, r)
	ctx, err := s.chain.Execute(ctx, plugin.PhasePreRequest)
	if err != nil {
		logging.Warn().Err(err).Msg("plugin chain blocked request")
		s.respondDeny(w, "plugin-chain", err.Error())
		return
	}

	// Run through policy engine
	result := s.engine.Evaluate(ctx, policy.PhaseRequest, req)

	switch result.Action {
	case policy.ActionAllow:
		s.respondAllow(w)
	case policy.ActionLog:
		logging.Warn().
			Str("rule_id", result.RuleID).
			Str("reason", result.Reason).
			Msg("policy matched (log only)")
		s.respondAllow(w)
	default:
		logging.Warn().
			Str("action", string(result.Action)).
			Str("rule_id", result.RuleID).
			Str("reason", result.Reason).
			Msg("policy blocked request")
		s.respondDeny(w, result.RuleID, result.Reason)
	}
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
