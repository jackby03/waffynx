// Package envoy implements the Envoy Proxy ext_proc gRPC L7 WAF inspection
// service for the decoupled stateless Data Plane (Phase 2 & Constitution §1.2-§1.4).
package envoy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/catalog"
	"github.com/jackby03/waffynx/internal/hotreload"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
	"github.com/jackby03/waffynx/internal/ratelimit"
	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/telemetry"
)

// DefaultMaxBodyBytes bounds request body buffering at 1 MiB to prevent OOM
// attacks on the Data Plane (Constitution §1.4).
const DefaultMaxBodyBytes = 1 << 20

var (
	extProcRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "waffynx_extproc_requests_total",
		Help: "Total HTTP requests inspected by the Envoy ext_proc WAF service.",
	}, []string{"action", "stage"})
	extProcLatencyUs = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "waffynx_extproc_inspection_microseconds",
		Help:    "L7 WAF inspection latency in microseconds.",
		Buckets: []float64{50, 100, 250, 500, 1000, 2000, 5000, 10000, 25000},
	})
)

var bodyBufPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 4096))
	},
}

// Config tunes the Envoy ext_proc WAF processor.
type Config struct {
	NodeID            string
	MaxBodyBytes      int
	ShadowMode        bool
	AppSecFailOpen    bool
	RateLimitEnabled  bool
	RateLimitRPS      int
	RateLimitWindow   time.Duration
	RateLimitFailOpen bool
}

// Decision describes the L7 WAF inspection verdict.
type Decision struct {
	Allow       bool
	ShadowBlock bool
	StatusCode  int // 200, 403, 413, 429, 503
	Action      telemetry.EventAction
	Stage       string
	RuleID      string
	Severity    string
	Reason      string
	MLScore     float64
}

// Processor implements envoy.service.ext_proc.v3.ExternalProcessorServer.
type Processor struct {
	extprocv3.UnimplementedExternalProcessorServer

	cfg     Config
	catalog *catalog.Catalog
	chain   *plugin.Chain
	rules   *rules.Engine
	policy  policy.Evaluator
	scorer  appsec.Scorer
	limiter ratelimit.Limiter
	jails   ratelimit.JailStore
	emitter telemetry.Emitter

	// bannedIPs holds in-memory IP bans synced from the latest hot-reload
	// snapshot so bans stay enforced even if Redis is unreachable (Constitution §3.4).
	bannedIPs atomic.Pointer[map[string]string]
	revision  atomic.Int64
}

// NewProcessor constructs a stateless, lock-free Envoy ext_proc WAF processor.
func NewProcessor(
	cfg Config,
	cat *catalog.Catalog,
	chain *plugin.Chain,
	ruleEngine *rules.Engine,
	polEval policy.Evaluator,
	scorer appsec.Scorer,
	limiter ratelimit.Limiter,
	jails ratelimit.JailStore,
	emitter telemetry.Emitter,
) *Processor {
	if cfg.NodeID == "" {
		cfg.NodeID = "waf-engine"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.RateLimitRPS <= 0 {
		cfg.RateLimitRPS = 100
	}
	if cfg.RateLimitWindow <= 0 {
		cfg.RateLimitWindow = time.Second
	}
	if ruleEngine == nil {
		ruleEngine = rules.NewEngine()
	}
	if polEval == nil {
		polEval = policy.NewRuleEngine()
	}
	if chain == nil {
		chain = plugin.NewChain()
	}

	p := &Processor{
		cfg:     cfg,
		catalog: cat,
		chain:   chain,
		rules:   ruleEngine,
		policy:  polEval,
		scorer:  scorer,
		limiter: limiter,
		jails:   jails,
		emitter: emitter,
	}
	emptyBans := make(map[string]string)
	p.bannedIPs.Store(&emptyBans)
	return p
}

// Revision returns the last applied hot-reload snapshot revision.
func (p *Processor) Revision() int64 {
	return p.revision.Load()
}

// ApplySnapshot atomically swaps custom rules, exclusions, and in-memory IP bans
// from a Control Plane PolicySnapshot without stalling active streams (Constitution §1.2).
func (p *Processor) ApplySnapshot(snap hotreload.PolicySnapshot) {
	p.rules.ReplaceSnapshot(snap.CustomRules, snap.Exclusions)

	bans := make(map[string]string, len(snap.BannedIPs))
	now := time.Now().UTC()
	for _, b := range snap.BannedIPs {
		if b.ExpiresAt.IsZero() || b.ExpiresAt.After(now) {
			reason := b.Reason
			if reason == "" {
				reason = "IP banned by policy"
			}
			bans[b.IP] = reason
		}
	}
	p.bannedIPs.Store(&bans)
	p.revision.Store(snap.Revision)
}

// Process handles Envoy's bidirectional ext_proc stream for one HTTP request.
func (p *Processor) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	var (
		req       *policy.Request
		flatHdrs  map[string]string
		ztSubject string
		bodyBuf   *bytes.Buffer
		start     time.Time
		decided   bool
	)
	defer func() {
		if bodyBuf != nil {
			bodyBuf.Reset()
			bodyBufPool.Put(bodyBuf)
		}
	}()

	for {
		in, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		switch frame := in.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			start = time.Now()
			req, flatHdrs, ztSubject = extractRequestFromHeaders(frame.RequestHeaders.GetHeaders())

			// Fail-closed anti-OOM check on declared Content-Length before buffering.
			if clStr := flatHdrs["content-length"]; clStr != "" {
				if cl, parseErr := strconv.Atoi(strings.TrimSpace(clStr)); parseErr == nil && cl > p.cfg.MaxBodyBytes {
					d := Decision{
						Allow:      false,
						StatusCode: http.StatusRequestEntityTooLarge,
						Action:     telemetry.ActionBlock,
						Stage:      "body-limit",
						RuleID:     "anti-oom-max-body",
						Severity:   "high",
						Reason:     fmt.Sprintf("request body %d bytes exceeds limit %d", cl, p.cfg.MaxBodyBytes),
					}
					p.record(req, flatHdrs, ztSubject, d, start)
					if sendErr := stream.Send(immediateDenyResponse(d)); sendErr != nil {
						return sendErr
					}
					return nil
				}
			}

			// Run inspection immediately on header-only requests or fail-fast on header attacks.
			if frame.RequestHeaders.GetEndOfStream() {
				d := p.Evaluate(ctx, req, flatHdrs)
				p.record(req, flatHdrs, ztSubject, d, start)
				decided = true
				if !d.Allow {
					if sendErr := stream.Send(immediateDenyResponse(d)); sendErr != nil {
						return sendErr
					}
					return nil
				}
				if sendErr := stream.Send(continueHeadersResponse(d)); sendErr != nil {
					return sendErr
				}
				continue
			}

			// Request has a body: check fast header/IP/rate-limit rules before buffering body.
			d := p.Evaluate(ctx, req, flatHdrs)
			if !d.Allow {
				p.record(req, flatHdrs, ztSubject, d, start)
				if sendErr := stream.Send(immediateDenyResponse(d)); sendErr != nil {
					return sendErr
				}
				return nil
			}
			if sendErr := stream.Send(continueHeadersResponse(d)); sendErr != nil {
				return sendErr
			}

		case *extprocv3.ProcessingRequest_RequestBody:
			if decided || req == nil {
				if sendErr := stream.Send(continueBodyResponse(Decision{Allow: true})); sendErr != nil {
					return sendErr
				}
				continue
			}

			chunk := frame.RequestBody.GetBody()
			if bodyBuf == nil {
				if pooled, ok := bodyBufPool.Get().(*bytes.Buffer); ok {
					bodyBuf = pooled
				} else {
					bodyBuf = bytes.NewBuffer(make([]byte, 0, 4096))
				}
				bodyBuf.Reset()
			}
			if bodyBuf.Len()+len(chunk) > p.cfg.MaxBodyBytes {
				d := Decision{
					Allow:      false,
					StatusCode: http.StatusRequestEntityTooLarge,
					Action:     telemetry.ActionBlock,
					Stage:      "body-limit",
					RuleID:     "anti-oom-max-body",
					Severity:   "high",
					Reason:     fmt.Sprintf("buffered body exceeds limit %d bytes", p.cfg.MaxBodyBytes),
				}
				p.record(req, flatHdrs, ztSubject, d, start)
				if sendErr := stream.Send(immediateDenyResponse(d)); sendErr != nil {
					return sendErr
				}
				return nil
			}
			_, _ = bodyBuf.Write(chunk)

			if !frame.RequestBody.GetEndOfStream() {
				if sendErr := stream.Send(continueBodyResponse(Decision{Allow: true})); sendErr != nil {
					return sendErr
				}
				continue
			}

			req.Body = append([]byte(nil), bodyBuf.Bytes()...)
			d := p.Evaluate(ctx, req, flatHdrs)
			p.record(req, flatHdrs, ztSubject, d, start)
			decided = true
			if !d.Allow {
				if sendErr := stream.Send(immediateDenyResponse(d)); sendErr != nil {
					return sendErr
				}
				return nil
			}
			if sendErr := stream.Send(continueBodyResponse(d)); sendErr != nil {
				return sendErr
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			if sendErr := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocv3.HeadersResponse{
						Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE},
					},
				},
			}); sendErr != nil {
				return sendErr
			}

		case *extprocv3.ProcessingRequest_ResponseBody:
			if sendErr := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: &extprocv3.BodyResponse{
						Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE},
					},
				},
			}); sendErr != nil {
				return sendErr
			}

		case *extprocv3.ProcessingRequest_RequestTrailers:
			if sendErr := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestTrailers{
					RequestTrailers: &extprocv3.TrailersResponse{},
				},
			}); sendErr != nil {
				return sendErr
			}

		case *extprocv3.ProcessingRequest_ResponseTrailers:
			if sendErr := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseTrailers{
					ResponseTrailers: &extprocv3.TrailersResponse{},
				},
			}); sendErr != nil {
				return sendErr
			}
		}
	}
}

// Evaluate runs the full multi-stage L7 inspection pipeline for req.
func (p *Processor) Evaluate(ctx context.Context, req *policy.Request, flatHdrs map[string]string) Decision {
	// Stage 0a: Snapshot in-memory IP bans (always enforced even during Redis outage).
	if bans := p.bannedIPs.Load(); bans != nil && req.RemoteIP != "" {
		if reason, banned := (*bans)[req.RemoteIP]; banned {
			if !p.rules.IsExcluded(req, "ip-ban-"+req.RemoteIP) {
				return p.applyShadowMode(Decision{
					Allow:      false,
					StatusCode: http.StatusForbidden,
					Action:     telemetry.ActionBlock,
					Stage:      "ip-jail",
					RuleID:     "ip-ban-" + req.RemoteIP,
					Severity:   "critical",
					Reason:     reason,
				})
			}
		}
	}

	// Stage 0b: Ephemeral Redis/Dragonfly IP Jail lookup (strict <=10ms timeout).
	if p.jails != nil && req.RemoteIP != "" {
		jailed, reason, err := p.jails.IsJailed(ctx, req.RemoteIP)
		if err != nil {
			if p.cfg.RateLimitFailOpen {
				logging.Warn().Err(err).Str("ip", req.RemoteIP).Msg("ip jail lookup degraded (controlled fail-open)")
			} else {
				return p.applyShadowMode(Decision{
					Allow:      false,
					StatusCode: http.StatusServiceUnavailable,
					Action:     telemetry.ActionBlock,
					Stage:      "ip-jail",
					RuleID:     "ip-jail-unavailable",
					Severity:   "high",
					Reason:     "ephemeral jail store unavailable (fail-closed)",
				})
			}
		} else if jailed && !p.rules.IsExcluded(req, "ip-jail-"+req.RemoteIP) {
			return p.applyShadowMode(Decision{
				Allow:      false,
				StatusCode: http.StatusForbidden,
				Action:     telemetry.ActionBlock,
				Stage:      "ip-jail",
				RuleID:     "ip-jail-" + req.RemoteIP,
				Severity:   "critical",
				Reason:     reason,
			})
		}
	}

	// Stage 0c: Distributed Sliding-Window Rate Limit (strict <=10ms timeout,
	// fail-closed by default, controlled fail-open only if explicitly enabled).
	if p.cfg.RateLimitEnabled && p.limiter != nil && req.RemoteIP != "" {
		allowed, err := p.limiter.Allow(ctx, req.RemoteIP, p.cfg.RateLimitRPS, p.cfg.RateLimitWindow)
		if err != nil {
			if p.cfg.RateLimitFailOpen {
				logging.Warn().Err(err).Str("ip", req.RemoteIP).Msg("rate limit lookup failed, continuing with L7 rules (controlled fail-open)")
			} else {
				return p.applyShadowMode(Decision{
					Allow:      false,
					StatusCode: http.StatusServiceUnavailable,
					Action:     telemetry.ActionRateLimited,
					Stage:      "rate-limit",
					RuleID:     "rate-limit-unavailable",
					Severity:   "high",
					Reason:     "rate limit store unavailable (fail-closed)",
				})
			}
		} else if !allowed && !p.rules.IsExcluded(req, "rate-limit") {
			return p.applyShadowMode(Decision{
				Allow:      false,
				StatusCode: http.StatusTooManyRequests,
				Action:     telemetry.ActionRateLimited,
				Stage:      "rate-limit",
				RuleID:     "rate-limit-exceeded",
				Severity:   "medium",
				Reason:     fmt.Sprintf("sliding-window rate limit exceeded for %s", req.RemoteIP),
			})
		}
	}

	// Stage 1: Managed Ruleset (Aho-Corasick) with dynamic Exclusion tuning.
	if p.catalog != nil {
		if hit := p.catalog.Evaluate(req); hit != nil {
			if hit.Action == catalog.ActionBlock && !p.rules.IsExcluded(req, hit.RuleID) {
				return p.applyShadowMode(Decision{
					Allow:      false,
					StatusCode: http.StatusForbidden,
					Action:     telemetry.ActionBlock,
					Stage:      "catalog",
					RuleID:     hit.RuleID,
					Severity:   string(hit.Severity),
					Reason:     hit.Name + " (matched in " + string(hit.Field) + ")",
				})
			}
		}
	}

	// Stage 2: Plugin Chain.
	if p.chain != nil {
		rec := httptest.NewRecorder()
		httpReq := httptest.NewRequest(safeMethod(req.Method), "http://"+safeHost(req.Host)+safePath(req.Path), bytes.NewReader(req.Body))
		httpReq.RemoteAddr = req.RemoteIP
		for k, v := range flatHdrs {
			if !strings.HasPrefix(k, ":") {
				httpReq.Header.Set(k, v)
			}
		}
		pctx := plugin.NewContext(ctx, rec, httpReq)
		pctx.Values["wn_method"] = req.Method
		pctx.Values["wn_uri"] = req.Path
		pctx.Values["wn_host"] = req.Host
		pctx.Values["wn_ip"] = req.RemoteIP
		pctx.Values["wn_ua"] = flatHdrs["user-agent"]
		pctx.Values["wn_ct"] = flatHdrs["content-type"]
		pctx.Values["wn_ref"] = flatHdrs["referer"]
		if len(req.Body) > 0 {
			pctx.Values["wn_body"] = string(req.Body)
		}

		resCtx, err := p.chain.Execute(pctx, plugin.PhasePreRequest)
		if err != nil && !p.rules.IsExcluded(req, "plugin-chain") {
			code := http.StatusForbidden
			act := telemetry.ActionBlock
			if resCtx != nil && resCtx.StatusCode != 0 {
				code = resCtx.StatusCode
				if code == http.StatusTooManyRequests {
					act = telemetry.ActionRateLimited
				}
			}
			return p.applyShadowMode(Decision{
				Allow:      false,
				StatusCode: code,
				Action:     act,
				Stage:      "plugin-chain",
				RuleID:     "plugin-chain",
				Severity:   "high",
				Reason:     err.Error(),
			})
		}
	}

	// Stage 3: Lock-free Custom Rules (exclusions already honored inside rules.Engine).
	if p.rules != nil {
		rr := p.rules.Evaluate(req)
		if rr.Action != rules.ActionAllow && rr.Action != rules.ActionLog {
			return p.applyShadowMode(Decision{
				Allow:      false,
				StatusCode: http.StatusForbidden,
				Action:     telemetry.ActionBlock,
				Stage:      "custom-rule",
				RuleID:     rr.RuleID,
				Severity:   "high",
				Reason:     rr.Reason,
			})
		}
	}

	// Stage 4: Policy Engine.
	if p.policy != nil {
		pr := p.policy.Evaluate(ctx, policy.PhaseRequest, req)
		if pr.Action != policy.ActionAllow && pr.Action != policy.ActionLog && !p.rules.IsExcluded(req, pr.RuleID) {
			return p.applyShadowMode(Decision{
				Allow:      false,
				StatusCode: http.StatusForbidden,
				Action:     telemetry.ActionBlock,
				Stage:      "policy",
				RuleID:     pr.RuleID,
				Severity:   "high",
				Reason:     pr.Reason,
			})
		}
	}

	// Stage 5: AppSec ML Anomaly Scorer (fail-closed by default).
	if p.scorer != nil {
		appRes, err := p.scorer.Evaluate(ctx, &appsec.Features{
			Method:      req.Method,
			URI:         req.Path,
			Host:        req.Host,
			ClientIP:    req.RemoteIP,
			UserAgent:   flatHdrs["user-agent"],
			ContentType: flatHdrs["content-type"],
			Referer:     flatHdrs["referer"],
			Body:        req.Body,
			URILength:   len(req.Path),
			PayloadSize: int64(len(req.Body)),
			HasPayload:  len(req.Body) > 0,
			QueryParams: extractQueryParams(req.Path),
		})
		if err != nil {
			if !p.cfg.AppSecFailOpen {
				return p.applyShadowMode(Decision{
					Allow:      false,
					StatusCode: http.StatusForbidden,
					Action:     telemetry.ActionBlock,
					Stage:      "appsec-error",
					RuleID:     "appsec-unavailable",
					Severity:   "critical",
					Reason:     "scoring engine unavailable and fail_open is false",
				})
			}
		} else if appRes.Verdict == appsec.VerdictBlock && !p.rules.IsExcluded(req, "appsec-"+appRes.ModelName) {
			return p.applyShadowMode(Decision{
				Allow:      false,
				StatusCode: http.StatusForbidden,
				Action:     telemetry.ActionBlock,
				Stage:      "appsec",
				RuleID:     "appsec-" + appRes.ModelName,
				Severity:   "high",
				Reason:     "ML anomaly: " + strings.Join(appRes.Reasons, "; "),
				MLScore:    appRes.Score,
			})
		}
	}

	return Decision{
		Allow:      true,
		StatusCode: http.StatusOK,
		Action:     telemetry.ActionAllow,
		Stage:      "allow",
	}
}

func (p *Processor) applyShadowMode(d Decision) Decision {
	if !p.cfg.ShadowMode || d.Allow {
		return d
	}
	d.Allow = true
	d.ShadowBlock = true
	d.Action = telemetry.ActionShadowBlock
	return d
}

func (p *Processor) record(req *policy.Request, flatHdrs map[string]string, ztSubject string, d Decision, start time.Time) {
	latencyUs := time.Since(start).Microseconds()
	extProcRequests.WithLabelValues(string(d.Action), d.Stage).Inc()
	extProcLatencyUs.Observe(float64(latencyUs))

	if p.emitter == nil {
		return
	}
	snippet := ""
	if len(req.Body) > 0 {
		n := len(req.Body)
		if n > 512 {
			n = 512
		}
		snippet = string(req.Body[:n])
	}
	p.emitter.Emit(telemetry.SecurityEvent{
		EventID:     uuid.NewString(),
		Timestamp:   time.Now().UTC(),
		NodeID:      p.cfg.NodeID,
		Plane:       "data-plane",
		Action:      d.Action,
		Stage:       d.Stage,
		Method:      req.Method,
		Host:        req.Host,
		Path:        req.Path,
		RemoteIP:    req.RemoteIP,
		UserAgent:   flatHdrs["user-agent"],
		RuleID:      d.RuleID,
		Severity:    d.Severity,
		Reason:      d.Reason,
		StatusCode:  d.StatusCode,
		LatencyUs:   latencyUs,
		MLScore:     d.MLScore,
		ZTSubject:   ztSubject,
		ShadowMode:  d.ShadowBlock,
		Headers:     flatHdrs,
		BodySnippet: snippet,
	})
}

func extractRequestFromHeaders(hm *corev3.HeaderMap) (*policy.Request, map[string]string, string) {
	flat := make(map[string]string, len(hm.GetHeaders()))
	multi := make(map[string][]string, len(hm.GetHeaders()))
	for _, h := range hm.GetHeaders() {
		key := strings.ToLower(h.GetKey())
		val := h.GetValue()
		if len(h.GetRawValue()) > 0 {
			val = string(h.GetRawValue())
		}
		flat[key] = val
		if !strings.HasPrefix(key, ":") {
			canon := http.CanonicalHeaderKey(key)
			multi[canon] = append(multi[canon], val)
		}
	}

	host := flat[":authority"]
	if host == "" {
		host = flat["host"]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	remoteIP := ""
	if xff := strings.TrimSpace(flat["x-forwarded-for"]); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		remoteIP = strings.TrimSpace(first)
	}
	if remoteIP == "" {
		remoteIP = strings.TrimSpace(flat["x-envoy-external-address"])
	}
	if remoteIP == "" {
		remoteIP = strings.TrimSpace(flat["x-real-ip"])
	}

	req := &policy.Request{
		Method:   flat[":method"],
		Host:     host,
		Path:     flat[":path"],
		RemoteIP: remoteIP,
		Headers:  multi,
	}
	return req, flat, flat["x-waffynx-user"]
}

func immediateDenyResponse(d Decision) *extprocv3.ProcessingResponse {
	code := typev3.StatusCode_Forbidden
	switch d.StatusCode {
	case http.StatusTooManyRequests:
		code = typev3.StatusCode_TooManyRequests
	case http.StatusRequestEntityTooLarge:
		code = typev3.StatusCode_PayloadTooLarge
	case http.StatusServiceUnavailable:
		code = typev3.StatusCode_ServiceUnavailable
	}
	body, _ := json.Marshal(map[string]string{
		"error":   "blocked by Waffynx WAF",
		"stage":   d.Stage,
		"rule_id": d.RuleID,
		"reason":  d.Reason,
	})
	hdrs := []*corev3.HeaderValueOption{
		{Header: &corev3.HeaderValue{Key: "content-type", RawValue: []byte("application/json")}},
		{Header: &corev3.HeaderValue{Key: "x-waffynx-verdict", RawValue: []byte("deny")}},
		{Header: &corev3.HeaderValue{Key: "x-waffynx-rule", RawValue: []byte(d.RuleID)}},
	}
	if d.StatusCode == http.StatusTooManyRequests {
		hdrs = append(hdrs, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{Key: "retry-after", RawValue: []byte("1")},
		})
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{Code: code},
				Headers: &extprocv3.HeaderMutation{
					SetHeaders: hdrs,
				},
				Body: body,
			},
		},
	}
}

func continueHeadersResponse(d Decision) *extprocv3.ProcessingResponse {
	common := &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE}
	if d.ShadowBlock {
		common.HeaderMutation = &extprocv3.HeaderMutation{
			SetHeaders: []*corev3.HeaderValueOption{
				{
					Header:       &corev3.HeaderValue{Key: "x-waffynx-shadow-rule", RawValue: []byte(d.RuleID)},
					AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
				},
			},
		}
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{Response: common},
		},
	}
}

func continueBodyResponse(d Decision) *extprocv3.ProcessingResponse {
	common := &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE}
	if d.ShadowBlock {
		common.HeaderMutation = &extprocv3.HeaderMutation{
			SetHeaders: []*corev3.HeaderValueOption{
				{
					Header:       &corev3.HeaderValue{Key: "x-waffynx-shadow-rule", RawValue: []byte(d.RuleID)},
					AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
				},
			},
		}
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{Response: common},
		},
	}
}

func safeMethod(m string) string {
	if m == "" {
		return http.MethodGet
	}
	return m
}

func safeHost(h string) string {
	if h == "" {
		return "localhost"
	}
	return h
}

func safePath(p string) string {
	if p == "" || p[0] != '/' {
		return "/"
	}
	return p
}

func extractQueryParams(rawURI string) map[string]string {
	params := make(map[string]string)
	idx := strings.IndexByte(rawURI, '?')
	if idx < 0 || idx == len(rawURI)-1 {
		return params
	}
	q, err := url.QueryUnescape(rawURI[idx+1:])
	if err != nil {
		q = rawURI[idx+1:]
	}
	for _, pair := range strings.Split(q, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if ok && k != "" {
			params[k] = v
		}
	}
	return params
}
