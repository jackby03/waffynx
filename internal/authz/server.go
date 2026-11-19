package authz

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/jackby03/waffynx/internal/telemetry"
)

// IdentityHeaders are stripped from untrusted client requests on every pass and
// injected exclusively by Waffynx after verified Zero-Trust evaluation.
var IdentityHeaders = []string{
	"x-waffynx-user",
	"x-waffynx-role",
	"x-waffynx-scopes",
	"x-waffynx-zt-verdict",
	"x-waffynx-zt-policy",
}

// Server implements Envoy's envoy.service.auth.v3.Authorization gRPC service.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	evaluator *Evaluator
	emitter   telemetry.Emitter
	nodeID    string
}

func NewServer(evaluator *Evaluator, emitter telemetry.Emitter, nodeID string) *Server {
	if nodeID == "" {
		nodeID = "waf-engine"
	}
	return &Server{
		evaluator: evaluator,
		emitter:   emitter,
		nodeID:    nodeID,
	}
}

func (s *Server) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	start := time.Now()

	httpReq := req.GetAttributes().GetRequest().GetHttp()
	headers := make(map[string]string, len(httpReq.GetHeaders()))
	for k, v := range httpReq.GetHeaders() {
		headers[strings.ToLower(k)] = v
	}

	remoteIP := extractClientIP(req, headers)
	host := stripPort(httpReq.GetHost())
	if host == "" {
		host = stripPort(headers[":authority"])
	}

	zreq := Request{
		Method:   httpReq.GetMethod(),
		Host:     host,
		Path:     httpReq.GetPath(),
		RemoteIP: remoteIP,
		Headers:  headers,
	}

	decision := s.evaluator.Evaluate(zreq)

	if !decision.Allowed {
		s.emitEvent(zreq, decision, telemetry.ActionAuthDenied, start)
		httpCode := typev3.StatusCode_Forbidden
		rpcCode := codes.PermissionDenied
		if decision.StatusCode == 401 {
			httpCode = typev3.StatusCode_Unauthorized
			rpcCode = codes.Unauthenticated
		}
		body, _ := json.Marshal(map[string]string{
			"error":     "zero_trust_denied",
			"policy_id": decision.PolicyID,
			"reason":    decision.Reason,
		})
		return &authv3.CheckResponse{
			Status: &status.Status{
				Code:    int32(rpcCode),
				Message: decision.Reason,
			},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: httpCode},
					Headers: []*corev3.HeaderValueOption{
						{Header: &corev3.HeaderValue{Key: "content-type", Value: "application/json"}},
						{Header: &corev3.HeaderValue{Key: "x-waffynx-zt-verdict", Value: "denied"}},
						{Header: &corev3.HeaderValue{Key: "x-waffynx-zt-policy", Value: decision.PolicyID}},
					},
					Body: string(body),
				},
			},
		}, nil
	}

	if decision.ShadowDenied {
		s.emitEvent(zreq, decision, telemetry.ActionShadowBlock, start)
	}

	injected := []*corev3.HeaderValueOption{
		{
			Header:       &corev3.HeaderValue{Key: "x-waffynx-zt-verdict", Value: verdictLabel(decision)},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		},
	}
	if decision.Subject != "" {
		injected = append(injected,
			&corev3.HeaderValueOption{
				Header:       &corev3.HeaderValue{Key: "x-waffynx-user", Value: decision.Subject},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			},
			&corev3.HeaderValueOption{
				Header:       &corev3.HeaderValue{Key: "x-waffynx-role", Value: decision.Role},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			},
			&corev3.HeaderValueOption{
				Header:       &corev3.HeaderValue{Key: "x-waffynx-scopes", Value: strings.Join(decision.Scopes, ",")},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			},
		)
	}

	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				HeadersToRemove: IdentityHeaders,
				Headers:         injected,
			},
		},
	}, nil
}

func verdictLabel(d Decision) string {
	if d.ShadowDenied {
		return "shadow_denied"
	}
	return "allow"
}

func (s *Server) emitEvent(req Request, d Decision, action telemetry.EventAction, start time.Time) {
	if s.emitter == nil {
		return
	}
	s.emitter.Emit(telemetry.SecurityEvent{
		EventID:     uuid.NewString(),
		Timestamp:   time.Now().UTC(),
		NodeID:      s.nodeID,
		Plane:       "data-plane",
		Action:      action,
		Stage:       "ext_authz",
		Method:      req.Method,
		Host:        req.Host,
		Path:        req.Path,
		RemoteIP:    req.RemoteIP,
		CountryCode: d.CountryCode,
		UserAgent:   req.Headers["user-agent"],
		RuleID:      d.PolicyID,
		Severity:    "high",
		Reason:      d.Reason,
		StatusCode:  d.StatusCode,
		LatencyUs:   time.Since(start).Microseconds(),
		ZTSubject:   d.Subject,
		ShadowMode:  d.ShadowDenied,
		Headers:     req.Headers,
	})
}

func extractClientIP(req *authv3.CheckRequest, headers map[string]string) string {
	if xff := strings.TrimSpace(headers["x-forwarded-for"]); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	if sock := req.GetAttributes().GetSource().GetAddress().GetSocketAddress(); sock != nil {
		return sock.GetAddress()
	}
	return ""
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
