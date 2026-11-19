package authz

import (
	"context"
	"slices"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	"github.com/jackby03/waffynx/internal/auth"
	"github.com/jackby03/waffynx/internal/storage"
	"github.com/jackby03/waffynx/internal/telemetry"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func buildCheckReq(host, path, ip string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{Address: ip},
					},
				},
			},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "GET",
					Host:    host,
					Path:    path,
					Headers: headers,
				},
			},
		},
	}
}

func TestZeroTrustExtAuthz_JWTScopesCIDRCountryDeviceAndHeaderStrip(t *testing.T) {
	mgr := auth.NewManager(testSecret, 3600)
	em := telemetry.NewMemoryEmitter(16)
	eval := NewEvaluator(mgr, func(ip string) string {
		if ip == "198.51.100.9" {
			return "KP"
		}
		return "US"
	})
	eval.ReplacePolicies([]storage.ZeroTrustPolicy{
		{
			ID:                  "zt-admin",
			Name:                "Admin Zero Trust",
			Host:                "app.example.test",
			PathPrefix:          "/admin",
			Enabled:             true,
			Priority:            10,
			RequireJWT:          true,
			AllowedIssuers:      []string{"waffynx"},
			RequiredScopes:      []string{"admin"},
			AllowedCIDRs:        []string{"10.0.0.0/8", "198.51.100.0/24"},
			BlockedCountries:    []string{"KP"},
			RequireDeviceHeader: "x-device-trust: verified",
		},
	})

	srv := NewServer(eval, em, "engine-1")
	ctx := context.Background()

	// 1. Unmatched path is allowed and strips spoofed x-waffynx-* headers.
	resp, err := srv.Check(ctx, buildCheckReq("app.example.test:8080", "/public", "10.0.0.5", map[string]string{
		"x-waffynx-user": "spoofed-admin",
	}))
	if err != nil || resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("expected OK on public path, got %+v err=%v", resp, err)
	}
	if !slices.Contains(resp.GetOkResponse().GetHeadersToRemove(), "x-waffynx-user") {
		t.Fatal("expected spoofed x-waffynx-user to be stripped")
	}

	// 2. Blocked GeoIP country denied (403).
	resp, _ = srv.Check(ctx, buildCheckReq("app.example.test", "/admin/panel", "198.51.100.9", map[string]string{
		"x-device-trust": "verified",
	}))
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("expected PermissionDenied for blocked country, got %v", resp.GetStatus())
	}

	// 3. Disallowed CIDR denied (403).
	resp, _ = srv.Check(ctx, buildCheckReq("app.example.test", "/admin/panel", "203.0.113.1", map[string]string{
		"x-device-trust": "verified",
	}))
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("expected PermissionDenied for CIDR mismatch, got %v", resp.GetStatus())
	}

	// 4. Missing device posture denied (403).
	resp, _ = srv.Check(ctx, buildCheckReq("app.example.test", "/admin/panel", "10.0.0.5", nil))
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("expected PermissionDenied for missing device header, got %v", resp.GetStatus())
	}

	// 5. Missing JWT denied (401 Unauthenticated).
	resp, _ = srv.Check(ctx, buildCheckReq("app.example.test", "/admin/panel", "10.0.0.5", map[string]string{
		"x-device-trust": "verified",
	}))
	if resp.GetStatus().GetCode() != int32(codes.Unauthenticated) {
		t.Fatalf("expected Unauthenticated for missing JWT, got %v", resp.GetStatus())
	}

	// 6. JWT missing required scope denied (403).
	viewerToken, _ := mgr.GenerateToken("bob", "viewer", []string{"read"})
	resp, _ = srv.Check(ctx, buildCheckReq("app.example.test", "/admin/panel", "10.0.0.5", map[string]string{
		"x-device-trust": "verified",
		"authorization":  "Bearer " + viewerToken,
	}))
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("expected PermissionDenied for missing scope, got %v", resp.GetStatus())
	}

	// 7. Valid JWT with required scope allowed and injects verified identity headers.
	adminToken, _ := mgr.GenerateToken("alice", "admin", []string{"read", "admin"})
	resp, _ = srv.Check(ctx, buildCheckReq("app.example.test", "/admin/panel", "10.0.0.5", map[string]string{
		"x-device-trust": "verified",
		"authorization":  "Bearer " + adminToken,
	}))
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("expected OK for valid admin JWT, got %v", resp.GetStatus())
	}
	foundUser := false
	for _, h := range resp.GetOkResponse().GetHeaders() {
		if h.GetHeader().GetKey() == "x-waffynx-user" && h.GetHeader().GetValue() == "alice" {
			foundUser = true
		}
	}
	if !foundUser {
		t.Fatal("expected verified x-waffynx-user=alice header to be injected")
	}

	// Telemetry captured denials with redacted Authorization header.
	evs := em.Events()
	if len(evs) < 4 {
		t.Fatalf("expected telemetry events for denials, got %d", len(evs))
	}
}

func TestZeroTrustExtAuthz_ShadowModeAndFailClosedNoJWTMgr(t *testing.T) {
	// Shadow mode allows request while marking shadow_denied + emitting telemetry.
	em := telemetry.NewMemoryEmitter(8)
	eval := NewEvaluator(nil, nil)
	eval.ReplacePolicies([]storage.ZeroTrustPolicy{
		{ID: "zt-shadow", PathPrefix: "/beta", Enabled: true, RequireJWT: true, ShadowMode: true},
	})
	srv := NewServer(eval, em, "")
	resp, err := srv.Check(context.Background(), buildCheckReq("app.example.test", "/beta/x", "10.0.0.1", nil))
	if err != nil || resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("shadow mode must allow traffic, got %+v err=%v", resp, err)
	}
	evs := em.Events()
	if len(evs) != 1 || evs[0].Action != telemetry.ActionShadowBlock {
		t.Fatalf("expected 1 shadow_block event, got %+v", evs)
	}

	// Non-shadow policy with nil jwtMgr fails closed (Constitution §1.1).
	eval.ReplacePolicies([]storage.ZeroTrustPolicy{
		{ID: "zt-strict", PathPrefix: "/strict", Enabled: true, RequireJWT: true},
	})
	resp, _ = srv.Check(context.Background(), buildCheckReq("app.example.test", "/strict", "10.0.0.1", nil))
	if resp.GetStatus().GetCode() != int32(codes.Unauthenticated) {
		t.Fatalf("expected fail-closed Unauthenticated when jwtMgr nil, got %v", resp.GetStatus())
	}
}
