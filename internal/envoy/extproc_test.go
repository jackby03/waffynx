package envoy

import (
	"context"
	"net"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/catalog"
	"github.com/jackby03/waffynx/internal/hotreload"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
	"github.com/jackby03/waffynx/internal/ratelimit"
	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/storage"
	"github.com/jackby03/waffynx/internal/telemetry"
)

func startTestExtProc(t *testing.T, proc *Processor) (extprocv3.ExternalProcessorClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(srv, proc)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc dial bufconn: %v", err)
	}
	return extprocv3.NewExternalProcessorClient(conn), func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	}
}

func makeHeaders(method, host, path, ip string, extra map[string]string) *corev3.HeaderMap {
	list := []*corev3.HeaderValue{
		{Key: ":method", RawValue: []byte(method)},
		{Key: ":authority", RawValue: []byte(host)},
		{Key: ":path", RawValue: []byte(path)},
		{Key: "x-forwarded-for", RawValue: []byte(ip)},
	}
	for k, v := range extra {
		list = append(list, &corev3.HeaderValue{Key: k, RawValue: []byte(v)})
	}
	return &corev3.HeaderMap{Headers: list}
}

func TestExtProc_PipelineExclusionsAntiOOMRateLimitAndHotReload(t *testing.T) {
	cat, err := catalog.Embedded()
	if err != nil {
		t.Fatalf("catalog.Embedded: %v", err)
	}
	lim := ratelimit.NewMemoryLimiter()
	defer lim.Close()
	em := telemetry.NewMemoryEmitter(32)

	proc := NewProcessor(
		Config{
			NodeID:           "waf-test",
			MaxBodyBytes:     128,
			RateLimitEnabled: true,
			RateLimitRPS:     50,
			RateLimitWindow:  time.Second,
		},
		cat,
		plugin.NewChain(),
		rules.NewEngine(),
		policy.NewRuleEngine(),
		appsec.NewBasicScorer(),
		lim,
		lim,
		em,
	)

	client, stop := startTestExtProc(t, proc)
	defer stop()
	ctx := context.Background()

	// 1. Benign GET request -> CONTINUE.
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers:     makeHeaders("GET", "app.example.test", "/api/items?page=1", "10.0.0.10", nil),
				EndOfStream: true,
			},
		},
	})
	resp, err := stream.Recv()
	if err != nil || resp.GetRequestHeaders().GetResponse().GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("expected CONTINUE for benign GET, got %+v err=%v", resp, err)
	}
	_ = stream.CloseSend()

	// 2. SQLi in query -> ImmediateResponse 403.
	stream, _ = client.Process(ctx)
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers:     makeHeaders("GET", "app.example.test", "/search?q=UNION+SELECT+1,2,3", "10.0.0.11", nil),
				EndOfStream: true,
			},
		},
	})
	resp, err = stream.Recv()
	if err != nil || resp.GetImmediateResponse().GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected 403 ImmediateResponse for SQLi, got %+v err=%v", resp, err)
	}
	_ = stream.CloseSend()

	// 3. Hot-reload an exclusion waiving all rules on /search -> now allowed!
	proc.ApplySnapshot(hotreload.PolicySnapshot{
		Revision: 42,
		Exclusions: []rules.Exclusion{
			{ID: "ex-search", RuleID: "*", Host: "app.example.test", PathExact: "/search", Enabled: true},
		},
		BannedIPs: []storage.IPBan{
			{IP: "203.0.113.77", Reason: "scanner", ExpiresAt: time.Now().Add(time.Minute)},
		},
	})
	if proc.Revision() != 42 {
		t.Fatalf("expected revision 42, got %d", proc.Revision())
	}

	stream, _ = client.Process(ctx)
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers:     makeHeaders("GET", "app.example.test", "/search?q=UNION+SELECT+1,2,3", "10.0.0.11", nil),
				EndOfStream: true,
			},
		},
	})
	resp, err = stream.Recv()
	if err != nil || resp.GetRequestHeaders().GetResponse().GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("expected excluded /search to CONTINUE, got %+v err=%v", resp, err)
	}
	_ = stream.CloseSend()

	// 4. Snapshot banned IP -> ImmediateResponse 403.
	stream, _ = client.Process(ctx)
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers:     makeHeaders("GET", "app.example.test", "/", "203.0.113.77", nil),
				EndOfStream: true,
			},
		},
	})
	resp, _ = stream.Recv()
	if resp.GetImmediateResponse().GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected 403 for banned IP, got %+v", resp)
	}
	_ = stream.CloseSend()

	// 5. POST with XSS payload in body -> headers CONTINUE, body 403.
	stream, _ = client.Process(ctx)
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers:     makeHeaders("POST", "app.example.test", "/comments", "10.0.0.12", map[string]string{"content-type": "application/json"}),
				EndOfStream: false,
			},
		},
	})
	resp, _ = stream.Recv()
	if resp.GetRequestHeaders().GetResponse().GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("expected headers CONTINUE before body, got %+v", resp)
	}
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        []byte(`{"comment":"<script>alert(1)</script>"}`),
				EndOfStream: true,
			},
		},
	})
	resp, _ = stream.Recv()
	if resp.GetImmediateResponse().GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected 403 on XSS body, got %+v", resp)
	}
	_ = stream.CloseSend()

	// 6. Anti-OOM body limit (> 128 bytes) -> 413 PayloadTooLarge fail-closed.
	stream, _ = client.Process(ctx)
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers:     makeHeaders("POST", "app.example.test", "/upload", "10.0.0.13", map[string]string{"content-length": "9999"}),
				EndOfStream: false,
			},
		},
	})
	resp, _ = stream.Recv()
	if resp.GetImmediateResponse().GetStatus().GetCode() != typev3.StatusCode_PayloadTooLarge {
		t.Fatalf("expected 413 PayloadTooLarge, got %+v", resp)
	}
	_ = stream.CloseSend()

	// Verify async telemetry recorded events.
	if len(em.Events()) < 4 {
		t.Fatalf("expected >=4 telemetry events, got %d", len(em.Events()))
	}
}

func TestExtProc_ShadowModeAllowsAndMarksHeader(t *testing.T) {
	cat, _ := catalog.Embedded()
	em := telemetry.NewMemoryEmitter(8)
	proc := NewProcessor(Config{ShadowMode: true}, cat, nil, nil, nil, nil, nil, nil, em)

	client, stop := startTestExtProc(t, proc)
	defer stop()

	stream, _ := client.Process(context.Background())
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers:     makeHeaders("GET", "app.example.test", "/?q=UNION+SELECT+1,2,3", "10.0.0.50", nil),
				EndOfStream: true,
			},
		},
	})
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	hdrResp := resp.GetRequestHeaders().GetResponse()
	if hdrResp.GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("shadow mode must CONTINUE, got %+v", resp)
	}
	if len(hdrResp.GetHeaderMutation().GetSetHeaders()) == 0 {
		t.Fatal("shadow mode should attach x-waffynx-shadow-rule header")
	}
	evs := em.Events()
	if len(evs) != 1 || evs[0].Action != telemetry.ActionShadowBlock {
		t.Fatalf("expected 1 shadow_block event, got %+v", evs)
	}
}
