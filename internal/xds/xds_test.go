package xds

import (
	"context"
	"net"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/jackby03/waffynx/internal/sites"
)

func TestBuildSnapshot_ConsistentWithMTLSAndEdgeTLS(t *testing.T) {
	cfg := DefaultTopologyConfig()
	cfg.EngineMTLS = true
	cfg.UpstreamMTLS = true
	cfg.EdgeTLS = true
	cfg.EnvoyCertPath = "/etc/waffynx/certs/envoy.crt"
	cfg.EnvoyKeyPath = "/etc/waffynx/certs/envoy.key"
	cfg.CACertPath = "/etc/waffynx/certs/ca.crt"

	siteList := []sites.Site{
		{
			Host:     "app.example.test",
			Upstream: "backend:80",
			Headers:  map[string]string{"X-Protected-By": "Waffynx"},
		},
		{
			Host:     "api.example.test",
			Upstream: "http://api-svc:8080/v1",
		},
	}

	snap, err := BuildSnapshot("1", siteList, cfg)
	if err != nil {
		t.Fatalf("BuildSnapshot failed: %v", err)
	}
	if err := snap.Consistent(); err != nil {
		t.Fatalf("snapshot inconsistent: %v", err)
	}
	if got := len(snap.GetResources(resourcev3.ClusterType)); got != 3 {
		t.Fatalf("expected 3 clusters (waf_engine + 2 sites), got %d", got)
	}
	if got := len(snap.GetResources(resourcev3.ListenerType)); got != 2 {
		t.Fatalf("expected 2 listeners (http + https), got %d", got)
	}
	if got := len(snap.GetResources(resourcev3.SecretType)); got != 1 {
		t.Fatalf("expected 1 SDS secret, got %d", got)
	}
}

func TestXDSServer_LiveADSStreamAndNodeTracking(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServer(DefaultTopologyConfig())
	rev, err := srv.UpdateSites(ctx, []sites.Site{
		{Host: "app.example.test", Upstream: "backend:80"},
	})
	if err != nil || rev != 1 {
		t.Fatalf("UpdateSites: rev=%d err=%v", rev, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.ServeListener(ctx, ln, nil) }()

	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc dial: %v", err)
	}
	defer conn.Close()

	ads := discoverygrpc.NewAggregatedDiscoveryServiceClient(conn)
	stream, err := ads.StreamAggregatedResources(ctx)
	if err != nil {
		t.Fatalf("StreamAggregatedResources: %v", err)
	}

	// Request CDS as a custom Envoy pod node ID -> should auto-hydrate snapshot.
	if err := stream.Send(&discoverygrpc.DiscoveryRequest{
		Node:    &corev3.Node{Id: "envoy-pod-1"},
		TypeUrl: resourcev3.ClusterType,
	}); err != nil {
		t.Fatalf("Send CDS request: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv CDS response: %v", err)
	}
	if resp.GetVersionInfo() != "1" || len(resp.GetResources()) != 2 {
		t.Fatalf("unexpected CDS response: ver=%s count=%d", resp.GetVersionInfo(), len(resp.GetResources()))
	}

	nodes := srv.ConnectedNodes()
	if len(nodes) != 1 || nodes[0].NodeID != "envoy-pod-1" {
		t.Fatalf("expected envoy-pod-1 tracked, got %+v", nodes)
	}
	if srv.CurrentVersion() != 1 {
		t.Fatalf("expected version 1, got %d", srv.CurrentVersion())
	}

	cancel()
	time.Sleep(30 * time.Millisecond)
}
