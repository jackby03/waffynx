package xds

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/sites"
)

// DefaultNodeID is the canonical Envoy node cluster/id shared across replicas
// unless overridden per node.
const DefaultNodeID = "waffynx-envoy"

// ConnectedNode records live Envoy proxy replicas connected to the xDS server.
type ConnectedNode struct {
	NodeID      string    `json:"node_id"`
	ConnectedAt time.Time `json:"connected_at"`
	Streams     int       `json:"streams"`
}

// Server wraps go-control-plane's xDS ADS gRPC server and tracks active Envoy nodes.
type Server struct {
	cache    cachev3.SnapshotCache
	topology TopologyConfig
	version  atomic.Int64

	mu        sync.RWMutex
	nodes     map[string]*ConnectedNode
	nodeIDs   map[int64]string
	lastSites []sites.Site

	grpcServer *grpc.Server
}

// NewServer initializes an Envoy v3 xDS snapshot cache and callback tracker.
func NewServer(topology TopologyConfig) *Server {
	s := &Server{
		cache:    cachev3.NewSnapshotCache(true, cachev3.IDHash{}, nil),
		topology: topology,
		nodes:    make(map[string]*ConnectedNode),
		nodeIDs:  make(map[int64]string),
	}
	return s
}

// UpdateSites builds and pushes a fresh Envoy xDS snapshot to DefaultNodeID and
// every currently connected Envoy node ID.
func (s *Server) UpdateSites(ctx context.Context, siteList []sites.Site) (int64, error) {
	rev := s.version.Add(1)
	verStr := strconv.FormatInt(rev, 10)

	snap, err := BuildSnapshot(verStr, siteList, s.topology)
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	s.lastSites = append([]sites.Site(nil), siteList...)
	targets := make(map[string]struct{}, len(s.nodes)+1)
	targets[DefaultNodeID] = struct{}{}
	for id := range s.nodes {
		targets[id] = struct{}{}
	}
	s.mu.Unlock()

	for id := range targets {
		if err := s.cache.SetSnapshot(ctx, id, snap); err != nil {
			return 0, fmt.Errorf("setting xDS snapshot for node %s: %w", id, err)
		}
	}

	logging.Info().
		Int64("xds_version", rev).
		Int("sites", len(siteList)).
		Int("nodes", len(targets)).
		Msg("pushed Envoy xDS snapshot")
	return rev, nil
}

// ConnectedNodes returns currently connected Envoy replicas sorted by NodeID.
func (s *Server) ConnectedNodes() []ConnectedNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ConnectedNode, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// CurrentVersion returns the last published xDS snapshot version.
func (s *Server) CurrentVersion() int64 {
	return s.version.Load()
}

// Serve runs the gRPC xDS server on listenAddr until ctx is cancelled.
// If tlsCfg is non-nil, strict TLS/mTLS transport credentials are enforced.
func (s *Server) Serve(ctx context.Context, listenAddr string, tlsCfg *tls.Config) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("xds listen on %s: %w", listenAddr, err)
	}
	return s.ServeListener(ctx, ln, tlsCfg)
}

// ServeListener serves xDS over a pre-bound net.Listener (useful for tests).
func (s *Server) ServeListener(ctx context.Context, ln net.Listener, tlsCfg *tls.Config) error {
	var opts []grpc.ServerOption
	if tlsCfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	grpcSrv := grpc.NewServer(opts...)
	xdsSrv := serverv3.NewServer(ctx, s.cache, &callbacks{srv: s})

	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcSrv, xdsSrv)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcSrv, xdsSrv)
	clusterservice.RegisterClusterDiscoveryServiceServer(grpcSrv, xdsSrv)
	routeservice.RegisterRouteDiscoveryServiceServer(grpcSrv, xdsSrv)
	listenerservice.RegisterListenerDiscoveryServiceServer(grpcSrv, xdsSrv)
	secretservice.RegisterSecretDiscoveryServiceServer(grpcSrv, xdsSrv)

	s.mu.Lock()
	s.grpcServer = grpcSrv
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		grpcSrv.GracefulStop()
	}()

	logging.Info().Str("listen", ln.Addr().String()).Bool("mtls", tlsCfg != nil).Msg("Envoy xDS control plane listening")
	if err := grpcSrv.Serve(ln); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

type callbacks struct {
	srv *Server
}

func (c *callbacks) OnStreamOpen(_ context.Context, _ int64, _ string) error { return nil }
func (c *callbacks) OnStreamClosed(streamID int64, _ *corev3.Node) {
	c.srv.mu.Lock()
	defer c.srv.mu.Unlock()
	if nodeID, ok := c.srv.nodeIDs[streamID]; ok {
		delete(c.srv.nodeIDs, streamID)
		if node, exists := c.srv.nodes[nodeID]; exists {
			node.Streams--
			if node.Streams <= 0 {
				delete(c.srv.nodes, nodeID)
			}
		}
	}
}
func (c *callbacks) OnDeltaStreamOpen(_ context.Context, _ int64, _ string) error { return nil }
func (c *callbacks) OnDeltaStreamClosed(streamID int64, node *corev3.Node) {
	c.OnStreamClosed(streamID, node)
}
func (c *callbacks) OnStreamRequest(streamID int64, req *discoverygrpc.DiscoveryRequest) error {
	nodeID := req.GetNode().GetId()
	if nodeID == "" {
		return nil
	}
	c.srv.registerNodeStream(streamID, nodeID)
	return nil
}
func (c *callbacks) OnStreamResponse(context.Context, int64, *discoverygrpc.DiscoveryRequest, *discoverygrpc.DiscoveryResponse) {
}
func (c *callbacks) OnStreamDeltaRequest(streamID int64, req *discoverygrpc.DeltaDiscoveryRequest) error {
	if nodeID := req.GetNode().GetId(); nodeID != "" {
		c.srv.registerNodeStream(streamID, nodeID)
	}
	return nil
}
func (c *callbacks) OnStreamDeltaResponse(int64, *discoverygrpc.DeltaDiscoveryRequest, *discoverygrpc.DeltaDiscoveryResponse) {
}
func (c *callbacks) OnFetchRequest(context.Context, *discoverygrpc.DiscoveryRequest) error {
	return nil
}
func (c *callbacks) OnFetchResponse(*discoverygrpc.DiscoveryRequest, *discoverygrpc.DiscoveryResponse) {
}

func (s *Server) registerNodeStream(streamID int64, nodeID string) {
	s.mu.Lock()
	needHydrate := false
	if _, seen := s.nodeIDs[streamID]; !seen {
		s.nodeIDs[streamID] = nodeID
		node, exists := s.nodes[nodeID]
		if !exists {
			node = &ConnectedNode{NodeID: nodeID, ConnectedAt: time.Now().UTC()}
			s.nodes[nodeID] = node
			needHydrate = true
		}
		node.Streams++
	}
	siteCopy := append([]sites.Site(nil), s.lastSites...)
	ver := s.version.Load()
	s.mu.Unlock()

	// Ensure newly connected Envoy pods with custom node IDs receive the active
	// snapshot immediately without waiting for the next site mutation.
	if needHydrate && nodeID != DefaultNodeID {
		if ver == 0 {
			ver = s.version.Add(1)
		}
		if snap, err := BuildSnapshot(strconv.FormatInt(ver, 10), siteCopy, s.topology); err == nil {
			_ = s.cache.SetSnapshot(context.Background(), nodeID, snap)
		}
	}
}
