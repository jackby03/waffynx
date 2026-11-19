// Package xds implements the Envoy v3 dynamic xDS Control Plane (ADS: LDS, RDS,
// CDS, SDS) backed by go-control-plane so routes, upstreams, TLS certificates,
// and Zero-Trust ext_authz/ext_proc filters are pushed live with zero restarts.
package xds

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstreamshttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/jackby03/waffynx/internal/sites"
)

const (
	WAFEngineClusterName = "waf_engine_cluster"
	RouteConfigName      = "waffynx_routes"
	HTTPListenerName     = "waffynx_http"
	HTTPSListenerName    = "waffynx_https"
	//nolint:gosec // G101: Envoy SDS resource identifier name, not a credential.
	EdgeTLSSecretName  = "waffynx_edge_tls"
	ExtAuthzFilterName = "envoy.filters.http.ext_authz"
	ExtProcFilterName  = "envoy.filters.http.ext_proc"
)

// TopologyConfig defines the Envoy Data Plane endpoints and mTLS paths rendered
// into xDS resources.
type TopologyConfig struct {
	HTTPPort            uint32
	HTTPSPort           uint32
	WAFEngineHost       string
	WAFEnginePort       uint32
	EnableExtAuthz      bool
	EnableExtProc       bool
	FailureModeAllow    bool // false (fail-closed) per Constitution §1.1
	MaxRequestBodyBytes uint32
	EnvoyCertPath       string
	EnvoyKeyPath        string
	CACertPath          string
	EngineMTLS          bool
	EdgeTLS             bool
	UpstreamMTLS        bool
}

// DefaultTopologyConfig returns safe fail-closed production defaults.
func DefaultTopologyConfig() TopologyConfig {
	return TopologyConfig{
		HTTPPort:            8080,
		HTTPSPort:           8443,
		WAFEngineHost:       "waf-engine",
		WAFEnginePort:       50051,
		EnableExtAuthz:      true,
		EnableExtProc:       true,
		FailureModeAllow:    false,
		MaxRequestBodyBytes: 1 << 20, // 1 MiB anti-OOM
	}
}

// BuildSnapshot compiles the current sites topology into a consistent Envoy v3
// xDS snapshot containing CDS, RDS, LDS, and optional SDS resources.
func BuildSnapshot(version string, siteList []sites.Site, cfg TopologyConfig) (*cachev3.Snapshot, error) {
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8080
	}
	if cfg.WAFEngineHost == "" {
		cfg.WAFEngineHost = "waf-engine"
	}
	if cfg.WAFEnginePort == 0 {
		cfg.WAFEnginePort = 50051
	}
	if cfg.MaxRequestBodyBytes == 0 {
		cfg.MaxRequestBodyBytes = 1 << 20
	}

	clusters := make([]types.Resource, 0, len(siteList)+1)
	wafCluster, err := buildWAFEngineCluster(cfg)
	if err != nil {
		return nil, fmt.Errorf("building waf_engine_cluster: %w", err)
	}
	clusters = append(clusters, wafCluster)

	for _, site := range siteList {
		c, err := buildSiteCluster(site, cfg)
		if err != nil {
			return nil, fmt.Errorf("building cluster for %s: %w", site.Host, err)
		}
		clusters = append(clusters, c)
	}

	routeCfg, err := buildRouteConfig(siteList, cfg)
	if err != nil {
		return nil, fmt.Errorf("building route config: %w", err)
	}

	httpListener, err := buildHTTPListener(HTTPListenerName, cfg.HTTPPort, false, cfg)
	if err != nil {
		return nil, fmt.Errorf("building http listener: %w", err)
	}
	listeners := []types.Resource{httpListener}

	var secrets []types.Resource
	if cfg.EdgeTLS && cfg.HTTPSPort > 0 && cfg.EnvoyCertPath != "" && cfg.EnvoyKeyPath != "" {
		httpsListener, err := buildHTTPListener(HTTPSListenerName, cfg.HTTPSPort, true, cfg)
		if err != nil {
			return nil, fmt.Errorf("building https listener: %w", err)
		}
		listeners = append(listeners, httpsListener)
		secrets = append(secrets, &tlsv3.Secret{
			Name: EdgeTLSSecretName,
			Type: &tlsv3.Secret_TlsCertificate{
				TlsCertificate: &tlsv3.TlsCertificate{
					CertificateChain: &corev3.DataSource{
						Specifier: &corev3.DataSource_Filename{Filename: cfg.EnvoyCertPath},
					},
					PrivateKey: &corev3.DataSource{
						Specifier: &corev3.DataSource_Filename{Filename: cfg.EnvoyKeyPath},
					},
				},
			},
		})
	}

	resources := map[resourcev3.Type][]types.Resource{
		resourcev3.ClusterType:  clusters,
		resourcev3.RouteType:    {routeCfg},
		resourcev3.ListenerType: listeners,
	}
	if len(secrets) > 0 {
		resources[resourcev3.SecretType] = secrets
	}

	snap, err := cachev3.NewSnapshot(version, resources)
	if err != nil {
		return nil, fmt.Errorf("creating xDS snapshot %s: %w", version, err)
	}
	if err := snap.Consistent(); err != nil {
		return nil, fmt.Errorf("xDS snapshot consistency check failed: %w", err)
	}
	return snap, nil
}

// ClusterNameForHost derives a deterministic Envoy cluster name for a site host.
func ClusterNameForHost(host string) string {
	clean := strings.ToLower(strings.TrimSpace(host))
	var b strings.Builder
	b.WriteString("site_")
	for _, r := range clean {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func buildWAFEngineCluster(cfg TopologyConfig) (*clusterv3.Cluster, error) {
	http2Opts, err := anypb.New(&upstreamshttpv3.HttpProtocolOptions{
		UpstreamProtocolOptions: &upstreamshttpv3.HttpProtocolOptions_ExplicitHttpConfig_{
			ExplicitHttpConfig: &upstreamshttpv3.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &upstreamshttpv3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
					Http2ProtocolOptions: &corev3.Http2ProtocolOptions{
						MaxConcurrentStreams: wrapperspb.UInt32(256),
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	c := &clusterv3.Cluster{
		Name:                 WAFEngineClusterName,
		ConnectTimeout:       durationpb.New(2 * time.Second),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS},
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": http2Opts,
		},
		LoadAssignment: singleEndpointAssignment(WAFEngineClusterName, cfg.WAFEngineHost, cfg.WAFEnginePort),
	}

	if cfg.EngineMTLS && cfg.EnvoyCertPath != "" && cfg.EnvoyKeyPath != "" && cfg.CACertPath != "" {
		ts, err := buildUpstreamMTLSTransportSocket(cfg.WAFEngineHost, cfg.EnvoyCertPath, cfg.EnvoyKeyPath, cfg.CACertPath)
		if err != nil {
			return nil, err
		}
		c.TransportSocket = ts
	}
	return c, nil
}

func buildSiteCluster(site sites.Site, cfg TopologyConfig) (*clusterv3.Cluster, error) {
	host, port, err := parseUpstreamHostPort(site.Upstream)
	if err != nil {
		return nil, err
	}
	name := ClusterNameForHost(site.Host)
	c := &clusterv3.Cluster{
		Name:                 name,
		ConnectTimeout:       durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS},
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
		LoadAssignment:       singleEndpointAssignment(name, host, port),
	}
	if cfg.UpstreamMTLS && cfg.EnvoyCertPath != "" && cfg.EnvoyKeyPath != "" && cfg.CACertPath != "" {
		ts, err := buildUpstreamMTLSTransportSocket(host, cfg.EnvoyCertPath, cfg.EnvoyKeyPath, cfg.CACertPath)
		if err != nil {
			return nil, err
		}
		c.TransportSocket = ts
	}
	return c, nil
}

func buildUpstreamMTLSTransportSocket(sni, certPath, keyPath, caPath string) (*corev3.TransportSocket, error) {
	tlsCtx := &tlsv3.UpstreamTlsContext{
		Sni: sni,
		CommonTlsContext: &tlsv3.CommonTlsContext{
			AlpnProtocols: []string{"h2"},
			TlsParams: &tlsv3.TlsParameters{
				TlsMinimumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
				TlsMaximumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
			},
			TlsCertificates: []*tlsv3.TlsCertificate{
				{
					CertificateChain: &corev3.DataSource{
						Specifier: &corev3.DataSource_Filename{Filename: certPath},
					},
					PrivateKey: &corev3.DataSource{
						Specifier: &corev3.DataSource_Filename{Filename: keyPath},
					},
				},
			},
			ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
				ValidationContext: &tlsv3.CertificateValidationContext{
					TrustedCa: &corev3.DataSource{
						Specifier: &corev3.DataSource_Filename{Filename: caPath},
					},
				},
			},
		},
	}
	anyCtx, err := anypb.New(tlsCtx)
	if err != nil {
		return nil, err
	}
	return &corev3.TransportSocket{
		Name: wellknown.TransportSocketTls,
		ConfigType: &corev3.TransportSocket_TypedConfig{
			TypedConfig: anyCtx,
		},
	}, nil
}

func singleEndpointAssignment(clusterName, host string, port uint32) *endpointv3.ClusterLoadAssignment {
	return &endpointv3.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpointv3.LocalityLbEndpoints{
			{
				LbEndpoints: []*endpointv3.LbEndpoint{
					{
						HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
							Endpoint: &endpointv3.Endpoint{
								Address: &corev3.Address{
									Address: &corev3.Address_SocketAddress{
										SocketAddress: &corev3.SocketAddress{
											Protocol: corev3.SocketAddress_TCP,
											Address:  host,
											PortSpecifier: &corev3.SocketAddress_PortValue{
												PortValue: port,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func buildRouteConfig(siteList []sites.Site, cfg TopologyConfig) (*routev3.RouteConfiguration, error) {
	bypassFilters, err := buildBypassFilterConfig(cfg)
	if err != nil {
		return nil, err
	}

	healthRoutes := []*routev3.Route{
		{
			Match: &routev3.RouteMatch{
				PathSpecifier: &routev3.RouteMatch_Path{Path: "/healthz"},
			},
			Action: &routev3.Route_DirectResponse{
				DirectResponse: &routev3.DirectResponseAction{
					Status: 200,
					Body: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineString{InlineString: `{"status":"ok","plane":"data-plane","pep":"envoy"}`},
					},
				},
			},
			TypedPerFilterConfig: bypassFilters,
		},
		{
			Match: &routev3.RouteMatch{
				PathSpecifier: &routev3.RouteMatch_Path{Path: "/health"},
			},
			Action: &routev3.Route_DirectResponse{
				DirectResponse: &routev3.DirectResponseAction{
					Status: 200,
					Body: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineString{InlineString: `{"status":"ok","plane":"data-plane","pep":"envoy"}`},
					},
				},
			},
			TypedPerFilterConfig: bypassFilters,
		},
	}

	vhosts := make([]*routev3.VirtualHost, 0, len(siteList)+1)
	for _, site := range siteList {
		host := sites.NormalizeHost(site.Host)
		reqHeaders := make([]*corev3.HeaderValueOption, 0, len(site.Headers))
		for k, v := range site.Headers {
			reqHeaders = append(reqHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{Key: k, Value: v},
			})
		}

		routes := make([]*routev3.Route, 0, len(healthRoutes)+1)
		routes = append(routes, healthRoutes...)
		routes = append(routes, &routev3.Route{
			Match: &routev3.RouteMatch{
				PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"},
			},
			Action: &routev3.Route_Route{
				Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{
						Cluster: ClusterNameForHost(site.Host),
					},
					Timeout: durationpb.New(30 * time.Second),
				},
			},
			RequestHeadersToAdd: reqHeaders,
		})

		vhosts = append(vhosts, &routev3.VirtualHost{
			Name:    "vhost_" + ClusterNameForHost(site.Host),
			Domains: []string{host, host + ":*"},
			Routes:  routes,
		})
	}

	// Default-deny catch-all virtual host: health probes answer 200, while
	// unconfigured hosts return 404 without forwarding anywhere (Constitution §1.1).
	catchAllRoutes := make([]*routev3.Route, 0, len(healthRoutes)+1)
	catchAllRoutes = append(catchAllRoutes, healthRoutes...)
	catchAllRoutes = append(catchAllRoutes, &routev3.Route{
		Match: &routev3.RouteMatch{
			PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"},
		},
		Action: &routev3.Route_DirectResponse{
			DirectResponse: &routev3.DirectResponseAction{
				Status: 404,
				Body: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineString{InlineString: `{"error":"unknown host"}`},
				},
			},
		},
		TypedPerFilterConfig: bypassFilters,
	})

	vhosts = append(vhosts, &routev3.VirtualHost{
		Name:    "vhost_default_deny",
		Domains: []string{"*"},
		Routes:  catchAllRoutes,
	})

	return &routev3.RouteConfiguration{
		Name:         RouteConfigName,
		VirtualHosts: vhosts,
	}, nil
}

func buildBypassFilterConfig(cfg TopologyConfig) (map[string]*anypb.Any, error) {
	out := make(map[string]*anypb.Any)
	if cfg.EnableExtAuthz {
		anyAuth, err := anypb.New(&extauthzv3.ExtAuthzPerRoute{
			Override: &extauthzv3.ExtAuthzPerRoute_Disabled{Disabled: true},
		})
		if err != nil {
			return nil, err
		}
		out[ExtAuthzFilterName] = anyAuth
	}
	if cfg.EnableExtProc {
		anyProc, err := anypb.New(&extprocv3.ExtProcPerRoute{
			Override: &extprocv3.ExtProcPerRoute_Disabled{Disabled: true},
		})
		if err != nil {
			return nil, err
		}
		out[ExtProcFilterName] = anyProc
	}
	return out, nil
}

func buildHTTPListener(name string, port uint32, enableTLS bool, cfg TopologyConfig) (*listenerv3.Listener, error) {
	filters := make([]*hcmv3.HttpFilter, 0, 3)

	if cfg.EnableExtAuthz {
		extAuthzCfg, err := anypb.New(&extauthzv3.ExtAuthz{
			TransportApiVersion: corev3.ApiVersion_V3,
			Services: &extauthzv3.ExtAuthz_GrpcService{
				GrpcService: &corev3.GrpcService{
					TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
							ClusterName: WAFEngineClusterName,
						},
					},
					Timeout: durationpb.New(500 * time.Millisecond),
				},
			},
			FailureModeAllow:       cfg.FailureModeAllow,
			IncludePeerCertificate: true,
		})
		if err != nil {
			return nil, err
		}
		filters = append(filters, &hcmv3.HttpFilter{
			Name:       ExtAuthzFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: extAuthzCfg},
		})
	}

	if cfg.EnableExtProc {
		extProcCfg, err := anypb.New(&extprocv3.ExternalProcessor{
			GrpcService: &corev3.GrpcService{
				TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
						ClusterName: WAFEngineClusterName,
					},
				},
				Timeout: durationpb.New(2 * time.Second),
			},
			FailureModeAllow:  cfg.FailureModeAllow,
			AllowModeOverride: true,
			MessageTimeout:    durationpb.New(500 * time.Millisecond),
			ProcessingMode: &extprocv3.ProcessingMode{
				RequestHeaderMode:  extprocv3.ProcessingMode_SEND,
				RequestBodyMode:    extprocv3.ProcessingMode_BUFFERED,
				ResponseHeaderMode: extprocv3.ProcessingMode_SKIP,
				ResponseBodyMode:   extprocv3.ProcessingMode_NONE,
			},
		})
		if err != nil {
			return nil, err
		}
		filters = append(filters, &hcmv3.HttpFilter{
			Name:       ExtProcFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: extProcCfg},
		})
	}

	routerCfg, err := anypb.New(&routerv3.Router{})
	if err != nil {
		return nil, err
	}
	filters = append(filters, &hcmv3.HttpFilter{
		Name:       wellknown.Router,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: routerCfg},
	})

	statPrefix := "ingress_http"
	if enableTLS {
		statPrefix = "ingress_https"
	}

	hcm := &hcmv3.HttpConnectionManager{
		CodecType:        hcmv3.HttpConnectionManager_AUTO,
		StatPrefix:       statPrefix,
		UseRemoteAddress: wrapperspb.Bool(true),
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{
				RouteConfigName: RouteConfigName,
				ConfigSource: &corev3.ConfigSource{
					ResourceApiVersion: corev3.ApiVersion_V3,
					ConfigSourceSpecifier: &corev3.ConfigSource_Ads{
						Ads: &corev3.AggregatedConfigSource{},
					},
				},
			},
		},
		HttpFilters: filters,
	}

	hcmAny, err := anypb.New(hcm)
	if err != nil {
		return nil, err
	}

	fc := &listenerv3.FilterChain{
		Filters: []*listenerv3.Filter{
			{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: hcmAny},
			},
		},
	}

	if enableTLS {
		downstreamTLS := &tlsv3.DownstreamTlsContext{
			CommonTlsContext: &tlsv3.CommonTlsContext{
				AlpnProtocols: []string{"h2", "http/1.1"},
				TlsParams: &tlsv3.TlsParameters{
					TlsMinimumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
					TlsMaximumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
				},
				TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{
					{
						Name: EdgeTLSSecretName,
						SdsConfig: &corev3.ConfigSource{
							ResourceApiVersion: corev3.ApiVersion_V3,
							ConfigSourceSpecifier: &corev3.ConfigSource_Ads{
								Ads: &corev3.AggregatedConfigSource{},
							},
						},
					},
				},
			},
		}
		tlsAny, err := anypb.New(downstreamTLS)
		if err != nil {
			return nil, err
		}
		fc.TransportSocket = &corev3.TransportSocket{
			Name:       wellknown.TransportSocketTls,
			ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: tlsAny},
		}
	}

	return &listenerv3.Listener{
		Name: name,
		Address: &corev3.Address{
			Address: &corev3.Address_SocketAddress{
				SocketAddress: &corev3.SocketAddress{
					Protocol: corev3.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &corev3.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(cfg.MaxRequestBodyBytes),
		FilterChains:                  []*listenerv3.FilterChain{fc},
	}, nil
}

func parseUpstreamHostPort(raw string) (string, uint32, error) {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "http://")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	if idx := strings.IndexByte(trimmed, '/'); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	if !strings.Contains(trimmed, ":") {
		return trimmed, 80, nil
	}
	host, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		return "", 0, fmt.Errorf("invalid upstream %q: %w", raw, err)
	}
	p, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil || p == 0 || p > 65535 {
		return "", 0, fmt.Errorf("invalid upstream port %q in %q", portStr, raw)
	}
	return host, uint32(p), nil
}
