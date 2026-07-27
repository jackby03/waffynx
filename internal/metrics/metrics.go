package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waffynx_requests_total",
			Help: "Total number of requests processed",
		},
		[]string{"host", "method", "status"},
	)

	RequestsBlocked = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waffynx_requests_blocked_total",
			Help: "Total number of requests blocked by WAF",
		},
		[]string{"rule_id", "reason"},
	)

	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "waffynx_request_duration_seconds",
			Help:    "Request processing duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"host", "method"},
	)

	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "waffynx_active_connections",
			Help: "Current number of active connections",
		},
	)

	UpstreamHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "waffynx_upstream_healthy",
			Help: "Upstream health status (1=healthy, 0=unhealthy)",
		},
		[]string{"upstream"},
	)

	PluginExecutions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waffynx_plugin_executions_total",
			Help: "Total number of plugin executions",
		},
		[]string{"plugin", "phase"},
	)

	FirewallRules = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "waffynx_firewall_rules_total",
			Help: "Total number of active firewall rules",
		},
	)
)

func init() {
	prometheus.MustRegister(
		RequestsTotal,
		RequestsBlocked,
		RequestDuration,
		ActiveConnections,
		UpstreamHealth,
		PluginExecutions,
		FirewallRules,
	)
}

func Handler() http.Handler {
	return promhttp.Handler()
}
