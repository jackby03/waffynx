package upstream

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackby03/waffynx/internal/logging"
)

type HealthStatus string

const (
	StatusHealthy   HealthStatus = "healthy"
	StatusUnhealthy HealthStatus = "unhealthy"
)

type Target struct {
	URL         *url.URL
	Weight      int
	MaxConns    int
	activeConns int64
	healthy     atomic.Bool
	failures    atomic.Int64
}

type Pool struct {
	mu      sync.RWMutex
	targets []*Target
	index   uint64
	lbType  string // round_robin, least_conn, ip_hash
}

func NewPool(lbType string) *Pool {
	return &Pool{
		lbType: lbType,
	}
}

func (p *Pool) AddTarget(addr string, weight int) error {
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}

	t := &Target{
		URL:    u,
		Weight: weight,
	}
	t.healthy.Store(true)

	p.mu.Lock()
	p.targets = append(p.targets, t)
	p.mu.Unlock()

	return nil
}

func (p *Pool) Next() *Target {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.targets) == 0 {
		return nil
	}

	switch p.lbType {
	case "least_conn":
		return p.leastConn()
	case "round_robin":
		fallthrough
	default:
		return p.roundRobin()
	}
}

func (p *Pool) roundRobin() *Target {
	if len(p.targets) == 0 {
		return nil
	}

	n := atomic.AddUint64(&p.index, 1)
	idx := int(n) % len(p.targets)

	for i := 0; i < len(p.targets); i++ {
		t := p.targets[(idx+i)%len(p.targets)]
		if t.healthy.Load() {
			return t
		}
	}
	return nil
}

func (p *Pool) leastConn() *Target {
	var best *Target
	minConns := int64(1<<63 - 1)

	for _, t := range p.targets {
		if !t.healthy.Load() {
			continue
		}
		conns := atomic.LoadInt64(&t.activeConns)
		if conns < minConns {
			minConns = conns
			best = t
		}
	}
	return best
}

func (p *Pool) CreateReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			target := p.Next()
			if target == nil {
				logging.Error().Msg("no healthy upstream targets")
				return
			}

			atomic.AddInt64(&target.activeConns, 1)
			req.URL.Scheme = target.URL.Scheme
			req.URL.Host = target.URL.Host
			req.Host = target.URL.Host

			go func() {
				<-req.Context().Done()
				atomic.AddInt64(&target.activeConns, -1)
			}()
		},
		Transport: &http.Transport{
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
		},
	}
}

func (p *Pool) HealthCheck(ctx context.Context, path string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkAll(path)
		}
	}
}

func (p *Pool) checkAll(path string) {
	p.mu.RLock()
	targets := make([]*Target, len(p.targets))
	copy(targets, p.targets)
	p.mu.RUnlock()

	for _, t := range targets {
		checkURL := t.URL.String() + path
		resp, err := http.Get(checkURL)
		if err != nil || resp.StatusCode >= 500 {
			t.failures.Add(1)
			if t.failures.Load() >= 3 {
				t.healthy.Store(false)
				logging.Warn().Str("target", t.URL.Host).Msg("target marked unhealthy")
			}
		} else {
			t.failures.Store(0)
			t.healthy.Store(true)
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
}
