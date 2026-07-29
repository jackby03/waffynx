package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPool_Empty(t *testing.T) {
	p := NewPool("round_robin")
	if target := p.Next(""); target != nil {
		t.Errorf("expected nil target for empty pool, got %v", target)
	}
}

func TestPool_AddTarget(t *testing.T) {
	p := NewPool("round_robin")
	err := p.AddTarget("http://127.0.0.1:8080", 1)
	if err != nil {
		t.Fatalf("unexpected error adding target: %v", err)
	}

	err = p.AddTarget(":% invalid url", 1)
	if err == nil {
		t.Error("expected error for invalid url, got nil")
	}
}

func TestPool_RoundRobin(t *testing.T) {
	p := NewPool("round_robin")
	_ = p.AddTarget("http://backend1:8080", 1)
	_ = p.AddTarget("http://backend2:8080", 1)
	_ = p.AddTarget("http://backend3:8080", 1)

	// Expected order: backend2, backend3, backend1, backend2, backend3, backend1
	// because atomic.AddUint64(&p.index, 1) starts at 1.
	expectedHosts := []string{
		"backend2:8080",
		"backend3:8080",
		"backend1:8080",
		"backend2:8080",
		"backend3:8080",
		"backend1:8080",
	}

	for i, expected := range expectedHosts {
		tTarget := p.Next("")
		if tTarget == nil {
			t.Fatalf("call %d: expected target, got nil", i)
		}
		if tTarget.URL.Host != expected {
			t.Errorf("call %d: expected host %s, got %s", i, expected, tTarget.URL.Host)
		}
	}
}

func TestPool_LeastConn(t *testing.T) {
	p := NewPool("least_conn")
	_ = p.AddTarget("http://backend1:8080", 1)
	_ = p.AddTarget("http://backend2:8080", 1)
	_ = p.AddTarget("http://backend3:8080", 1)

	// Set active connections: backend1=10, backend2=2, backend3=5
	p.targets[0].activeConns = 10
	p.targets[1].activeConns = 2
	p.targets[2].activeConns = 5

	target := p.Next("")
	if target == nil || target.URL.Host != "backend2:8080" {
		t.Fatalf("expected backend2:8080 (least conns=2), got %v", target)
	}

	// Update backend2 active connections to 15
	atomic.StoreInt64(&p.targets[1].activeConns, 15)

	target = p.Next("")
	if target == nil || target.URL.Host != "backend3:8080" {
		t.Fatalf("expected backend3:8080 (least conns=5), got %v", target)
	}
}

func TestPool_IPHash(t *testing.T) {
	p := NewPool("ip_hash")
	_ = p.AddTarget("http://backend1:8080", 1)
	_ = p.AddTarget("http://backend2:8080", 1)
	_ = p.AddTarget("http://backend3:8080", 1)

	// Same client IP should consistently hit the same backend
	clientIP := "192.168.1.100:12345"
	firstTarget := p.Next(clientIP)
	if firstTarget == nil {
		t.Fatal("expected target, got nil")
	}

	for i := 0; i < 10; i++ {
		target := p.Next(clientIP)
		if target.URL.Host != firstTarget.URL.Host {
			t.Errorf("call %d: expected consistent host %s for IP %s, got %s",
				i, firstTarget.URL.Host, clientIP, target.URL.Host)
		}
	}
}

func TestPool_HealthCheck(t *testing.T) {
	// Server 1: Healthy (200 OK)
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()

	// Server 2: Unhealthy (500 Error)
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server2.Close()

	p := NewPool("round_robin")
	_ = p.AddTarget(server1.URL, 1)
	_ = p.AddTarget(server2.URL, 1)

	// Run checkAll 3 times so failure count reaches 3
	for i := 0; i < 3; i++ {
		p.checkAll("/health")
	}

	// Server 1 should be healthy, Server 2 should be unhealthy
	if !p.targets[0].healthy.Load() {
		t.Errorf("expected target 1 to be healthy")
	}
	if p.targets[1].healthy.Load() {
		t.Errorf("expected target 2 to be unhealthy after 3 failures")
	}

	// Next() should now only return target 1
	for i := 0; i < 5; i++ {
		target := p.Next("")
		if target == nil || target.URL.String() != server1.URL {
			t.Errorf("call %d: expected healthy target %s, got %v", i, server1.URL, target)
		}
	}
}

func TestPool_HealthCheck_Background(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := NewPool("round_robin")
	_ = p.AddTarget(server.URL, 1)

	ctx, cancel := context.WithCancel(context.Background())

	go p.HealthCheck(ctx, "/health", 10*time.Millisecond)

	time.Sleep(30 * time.Millisecond)
	cancel() // Stop health check loop

	if !p.targets[0].healthy.Load() {
		t.Error("expected target to be marked healthy by background health check")
	}
}
