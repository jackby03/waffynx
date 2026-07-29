package upstream

import (
	"testing"
)

func TestPool_RoundRobin(t *testing.T) {
	p := NewPool("round_robin")
	p.AddTarget("http://backend1:8080", 1)
	p.AddTarget("http://backend2:8080", 1)
	p.AddTarget("http://backend3:8080", 1)

	seen := make(map[string]int)
	for i := 0; i < 6; i++ {
		target := p.Next("")
		if target == nil {
			t.Fatal("expected target")
		}
		seen[target.URL.Host]++
	}

	if seen["backend1:8080"] != 2 || seen["backend2:8080"] != 2 || seen["backend3:8080"] != 2 {
		t.Errorf("expected each backend 2 times, got: %v", seen)
	}
}

func TestPool_LeastConn(t *testing.T) {
	p := NewPool("least_conn")
	p.AddTarget("http://backend1:8080", 1)
	p.AddTarget("http://backend2:8080", 1)

	p.targets[0].activeConns = 10
	p.targets[1].activeConns = 0

	target := p.Next("")
	if target == nil {
		t.Fatal("expected target")
	}
	if target.URL.Host != "backend2:8080" {
		t.Errorf("expected backend2 with fewer connections, got %s", target.URL.Host)
	}
}

func TestPool_IPHash(t *testing.T) {
	p := NewPool("ip_hash")
	p.AddTarget("http://backend1:8080", 1)
	p.AddTarget("http://backend2:8080", 1)
	p.AddTarget("http://backend3:8080", 1)

	first := p.Next("10.0.0.1:12345")
	second := p.Next("10.0.0.1:54321")
	third := p.Next("10.0.0.2:12345")

	if first == nil || second == nil || third == nil {
		t.Fatal("expected targets")
	}

	if first.URL.Host != second.URL.Host {
		t.Errorf("same IP should map to same backend: %s vs %s", first.URL.Host, second.URL.Host)
	}

	if third.URL.Host == first.URL.Host {
		t.Log("different IPs may map to same backend due to hash collision")
	}
}

func TestPool_Empty(t *testing.T) {
	p := NewPool("round_robin")
	if p.Next("") != nil {
		t.Error("expected nil for empty pool")
	}
}

func TestPool_AllUnhealthy(t *testing.T) {
	p := NewPool("round_robin")
	p.AddTarget("http://backend1:8080", 1)
	p.AddTarget("http://backend2:8080", 1)

	p.targets[0].healthy.Store(false)
	p.targets[1].healthy.Store(false)

	target := p.Next("")
	if target != nil {
		t.Error("expected nil when all targets unhealthy")
	}
}

func TestPool_SkipsUnhealthy(t *testing.T) {
	p := NewPool("round_robin")
	p.AddTarget("http://backend1:8080", 1)
	p.AddTarget("http://backend2:8080", 1)

	p.targets[0].healthy.Store(false)

	for i := 0; i < 5; i++ {
		target := p.Next("")
		if target == nil {
			t.Fatal("expected target")
		}
		if target.URL.Host != "backend2:8080" {
			t.Errorf("expected healthy backend2, got %s", target.URL.Host)
		}
	}
}
