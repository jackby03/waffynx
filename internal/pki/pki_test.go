package pki

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureBundleAndMTLSHandshake(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureBundle(dir, DefaultServices(), 24*time.Hour); err != nil {
		t.Fatalf("EnsureBundle failed: %v", err)
	}

	// Idempotent second call preserves existing CA and certs.
	caBefore, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	if err := EnsureBundle(dir, DefaultServices(), 24*time.Hour); err != nil {
		t.Fatalf("second EnsureBundle failed: %v", err)
	}
	caAfter, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if string(caBefore) != string(caAfter) {
		t.Fatal("EnsureBundle overwrote existing CA")
	}

	// Load server (waf-engine) and client (envoy) reloaders.
	srvReloader, err := NewReloader(
		filepath.Join(dir, "waf-engine.crt"),
		filepath.Join(dir, "waf-engine.key"),
		filepath.Join(dir, "ca.crt"),
	)
	if err != nil {
		t.Fatalf("server NewReloader: %v", err)
	}
	cliReloader, err := NewReloader(
		filepath.Join(dir, "envoy.crt"),
		filepath.Join(dir, "envoy.key"),
		filepath.Join(dir, "ca.crt"),
	)
	if err != nil {
		t.Fatalf("client NewReloader: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvReloader.ServerTLSConfig(true))
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		done <- tlsConn.Handshake()
	}()

	// Valid mTLS client succeeds.
	conn, err := tls.Dial("tcp", ln.Addr().String(), cliReloader.ClientTLSConfig("waf-engine"))
	if err != nil {
		t.Fatalf("mTLS client dial failed: %v", err)
	}
	_ = conn.Close()
	if err := <-done; err != nil {
		t.Fatalf("server mTLS handshake failed: %v", err)
	}

	// Unauthenticated client (no client cert) must be rejected fail-closed.
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer c.Close()
		_ = c.(*tls.Conn).Handshake()
	}()
	badCfg := cliReloader.ClientTLSConfig("waf-engine")
	badCfg.GetClientCertificate = nil
	badConn, dialErr := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ln.Addr().String(), badCfg)
	if dialErr == nil {
		// TLS 1.3 delivers alert on first read after handshake.
		buf := make([]byte, 8)
		_, readErr := badConn.Read(buf)
		_ = badConn.Close()
		if readErr == nil {
			t.Fatal("expected unauthenticated mTLS client to be rejected")
		}
	}
}

func TestEnsureBundleErrors(t *testing.T) {
	if err := EnsureBundle("", DefaultServices(), time.Hour); err == nil {
		t.Fatal("expected error for empty dir")
	}
	if _, err := NewReloader("missing.crt", "missing.key", "missing.ca"); err == nil {
		t.Fatal("expected error for missing cert files")
	}
}
