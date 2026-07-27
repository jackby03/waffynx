package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
)

type Manager struct {
	mu          sync.RWMutex
	certificates map[string]*tls.Certificate
	clientCAs   *x509.CertPool
	config      *tls.Config
	autoCert    bool
}

func NewManager() *Manager {
	return &Manager{
		certificates: make(map[string]*tls.Certificate),
	}
}

func (m *Manager) LoadCertificate(name, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("loading key pair for %s: %w", name, err)
	}

	m.mu.Lock()
	m.certificates[name] = &cert
	m.mu.Unlock()

	return nil
}

func (m *Manager) LoadClientCA(caFile string) error {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("reading CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	m.mu.Lock()
	m.clientCAs = pool
	m.mu.Unlock()

	return nil
}

func (m *Manager) GetCertificate(serverName string) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if cert, ok := m.certificates[serverName]; ok {
		return cert, nil
	}

	for _, cert := range m.certificates {
		return cert, nil
	}

	return nil, fmt.Errorf("no certificate for %s", serverName)
}

func (m *Manager) TLSConfig() *tls.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return m.GetCertificate(info.ServerName)
		},
	}

	if m.clientCAs != nil {
		cfg.ClientCAs = m.clientCAs
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg
}
