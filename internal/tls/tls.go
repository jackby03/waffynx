package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/jackby03/waffynx/internal/logging"
)

type Manager struct {
	mu           sync.RWMutex
	certificates map[string]*tls.Certificate
	clientCAs    *x509.CertPool
	config       *tls.Config
	autoCert     bool
	acmeManager  *autocert.Manager
}

type ACMEConfig struct {
	Enabled    bool
	Domains    []string
	Email      string
	CacheDir   string
	Staging    bool
}

func NewManager() *Manager {
	return &Manager{
		certificates: make(map[string]*tls.Certificate),
	}
}

func (m *Manager) EnableACME(cfg ACMEConfig) error {
	if !cfg.Enabled || len(cfg.Domains) == 0 {
		return nil
	}

	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = "/opt/waffynx/certs/acme-cache"
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return fmt.Errorf("creating ACME cache dir: %w", err)
	}

	directory := "https://acme-v02.api.letsencrypt.org/directory"
	if cfg.Staging {
		directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}

	m.acmeManager = &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Email:      cfg.Email,
		Client:     &acme.Client{DirectoryURL: directory},
	}

	m.autoCert = true

	logging.Info().
		Strs("domains", cfg.Domains).
		Str("cache", cacheDir).
		Bool("staging", cfg.Staging).
		Msg("ACME certificate auto-renewal enabled")

	return nil
}

func (m *Manager) ACMEHandler() http.Handler {
	if m.acmeManager == nil {
		return nil
	}
	return m.acmeManager.HTTPHandler(nil)
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

	if m.autoCert && m.acmeManager != nil {
		cert, err := m.acmeManager.GetCertificate(&tls.ClientHelloInfo{
			ServerName: serverName,
		})
		if err == nil {
			return cert, nil
		}
		logging.Warn().Err(err).Str("domain", serverName).Msg("ACME cert lookup failed, falling back to static certs")
	}

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

func (m *Manager) Shutdown(ctx context.Context) error {
	return nil
}
