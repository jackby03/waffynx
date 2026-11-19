// Package pki manages Zero-Trust internal PKI material and hot-reloading TLS 1.3
// mTLS configurations across Waffynx containers (Constitution §1.4 & §2.2).
//
// In Kubernetes/production, external CAs (step-ca, SPIRE, cert-manager) mount
// rotated leaf certificates and the CA bundle into the container volume; Reloader
// refreshes them transparently via GetCertificate/GetClientCertificate without
// dropping active connections. For self-hosted Docker Compose deployments,
// EnsureBundle provisions an internal ECDSA P-256 CA and per-service certificates
// with strict 0600 private-key permissions.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ServiceSpec declares a service identity certificate signed by the internal CA.
type ServiceSpec struct {
	Name     string
	DNSNames []string
	IPs      []net.IP
}

// DefaultServices returns the standard multi-container service identities used
// in Zero-Trust Docker Compose and Kubernetes deployments.
func DefaultServices() []ServiceSpec {
	loopback := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	return []ServiceSpec{
		{Name: "envoy", DNSNames: []string{"envoy", "waffynx-envoy", "localhost", "app.example.test"}, IPs: loopback},
		{Name: "waf-engine", DNSNames: []string{"waf-engine", "waffynx-engine", "localhost"}, IPs: loopback},
		{Name: "control-api", DNSNames: []string{"control-api", "waf-api", "waffynx-control-api", "localhost"}, IPs: loopback},
		{Name: "backend", DNSNames: []string{"backend", "upstream", "localhost"}, IPs: loopback},
		{Name: "log-ingestor", DNSNames: []string{"log-ingestor", "localhost"}, IPs: loopback},
	}
}

// EnsureBundle generates an internal Root CA (ca.crt, ca.key) and leaf
// certificates (<name>.crt, <name>.key) inside dir if they do not already exist.
// All private keys are written atomically with mode 0600 (Constitution §2.2).
func EnsureBundle(dir string, services []ServiceSpec, validity time.Duration) error {
	if dir == "" {
		return fmt.Errorf("pki directory is required")
	}
	if validity <= 0 {
		validity = 365 * 24 * time.Hour
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating pki dir %s: %w", dir, err)
	}

	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	caCert, caKey, err := loadOrCreateCA(caCertPath, caKeyPath, validity)
	if err != nil {
		return err
	}

	for _, svc := range services {
		certPath := filepath.Join(dir, svc.Name+".crt")
		keyPath := filepath.Join(dir, svc.Name+".key")
		if fileExists(certPath) && fileExists(keyPath) {
			continue
		}
		if err := issueLeafCert(caCert, caKey, svc, certPath, keyPath, validity); err != nil {
			return fmt.Errorf("issuing cert for %s: %w", svc.Name, err)
		}
	}
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

func loadOrCreateCA(certPath, keyPath string, validity time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, nil, fmt.Errorf("reading ca cert: %w", err)
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("reading ca key: %w", err)
		}
		cb, _ := pem.Decode(certPEM)
		kb, _ := pem.Decode(keyPEM)
		if cb == nil || kb == nil {
			return nil, nil, fmt.Errorf("corrupt ca pem files")
		}
		cert, err := x509.ParseCertificate(cb.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing ca cert: %w", err)
		}
		key, err := x509.ParseECPrivateKey(kb.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing ca key: %w", err)
		}
		return cert, key, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Waffynx Zero-Trust Internal CA"},
			CommonName:   "waffynx-internal-ca",
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity * 3),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating ca certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing generated ca cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling ca key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeFileMode(certPath, certPEM, 0o644); err != nil {
		return nil, nil, err
	}
	if err := writeFileMode(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func issueLeafCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, svc ServiceSpec, certPath, keyPath string, validity time.Duration) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating service key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Waffynx Zero-Trust Mesh"},
			CommonName:   svc.Name,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              svc.DNSNames,
		IPAddresses:           svc.IPs,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("signing certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling service key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeFileMode(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return writeFileMode(keyPath, keyPEM, 0o600)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	return n, nil
}

func writeFileMode(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pki-*")
	if err != nil {
		return fmt.Errorf("creating temp pki file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	tmpName = ""
	return nil
}

// Reloader loads and transparently reloads an X.509 keypair and CA trust bundle
// when the backing files change on disk (e.g. step-ca / SPIRE / cert-manager).
type Reloader struct {
	certPath string
	keyPath  string
	caPath   string

	mu          sync.RWMutex
	cert        *tls.Certificate
	certModTime time.Time
	caPool      *x509.CertPool
}

// NewReloader validates and loads certPath, keyPath, and caPath immediately
// (fail-closed at startup if credentials are missing or invalid).
func NewReloader(certPath, keyPath, caPath string) (*Reloader, error) {
	r := &Reloader{
		certPath: certPath,
		keyPath:  keyPath,
		caPath:   caPath,
	}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload parses the keypair and CA bundle from disk and swaps them under lock.
func (r *Reloader) Reload() error {
	pair, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("loading keypair (%s, %s): %w", r.certPath, r.keyPath, err)
	}
	info, err := os.Stat(r.certPath)
	if err != nil {
		return fmt.Errorf("stating cert %s: %w", r.certPath, err)
	}

	var pool *x509.CertPool
	if r.caPath != "" {
		caPEM, err := os.ReadFile(r.caPath)
		if err != nil {
			return fmt.Errorf("reading ca bundle %s: %w", r.caPath, err)
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("no valid CA certificates in %s", r.caPath)
		}
	}

	r.mu.Lock()
	r.cert = &pair
	r.certModTime = info.ModTime()
	r.caPool = pool
	r.mu.Unlock()
	return nil
}

func (r *Reloader) currentCert() (*tls.Certificate, error) {
	info, err := os.Stat(r.certPath)
	r.mu.RLock()
	cached := r.cert
	modTime := r.certModTime
	r.mu.RUnlock()

	if err == nil && info.ModTime().After(modTime) {
		if reloadErr := r.Reload(); reloadErr == nil {
			r.mu.RLock()
			cached = r.cert
			r.mu.RUnlock()
		}
	}
	if cached == nil {
		return nil, fmt.Errorf("no certificate loaded")
	}
	return cached, nil
}

// ServerTLSConfig returns a TLS 1.3 server configuration enforcing strict mTLS
// when a CA bundle is configured (Constitution §1.4).
func (r *Reloader) ServerTLSConfig(requireClientCert bool) *tls.Config {
	r.mu.RLock()
	pool := r.caPool
	r.mu.RUnlock()

	clientAuth := tls.NoClientCert
	if requireClientCert {
		clientAuth = tls.RequireAndVerifyClientCert
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientCAs:  pool,
		ClientAuth: clientAuth,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return r.currentCert()
		},
	}
}

// ClientTLSConfig returns a TLS 1.3 client configuration presenting the service
// leaf certificate and verifying the server against the internal CA bundle.
func (r *Reloader) ClientTLSConfig(serverName string) *tls.Config {
	r.mu.RLock()
	pool := r.caPool
	r.mu.RUnlock()

	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    pool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return r.currentCert()
		},
	}
}
