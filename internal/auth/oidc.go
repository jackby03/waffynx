package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
)

type OIDCManager struct {
	mu        sync.RWMutex
	providers map[string]*oidcProvider
	verifiers map[string]*oidc.IDTokenVerifier
}

type oidcProvider struct {
	name    string
	provider *oidc.Provider
}

func NewOIDCManager() *OIDCManager {
	return &OIDCManager{
		providers: make(map[string]*oidcProvider),
		verifiers: make(map[string]*oidc.IDTokenVerifier),
	}
}

func (m *OIDCManager) Configure(providers []config.OIDCProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, cfg := range providers {
		if cfg.IssuerURL == "" || cfg.ClientID == "" {
			continue
		}

		provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
		if err != nil {
			logging.Warn().Err(err).Str("provider", cfg.Name).Str("issuer", cfg.IssuerURL).
				Msg("failed to initialize OIDC provider")
			continue
		}

		name := cfg.Name
		if name == "" {
			name = cfg.IssuerURL
		}

		m.providers[name] = &oidcProvider{
			name:    name,
			provider: provider,
		}

		m.verifiers[name] = provider.Verifier(&oidc.Config{
			ClientID: cfg.ClientID,
		})

		logging.Info().Str("provider", name).Str("issuer", cfg.IssuerURL).Msg("OIDC provider configured")
	}

	if len(m.providers) == 0 {
		return nil
	}

	logging.Info().Int("providers", len(m.providers)).Msg("OIDC authentication enabled")
	return nil
}

func (m *OIDCManager) ValidateToken(ctx context.Context, rawToken string) (string, string, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.verifiers) == 0 {
		return "", "", "", fmt.Errorf("no OIDC providers configured")
	}

	var lastErr error
	for name, verifier := range m.verifiers {
		idToken, err := verifier.Verify(ctx, rawToken)
		if err != nil {
			lastErr = err
			continue
		}

		var claims struct {
			Email    string   `json:"email"`
			Name     string   `json:"name"`
			Username string   `json:"preferred_username"`
			Groups   []string `json:"groups"`
		}
		if err := idToken.Claims(&claims); err != nil {
			lastErr = fmt.Errorf("parsing claims from %s: %w", name, err)
			continue
		}

		username := claims.Username
		if username == "" {
			username = claims.Email
		}
		if username == "" {
			username = claims.Name
		}
		if username == "" {
			username = idToken.Subject
		}

		role := "viewer"
		for _, g := range claims.Groups {
			if g == "admin" || g == "waffynx-admin" {
				role = "admin"
				break
			}
		}

		return username, role, name, nil
	}

	return "", "", "", fmt.Errorf("OIDC validation failed: %w", lastErr)
}

func (m *OIDCManager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.providers) > 0
}
