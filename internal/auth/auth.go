package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	jwt.RegisteredClaims
	Username string   `json:"username"`
	Role     string   `json:"role"`
	Scopes   []string `json:"scopes"`
}

type Manager struct {
	secret   []byte
	TokenTTL time.Duration
}

func NewManager(secret string, ttlSeconds int) *Manager {
	return &Manager{
		secret:   []byte(secret),
		TokenTTL: time.Duration(ttlSeconds) * time.Second,
	}
}

func (m *Manager) GenerateToken(username, role string, scopes []string) (string, error) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.TokenTTL)),
		},
		Username: username,
		Role:     role,
		Scopes:   scopes,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.secret, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (m *Manager) SignPayload(payload []byte) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func (m *Manager) VerifySignature(payload []byte, signature string) bool {
	expected := m.SignPayload(payload)
	return hmac.Equal([]byte(expected), []byte(signature))
}
