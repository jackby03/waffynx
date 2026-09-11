package api

import (
	"context"
	"time"

	"github.com/jackby03/waffynx/internal/auth"
)

// BannedIP represents an IP blocked by host firewall rules with TTL tracking.
type BannedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TTL       int       `json:"ttl"`
}

// UserFromContext extracts the authenticated username from the request context.
func UserFromContext(ctx context.Context) string {
	if claims, ok := ctx.Value("claims").(*auth.Claims); ok && claims != nil {
		return claims.Username
	}
	return "admin"
}
