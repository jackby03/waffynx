package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/auth"
	"github.com/jackby03/waffynx/internal/logging"
)

// ctxKey is the unexported type used for every context key defined by this
// package. Using a dedicated type instead of a bare string prevents key
// collisions with values set by other packages (staticcheck SA1029).
type ctxKey string

// claimsKey is the context key holding the authenticated *auth.Claims.
const claimsKey ctxKey = "claims"

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logging.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Dur("duration", time.Since(start)).
			Msg("api request")
	})
}

func (s *Server) authMiddleware(mux *http.ServeMux) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				s.writeError(w, r, http.StatusUnauthorized, "missing authorization header")
				return
			}

			token := strings.TrimPrefix(header, "Bearer ")
			if token == header {
				s.writeError(w, r, http.StatusUnauthorized, "invalid authorization format")
				return
			}

			if s.oidcMgr != nil && s.oidcMgr.Enabled() {
				username, role, provider, err := s.oidcMgr.ValidateToken(r.Context(), token)
				if err == nil {
					claims := &auth.Claims{
						Username: username,
						Role:     role,
						Scopes:   []string{"read", "write"},
					}
					ctx := context.WithValue(r.Context(), claimsKey, claims)
					logging.Debug().Str("user", username).Str("provider", provider).Msg("OIDC authenticated")
					next(w, r.WithContext(ctx))
					return
				}
				logging.Debug().Err(err).Msg("OIDC validation failed, trying local JWT")
			}

			claims, err := s.authMgr.ValidateToken(token)
			if err != nil {
				s.writeError(w, r, http.StatusUnauthorized, "invalid token: "+err.Error())
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next(w, r.WithContext(ctx))
		}
	}
}

func (s *Server) requireRole(role string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(claimsKey).(*auth.Claims)
			if !ok || claims == nil {
				s.writeError(w, r, http.StatusUnauthorized, "unauthorized")
				return
			}
			if claims.Role != role && claims.Role != "admin" {
				s.writeError(w, r, http.StatusForbidden, "insufficient permissions: requires "+role+" role")
				return
			}
			next(w, r)
		}
	}
}

func (s *Server) requireScope(scope string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(claimsKey).(*auth.Claims)
			if !ok || claims == nil {
				s.writeError(w, r, http.StatusUnauthorized, "unauthorized")
				return
			}
			for _, granted := range claims.Scopes {
				if granted == scope {
					next(w, r)
					return
				}
			}
			s.writeError(w, r, http.StatusForbidden, "insufficient permissions")
		}
	}
}

type auditResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *auditResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *auditResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap exposes the underlying writer so http.ResponseController can reach it.
//
// Without it, a streaming handler cannot clear the server WriteTimeout: the
// controller returns ErrNotSupported for any wrapper that does not implement
// Unwrap, the deadline stays at 10s, and the SSE feed dies at the heartbeat.
func (w *auditResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (s *Server) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.audit == nil {
			next.ServeHTTP(w, r)
			return
		}

		rw := &auditResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		actor := "anonymous"
		actorIP := r.RemoteAddr
		if claims, ok := r.Context().Value(claimsKey).(*auth.Claims); ok && claims != nil {
			actor = claims.Username
		}

		result := "allowed"
		if rw.statusCode >= 400 {
			result = "blocked"
		}

		s.audit.Record(audit.Event{
			Actor:   actor,
			ActorIP: actorIP,
			Action:  r.Method + " " + r.URL.Path,
			Result:  result,
			Details: fmt.Sprintf("HTTP %d", rw.statusCode),
		})
	})
}

// corsPathPrefix is the only path prefix CORS is applied to.
//
// Scoping matters: wrapping the whole mux would newly expose /metrics (which is
// unauthenticated) and /debug/pprof to any browser on an allowed origin. Before
// this middleware existed those paths sent no CORS headers at all.
const corsPathPrefix = "/api/v1/"

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, corsPathPrefix) {
			next.ServeHTTP(w, r)
			return
		}

		origin := r.Header.Get("Origin")
		allowedOrigin := ""
		cfg := s.readConfig()

		if origin != "" {
			w.Header().Add("Vary", "Origin")
		}

		if cfg != nil && len(cfg.API.AllowedOrigins) > 0 && origin != "" {
			for _, o := range cfg.API.AllowedOrigins {
				if o != "*" && o == origin {
					allowedOrigin = o
					break
				}
			}
		}

		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}

		if r.Method == http.MethodOptions {
			if allowedOrigin != "" {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}
