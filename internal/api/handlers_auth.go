package api

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/jackby03/waffynx/internal/auth"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// handleMe echoes the identity the auth middleware already validated. It reads
// only the request context: no database lookup and no config read, so the answer
// cannot disagree with the token that authorised the call.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(claimsKey).(*auth.Claims)
	if !ok || claims == nil {
		s.writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}

	scopes := claims.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"username": claims.Username,
		"role":     claims.Role,
		"scopes":   scopes,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		s.writeError(w, r, http.StatusBadRequest, "username and password required")
		return
	}

	cfg := s.readConfig()
	if len(cfg.API.Auth.Users) == 0 {
		s.writeError(w, r, http.StatusNotImplemented, "no users configured")
		return
	}

	for _, u := range cfg.API.Auth.Users {
		if u.Username == req.Username {
			if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
				s.writeError(w, r, http.StatusUnauthorized, "invalid credentials")
				return
			}
			token, err := s.authMgr.GenerateToken(req.Username, "admin", []string{"read", "write"})
			if err != nil {
				s.writeError(w, r, http.StatusInternalServerError, "token generation failed")
				return
			}
			s.writeJSON(w, r, http.StatusOK, map[string]string{
				"token": token,
			})
			return
		}
	}

	s.writeError(w, r, http.StatusUnauthorized, "invalid credentials")
}
