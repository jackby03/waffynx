package api

import (
	"encoding/json"
	"net/http"

	"github.com/jackby03/waffynx/internal/logging"
)

// Learning endpoints proxy the behavioural learning engine, which lives in the
// data plane. The API does not keep a copy: suggestions are derived from traffic
// the sidecar inspected, and inventing them here would diverge from enforcement.
func (s *Server) handleLearningSuggestions(w http.ResponseWriter, r *http.Request) {
	client := s.sidecar()
	if client == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "sidecar socket is not configured")
		return
	}

	suggestions, err := client.LearningSuggestions(r.Context())
	if err != nil {
		logging.Warn().Err(err).Msg("reading learning suggestions from sidecar")
		s.writeProxyError(w, r, err)
		return
	}

	s.writeJSON(w, r, http.StatusOK, map[string]json.RawMessage{"suggestions": suggestions})
}

func (s *Server) handleLearningStats(w http.ResponseWriter, r *http.Request) {
	client := s.sidecar()
	if client == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "sidecar socket is not configured")
		return
	}

	stats, err := client.LearningStats(r.Context())
	if err != nil {
		logging.Warn().Err(err).Msg("reading learning stats from sidecar")
		s.writeProxyError(w, r, err)
		return
	}

	// Passthrough: the dashboard renders whatever the learning engine reports,
	// and re-encoding would silently drop fields the API does not know yet.
	s.writeJSON(w, r, http.StatusOK, stats)
}
