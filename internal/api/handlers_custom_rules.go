package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/storage"
)

const (
	// maxRuleBodyBytes bounds a proxied rule document. A rule is a handful of
	// short matchers; anything larger is a mistake or abuse, and the body is
	// copied into the sidecar request, so it must not be unbounded.
	maxRuleBodyBytes = 64 * 1024

	// maxRuleIDLength bounds an identifier before it reaches the sidecar's query
	// string. Rule ids are opaque but short by construction.
	maxRuleIDLength = 128
)

// validRuleID rejects ids that cannot be proxied safely: empty values cannot be
// addressed, and path separators or whitespace would corrupt the sidecar URL.
func validRuleID(id string) bool {
	if id == "" || len(id) > maxRuleIDLength {
		return false
	}
	return !strings.ContainsAny(id, "/ \t\r\n")
}

// writeProxyError maps a sidecar failure to an HTTP response.
//
// A 4xx from the sidecar means the data plane refused the payload, so it is a
// 400. Anything else is a 503: the API has no data to show and must not answer
// 200 with an empty collection, because "no rules" and "could not ask" are
// different facts (Constitution §1.1, fail closed).
func (s *Server) writeProxyError(w http.ResponseWriter, r *http.Request, err error) {
	var statusErr *sidecarResponseError
	if errors.As(err, &statusErr) && statusErr.StatusCode < 500 {
		s.writeError(w, r, http.StatusBadRequest, "sidecar rejected the request")
		return
	}
	s.writeError(w, r, http.StatusServiceUnavailable, "sidecar is unavailable")
}

// handleCustomRuleList proxies the data plane's custom rules. It is read-only:
// rules are evaluated by the sidecar on every request, so the sidecar is the
// only honest source for what is enforced.
func (s *Server) handleCustomRuleList(w http.ResponseWriter, r *http.Request) {
	if s.db != nil {
		list, err := s.db.ListCustomRules(r.Context())
		if err != nil {
			s.writeError(w, r, http.StatusInternalServerError, "could not list custom rules")
			return
		}
		s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"rules": list})
		return
	}

	client := s.sidecar()
	if client == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "sidecar socket is not configured")
		return
	}

	list, err := client.ListRules(r.Context())
	if err != nil {
		logging.Warn().Err(err).Msg("listing custom rules from sidecar")
		s.writeProxyError(w, r, err)
		return
	}

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"rules": list})
}

func (s *Server) handleCustomRuleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)
	var rule rules.CustomRule
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rule); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid rule body")
		return
	}
	// Exactly one JSON object: trailing data that is silently ignored is how a
	// malformed rule gets accepted while the operator sees a "created" response.
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		s.writeError(w, r, http.StatusBadRequest, "rule body must contain one JSON object")
		return
	}

	// An empty id is allowed here: the store/sidecar assigns one and returns it. A
	// supplied id must be safe to delete later, so it is validated now.
	if rule.ID != "" && !validRuleID(rule.ID) {
		s.writeError(w, r, http.StatusBadRequest, "invalid rule id")
		return
	}

	if s.db != nil {
		created, err := s.db.UpsertCustomRule(r.Context(), rule)
		if err != nil {
			s.writeError(w, r, http.StatusInternalServerError, "could not save custom rule")
			return
		}
		if err := s.syncControlPlane(r.Context(), "custom_rules", UserFromContext(r.Context())); err != nil {
			logging.Warn().Err(err).Msg("hot-reload sync after custom rule create")
		}
		if s.audit != nil {
			s.audit.Record(audit.Event{
				Actor:    UserFromContext(r.Context()),
				Action:   "custom_rule_create",
				Resource: created.ID,
				Result:   "success",
				Details:  created.Name,
			})
		}
		s.writeJSON(w, r, http.StatusCreated, created)
		return
	}

	client := s.sidecar()
	if client == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "sidecar socket is not configured")
		return
	}

	created, err := client.CreateRule(r.Context(), rule)
	if err != nil {
		logging.Warn().Err(err).Msg("creating custom rule via sidecar")
		s.writeProxyError(w, r, err)
		return
	}

	if s.audit != nil {
		s.audit.Record(audit.Event{
			Actor:    UserFromContext(r.Context()),
			Action:   "custom_rule_create",
			Resource: created.ID,
			Result:   "success",
			Details:  created.Name,
		})
	}

	s.writeJSON(w, r, http.StatusCreated, created)
}

func (s *Server) handleCustomRuleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validRuleID(id) {
		s.writeError(w, r, http.StatusBadRequest, "invalid rule id")
		return
	}

	if s.db != nil {
		if err := s.db.DeleteCustomRule(r.Context(), id); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				s.writeError(w, r, http.StatusNotFound, "rule not found")
				return
			}
			s.writeError(w, r, http.StatusInternalServerError, "could not delete custom rule")
			return
		}
		if err := s.syncControlPlane(r.Context(), "custom_rules", UserFromContext(r.Context())); err != nil {
			logging.Warn().Err(err).Msg("hot-reload sync after custom rule delete")
		}
		if s.audit != nil {
			s.audit.Record(audit.Event{
				Actor:    UserFromContext(r.Context()),
				Action:   "custom_rule_delete",
				Resource: id,
				Result:   "success",
				Details:  "deleted via control room",
			})
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	client := s.sidecar()
	if client == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "sidecar socket is not configured")
		return
	}

	if err := client.DeleteRule(r.Context(), id); err != nil {
		logging.Warn().Err(err).Str("rule_id", id).Msg("deleting custom rule via sidecar")
		s.writeProxyError(w, r, err)
		return
	}

	if s.audit != nil {
		s.audit.Record(audit.Event{
			Actor:    UserFromContext(r.Context()),
			Action:   "custom_rule_delete",
			Resource: id,
			Result:   "success",
			Details:  "deleted via control room",
		})
	}

	w.WriteHeader(http.StatusNoContent)
}
