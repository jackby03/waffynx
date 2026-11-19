package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jackby03/waffynx/internal/analytics"
	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/hotreload"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/rules"
	"github.com/jackby03/waffynx/internal/storage"
	"github.com/jackby03/waffynx/internal/telemetry"
	"github.com/jackby03/waffynx/internal/xds"
)

// syncControlPlane computes the next policy revision, builds an immutable
// PolicySnapshot from the persistent store, publishes it over Redis Pub/Sub to
// all waf-engine replicas, and updates the Envoy xDS snapshot cache.
func (s *Server) syncControlPlane(ctx context.Context, kind, actor string) error {
	if s.db == nil {
		return nil
	}
	rev, err := s.db.NextRevision(ctx, kind, actor)
	if err != nil {
		return fmt.Errorf("advancing config revision: %w", err)
	}
	snap, err := hotreload.BuildSnapshot(ctx, s.db, rev)
	if err != nil {
		return fmt.Errorf("building policy snapshot: %w", err)
	}

	var errs []string
	if s.reloadBus != nil {
		if err := s.reloadBus.PublishSnapshot(ctx, snap); err != nil {
			errs = append(errs, "hot-reload publish: "+err.Error())
		}
	}
	if s.xdsSrv != nil {
		if _, err := s.xdsSrv.UpdateSites(ctx, snap.Sites); err != nil {
			errs = append(errs, "xds update: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// handleReadyz verifies Control Plane readiness (database connectivity when enabled).
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.db != nil {
		if err := s.db.Ping(r.Context()); err != nil {
			s.writeError(w, r, http.StatusServiceUnavailable, "database unavailable")
			return
		}
	}
	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "ready",
		"plane":  "control-plane",
	})
}

// --- False-Positive Exclusions ---

func (s *Server) handleExclusionList(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"exclusions": []rules.Exclusion{}})
		return
	}
	list, err := s.db.ListExclusions(r.Context())
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "could not list exclusions")
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"exclusions": list})
}

func (s *Server) handleExclusionCreate(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "persistent storage is not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)
	var ex rules.Exclusion
	if err := json.NewDecoder(r.Body).Decode(&ex); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid exclusion body")
		return
	}
	ex.RuleID = strings.TrimSpace(ex.RuleID)
	if ex.RuleID == "" {
		s.writeError(w, r, http.StatusBadRequest, "rule_id is required (or '*' for all rules)")
		return
	}
	if ex.PathExact == "" && ex.PathPrefix == "" && ex.Host == "" && ex.Param == "" {
		s.writeError(w, r, http.StatusBadRequest, "at least one scope filter (host, path_exact, path_prefix, or param) is required")
		return
	}
	if ex.Name == "" {
		ex.Name = "Exclusion for " + ex.RuleID
	}
	ex.Enabled = true

	created, err := s.db.CreateExclusion(r.Context(), ex)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "could not persist exclusion")
		return
	}
	if err := s.syncControlPlane(r.Context(), "exclusions", UserFromContext(r.Context())); err != nil {
		logging.Warn().Err(err).Msg("hot-reload sync after exclusion create")
	}
	if s.audit != nil {
		s.audit.Record(audit.Event{
			Actor:    UserFromContext(r.Context()),
			Action:   "exclusion_create",
			Resource: created.ID,
			Result:   "success",
			Details:  fmt.Sprintf("rule=%s path=%s%s", created.RuleID, created.PathExact, created.PathPrefix),
		})
	}
	s.writeJSON(w, r, http.StatusCreated, created)
}

func (s *Server) handleExclusionDelete(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "persistent storage is not configured")
		return
	}
	id := r.PathValue("id")
	if !validRuleID(id) {
		s.writeError(w, r, http.StatusBadRequest, "invalid exclusion id")
		return
	}
	if err := s.db.DeleteExclusion(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.writeError(w, r, http.StatusNotFound, "exclusion not found")
			return
		}
		s.writeError(w, r, http.StatusInternalServerError, "could not delete exclusion")
		return
	}
	if err := s.syncControlPlane(r.Context(), "exclusions", UserFromContext(r.Context())); err != nil {
		logging.Warn().Err(err).Msg("hot-reload sync after exclusion delete")
	}
	if s.audit != nil {
		s.audit.Record(audit.Event{
			Actor:    UserFromContext(r.Context()),
			Action:   "exclusion_delete",
			Resource: id,
			Result:   "success",
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Zero-Trust Continuous Authorization Policies (ext_authz) ---

func (s *Server) handleZTPolicyList(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"policies": []storage.ZeroTrustPolicy{}})
		return
	}
	list, err := s.db.ListZTPolicies(r.Context())
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "could not list zero-trust policies")
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"policies": list})
}

func (s *Server) handleZTPolicyCreate(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "persistent storage is not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)
	var p storage.ZeroTrustPolicy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid zero-trust policy body")
		return
	}
	if strings.TrimSpace(p.Name) == "" {
		s.writeError(w, r, http.StatusBadRequest, "policy name is required")
		return
	}
	if p.PathPrefix == "" {
		p.PathPrefix = "/"
	}
	if p.Priority <= 0 {
		p.Priority = 100
	}

	created, err := s.db.UpsertZTPolicy(r.Context(), p)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "could not save zero-trust policy")
		return
	}
	if err := s.syncControlPlane(r.Context(), "zt_policies", UserFromContext(r.Context())); err != nil {
		logging.Warn().Err(err).Msg("hot-reload sync after zt policy create")
	}
	if s.audit != nil {
		s.audit.Record(audit.Event{
			Actor:    UserFromContext(r.Context()),
			Action:   "zt_policy_create",
			Resource: created.ID,
			Result:   "success",
			Details:  created.Name,
		})
	}
	s.writeJSON(w, r, http.StatusCreated, created)
}

func (s *Server) handleZTPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "persistent storage is not configured")
		return
	}
	id := r.PathValue("id")
	if !validRuleID(id) {
		s.writeError(w, r, http.StatusBadRequest, "invalid policy id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)
	var p storage.ZeroTrustPolicy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid zero-trust policy body")
		return
	}
	p.ID = id
	if strings.TrimSpace(p.Name) == "" {
		s.writeError(w, r, http.StatusBadRequest, "policy name is required")
		return
	}
	updated, err := s.db.UpsertZTPolicy(r.Context(), p)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "could not update zero-trust policy")
		return
	}
	if err := s.syncControlPlane(r.Context(), "zt_policies", UserFromContext(r.Context())); err != nil {
		logging.Warn().Err(err).Msg("hot-reload sync after zt policy update")
	}
	if s.audit != nil {
		s.audit.Record(audit.Event{
			Actor:    UserFromContext(r.Context()),
			Action:   "zt_policy_update",
			Resource: updated.ID,
			Result:   "success",
			Details:  updated.Name,
		})
	}
	s.writeJSON(w, r, http.StatusOK, updated)
}

func (s *Server) handleZTPolicyDelete(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "persistent storage is not configured")
		return
	}
	id := r.PathValue("id")
	if !validRuleID(id) {
		s.writeError(w, r, http.StatusBadRequest, "invalid policy id")
		return
	}
	if err := s.db.DeleteZTPolicy(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.writeError(w, r, http.StatusNotFound, "policy not found")
			return
		}
		s.writeError(w, r, http.StatusInternalServerError, "could not delete zero-trust policy")
		return
	}
	if err := s.syncControlPlane(r.Context(), "zt_policies", UserFromContext(r.Context())); err != nil {
		logging.Warn().Err(err).Msg("hot-reload sync after zt policy delete")
	}
	if s.audit != nil {
		s.audit.Record(audit.Event{
			Actor:    UserFromContext(r.Context()),
			Action:   "zt_policy_delete",
			Resource: id,
			Result:   "success",
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- ClickHouse Observability Analytics ---

func (s *Server) handleAnalyticsEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	sinceHours, _ := strconv.Atoi(q.Get("since_hours"))

	if s.analyticsReader != nil {
		events, err := s.analyticsReader.QueryEvents(r.Context(), analytics.EventFilter{
			Query:       q.Get("q"),
			Action:      q.Get("action"),
			Host:        q.Get("host"),
			RemoteIP:    q.Get("remote_ip"),
			RuleID:      q.Get("rule_id"),
			CountryCode: q.Get("country"),
			SinceHours:  sinceHours,
			Limit:       limit,
			Offset:      offset,
		})
		if err != nil {
			logging.Warn().Err(err).Msg("clickhouse analytics events query failed")
			s.writeError(w, r, http.StatusServiceUnavailable, "analytics store unavailable")
			return
		}
		s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
			"source": "clickhouse",
			"events": events,
		})
		return
	}

	// Standalone fallback: project the live in-process broker ring.
	if limit <= 0 || limit > eventHistoryMaxLimit {
		limit = eventHistoryDefaultLimit
	}
	ring := s.broker.History(limit)
	projected := make([]telemetry.SecurityEvent, 0, len(ring))
	for _, ev := range ring {
		projected = append(projected, telemetry.SecurityEvent{
			Timestamp:  ev.Timestamp,
			Plane:      "data-plane",
			Action:     telemetry.ActionBlock,
			Method:     ev.Method,
			Path:       ev.Path,
			RemoteIP:   ev.RemoteIP,
			RuleID:     ev.RuleID,
			Reason:     ev.Reason,
			StatusCode: http.StatusForbidden,
		})
	}
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"source": "broker",
		"events": projected,
	})
}

func (s *Server) handleAnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	windowHours, _ := strconv.Atoi(r.URL.Query().Get("window_hours"))
	if windowHours <= 0 {
		windowHours = 24
	}
	if s.analyticsReader != nil {
		summary, err := s.analyticsReader.QuerySummary(r.Context(), windowHours)
		if err != nil {
			logging.Warn().Err(err).Msg("clickhouse summary query failed")
			s.writeError(w, r, http.StatusServiceUnavailable, "analytics store unavailable")
			return
		}
		s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
			"source":  "clickhouse",
			"summary": summary,
		})
		return
	}

	ring := s.broker.History(eventHistoryMaxLimit)
	ips := make(map[string]struct{})
	for _, ev := range ring {
		if ev.RemoteIP != "" {
			ips[ev.RemoteIP] = struct{}{}
		}
	}
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"source": "broker",
		"summary": analytics.Summary{
			WindowHours:  windowHours,
			TotalEvents:  uint64(len(ring)),
			Blocked:      uint64(len(ring)),
			UniqueIPs:    uint64(len(ips)),
			TopRules:     []analytics.TopCount{},
			TopIPs:       []analytics.TopCount{},
			TopCountries: []analytics.TopCount{},
			Timeline:     []analytics.TimelinePoint{},
		},
	})
}

// --- Multi-Plane Cluster Topology ---

func (s *Server) handleClusterTopology(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	mode := "standalone"
	if s.db != nil || s.xdsSrv != nil {
		mode = "distributed"
	}

	var revision int64
	pgHealthy := false
	if s.db != nil {
		if err := s.db.Ping(ctx); err == nil {
			pgHealthy = true
			revision, _ = s.db.LatestRevision(ctx)
		}
	}

	redisHealthy := false
	if s.reloadBus != nil {
		if _, err := s.reloadBus.LatestSnapshot(ctx); err == nil {
			redisHealthy = true
		}
	}

	chHealthy := false
	if s.analyticsReader != nil {
		if err := s.analyticsReader.Ping(ctx); err == nil {
			chHealthy = true
		}
	}

	xdsNodes := []xds.ConnectedNode{}
	var xdsVersion int64
	if s.xdsSrv != nil {
		xdsNodes = s.xdsSrv.ConnectedNodes()
		xdsVersion = s.xdsSrv.CurrentVersion()
	}

	cfg := s.readConfig()
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"mode":            mode,
		"policy_revision": revision,
		"mtls_enabled":    cfg != nil && cfg.Distributed.MTLS.Enabled,
		"planes": map[string]interface{}{
			"data_plane": map[string]interface{}{
				"pep":             map[bool]string{true: "envoy-xds", false: "nginx-sidecar"}[s.xdsSrv != nil],
				"xds_enabled":     s.xdsSrv != nil,
				"xds_version":     xdsVersion,
				"connected_nodes": xdsNodes,
				"redis_enabled":   s.reloadBus != nil,
				"redis_healthy":   redisHealthy,
			},
			"control_plane": map[string]interface{}{
				"postgres_enabled": s.db != nil,
				"postgres_healthy": pgHealthy,
				"policy_revision":  revision,
			},
			"observability_plane": map[string]interface{}{
				"clickhouse_enabled": s.analyticsReader != nil,
				"clickhouse_healthy": chHealthy,
				"nats_enabled":       cfg != nil && cfg.Distributed.NATS.Enabled,
			},
		},
	})
}

// --- RBAC Users (PostgreSQL) ---

func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"users": []storage.User{}})
		return
	}
	users, err := s.db.ListUsers(r.Context())
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "could not list users")
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"users": users})
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "persistent storage is not configured")
		return
	}
	var req struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		Role     string   `json:"role"`
		Scopes   []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Password) < 12 {
		s.writeError(w, r, http.StatusBadRequest, "username and password (>= 12 chars) are required")
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	switch req.Role {
	case "admin", "operator", "viewer":
	default:
		s.writeError(w, r, http.StatusBadRequest, "role must be admin, operator, or viewer")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "could not hash password")
		return
	}
	if len(req.Scopes) == 0 {
		switch req.Role {
		case "admin":
			req.Scopes = []string{"read", "write", "admin"}
		case "operator":
			req.Scopes = []string{"read", "write"}
		default:
			req.Scopes = []string{"read"}
		}
	}
	user := storage.User{
		Username:     req.Username,
		PasswordHash: string(hash),
		Role:         req.Role,
		Scopes:       req.Scopes,
		Enabled:      true,
	}
	if err := s.db.UpsertUser(r.Context(), user); err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "could not save user")
		return
	}
	if s.audit != nil {
		s.audit.Record(audit.Event{
			Actor:    UserFromContext(r.Context()),
			Action:   "user_upsert",
			Resource: user.Username,
			Result:   "success",
			Details:  "role=" + user.Role,
		})
	}
	s.writeJSON(w, r, http.StatusCreated, user)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "persistent storage is not configured")
		return
	}
	username := strings.TrimSpace(r.PathValue("username"))
	if username == "" {
		s.writeError(w, r, http.StatusBadRequest, "username is required")
		return
	}
	if username == UserFromContext(r.Context()) {
		s.writeError(w, r, http.StatusBadRequest, "cannot delete currently authenticated user")
		return
	}
	if err := s.db.DeleteUser(r.Context(), username); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.writeError(w, r, http.StatusNotFound, "user not found")
			return
		}
		s.writeError(w, r, http.StatusInternalServerError, "could not delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
