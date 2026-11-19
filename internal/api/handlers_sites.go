package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/sites"
	"github.com/jackby03/waffynx/internal/storage"
)

var (
	errSiteExists   = errors.New("site already exists")
	errSiteNotFound = errors.New("site not found")
)

// mergeSitesIntoConfig rewrites the `sites:` key of the config document, leaving
// every other key untouched, and validates the result through the same parser the
// loader uses. Unknown keys survive, which matters because the config is a file
// operators also edit by hand.
func mergeSitesIntoConfig(raw []byte, list []sites.Site) ([]byte, *config.Config, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("reading current config: %w", err)
	}
	if doc == nil {
		doc = map[string]interface{}{}
	}

	if len(list) == 0 {
		delete(doc, "sites")
	} else {
		doc["sites"] = list
	}

	merged, err := yaml.Marshal(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding config: %w", err)
	}

	parsed, err := config.Parse(merged)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return merged, parsed, nil
}

// writeFileAtomic replaces path with data via a temp file in the same directory.
// The config carries the JWT secret, so it is 0600 from creation, never widened.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".waffynx-config-*")
	if err != nil {
		return fmt.Errorf("creating temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp config: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setting config mode: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replacing config: %w", err)
	}
	tmpName = ""
	return nil
}

// applySites renders the topology and makes it live. Nothing here touches disk.
func (s *Server) applySites(ctx context.Context, list []sites.Site) error {
	if s.siteApplier == nil {
		return errors.New("site management is not configured")
	}
	cfg := s.readConfig()
	if cfg == nil {
		return errors.New("configuration is not loaded")
	}

	fragments, err := sites.Render(list, siteRenderOptions(cfg))
	if err != nil {
		return err
	}
	_, err = s.siteApplier.Apply(ctx, fragments)
	return err
}

// commitSites applies a new topology to the proxy and only then persists it.
//
// Ordering is the contract: a topology the proxy refuses must never reach disk, so
// a restart cannot resurrect it. If the write fails after a successful apply, the
// previous topology is re-applied so runtime and disk agree.
func (s *Server) commitSites(ctx context.Context, list []sites.Site) error {
	previous := s.readConfig()
	if previous == nil {
		return errors.New("configuration is not loaded")
	}

	raw, err := os.ReadFile(s.configPath)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	merged, parsed, err := mergeSitesIntoConfig(raw, list)
	if err != nil {
		return err
	}

	if err := s.applySites(ctx, parsed.Sites); err != nil {
		return err
	}

	if err := writeFileAtomic(s.configPath, merged); err != nil {
		if rollbackErr := s.applySites(ctx, previous.Sites); rollbackErr != nil {
			logging.Error().Err(rollbackErr).Msg("rolling back applied sites after a config write failure")
		}
		return err
	}

	s.configMu.Lock()
	s.cfg = parsed
	s.configMu.Unlock()
	return nil
}

// siteList returns the configured sites ordered by host, so API listings are stable.
func (s *Server) siteList() []sites.Site {
	cfg := s.readConfig()
	if cfg == nil {
		return nil
	}
	return sites.SortByHost(cfg.Sites)
}

func (s *Server) siteGet(host string) (sites.Site, bool) {
	want := sites.NormalizeHost(host)
	for _, site := range s.siteList() {
		if sites.NormalizeHost(site.Host) == want {
			return site, true
		}
	}
	return sites.Site{}, false
}

// siteUpsert creates or replaces a site. replace=false turns an existing host into
// a conflict instead of an accidental overwrite.
func (s *Server) siteUpsert(ctx context.Context, site sites.Site, replace bool) error {
	if err := site.Validate(); err != nil {
		return err
	}

	current := s.siteList()
	want := sites.NormalizeHost(site.Host)

	next := make([]sites.Site, 0, len(current)+1)
	found := false
	for _, existing := range current {
		if sites.NormalizeHost(existing.Host) == want {
			found = true
			next = append(next, site)
			continue
		}
		next = append(next, existing)
	}
	if found && !replace {
		return errSiteExists
	}
	if !found {
		next = append(next, site)
	}

	return s.commitSites(ctx, next)
}

func (s *Server) siteDelete(ctx context.Context, host string) error {
	current := s.siteList()
	want := sites.NormalizeHost(host)

	next := make([]sites.Site, 0, len(current))
	found := false
	for _, existing := range current {
		if sites.NormalizeHost(existing.Host) == want {
			found = true
			continue
		}
		next = append(next, existing)
	}
	if !found {
		return errSiteNotFound
	}
	return s.commitSites(ctx, next)
}

// --- HTTP handlers ---

func (s *Server) handleSiteList(w http.ResponseWriter, r *http.Request) {
	if s.db != nil {
		list, err := s.db.ListSites(r.Context())
		if err != nil {
			s.writeError(w, r, http.StatusInternalServerError, "could not list sites: "+err.Error())
			return
		}
		s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"sites": list})
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"sites": s.siteList()})
}

func (s *Server) handleSiteGet(w http.ResponseWriter, r *http.Request) {
	if s.db != nil {
		site, err := s.db.GetSite(r.Context(), r.PathValue("host"))
		if errors.Is(err, storage.ErrNotFound) {
			s.writeError(w, r, http.StatusNotFound, "site not found")
			return
		}
		if err != nil {
			s.writeError(w, r, http.StatusInternalServerError, "could not fetch site: "+err.Error())
			return
		}
		s.writeJSON(w, r, http.StatusOK, site)
		return
	}
	site, ok := s.siteGet(r.PathValue("host"))
	if !ok {
		s.writeError(w, r, http.StatusNotFound, "site not found")
		return
	}
	s.writeJSON(w, r, http.StatusOK, site)
}

func (s *Server) handleSiteCreate(w http.ResponseWriter, r *http.Request) {
	var site sites.Site
	if err := json.NewDecoder(r.Body).Decode(&site); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}

	if s.db != nil {
		if err := site.Validate(); err != nil {
			s.writeSiteError(w, r, err, "create")
			return
		}
		if err := s.db.UpsertSite(r.Context(), site, false); err != nil {
			if errors.Is(err, storage.ErrConflict) {
				s.writeSiteError(w, r, errSiteExists, "create")
				return
			}
			s.writeSiteError(w, r, err, "create")
			return
		}
		if err := s.syncControlPlane(r.Context(), "sites", UserFromContext(r.Context())); err != nil {
			logging.Warn().Err(err).Str("host", site.Host).Msg("control plane sync after site create")
		}
		s.recordSiteAudit(r, "site_create", site.Host)
		created, _ := s.db.GetSite(r.Context(), site.Host)
		s.writeJSON(w, r, http.StatusCreated, created)
		return
	}

	if err := s.siteUpsert(r.Context(), site, false); err != nil {
		s.writeSiteError(w, r, err, "create")
		return
	}

	s.recordSiteAudit(r, "site_create", site.Host)
	created, _ := s.siteGet(site.Host)
	s.writeJSON(w, r, http.StatusCreated, created)
}

func (s *Server) handleSiteUpdate(w http.ResponseWriter, r *http.Request) {
	if s.db != nil {
		existing, err := s.db.GetSite(r.Context(), r.PathValue("host"))
		if errors.Is(err, storage.ErrNotFound) {
			s.writeError(w, r, http.StatusNotFound, "site not found")
			return
		}
		if err != nil {
			s.writeError(w, r, http.StatusInternalServerError, "could not load site")
			return
		}
		var site sites.Site
		if err := json.NewDecoder(r.Body).Decode(&site); err != nil {
			s.writeError(w, r, http.StatusBadRequest, "invalid request body")
			return
		}
		if site.Host == "" {
			site.Host = existing.Host
		}
		if sites.NormalizeHost(site.Host) != sites.NormalizeHost(existing.Host) {
			s.writeError(w, r, http.StatusBadRequest,
				"host cannot be changed; delete the site and create a new one")
			return
		}
		if err := site.Validate(); err != nil {
			s.writeSiteError(w, r, err, "update")
			return
		}
		if err := s.db.UpsertSite(r.Context(), site, true); err != nil {
			s.writeSiteError(w, r, err, "update")
			return
		}
		if err := s.syncControlPlane(r.Context(), "sites", UserFromContext(r.Context())); err != nil {
			logging.Warn().Err(err).Str("host", site.Host).Msg("control plane sync after site update")
		}
		s.recordSiteAudit(r, "site_update", site.Host)
		updated, _ := s.db.GetSite(r.Context(), site.Host)
		s.writeJSON(w, r, http.StatusOK, updated)
		return
	}

	existing, ok := s.siteGet(r.PathValue("host"))
	if !ok {
		s.writeError(w, r, http.StatusNotFound, "site not found")
		return
	}

	var site sites.Site
	if err := json.NewDecoder(r.Body).Decode(&site); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if site.Host == "" {
		site.Host = existing.Host
	}
	// The path identifies the site; a body that renames it would make the URL lie.
	if sites.NormalizeHost(site.Host) != sites.NormalizeHost(existing.Host) {
		s.writeError(w, r, http.StatusBadRequest,
			"host cannot be changed; delete the site and create a new one")
		return
	}

	if err := s.siteUpsert(r.Context(), site, true); err != nil {
		s.writeSiteError(w, r, err, "update")
		return
	}

	s.recordSiteAudit(r, "site_update", site.Host)
	updated, _ := s.siteGet(site.Host)
	s.writeJSON(w, r, http.StatusOK, updated)
}

func (s *Server) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")

	if s.db != nil {
		if err := s.db.DeleteSite(r.Context(), host); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				s.writeSiteError(w, r, errSiteNotFound, "delete")
				return
			}
			s.writeSiteError(w, r, err, "delete")
			return
		}
		if err := s.syncControlPlane(r.Context(), "sites", UserFromContext(r.Context())); err != nil {
			logging.Warn().Err(err).Str("host", host).Msg("control plane sync after site delete")
		}
		s.recordSiteAudit(r, "site_delete", host)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := s.siteDelete(r.Context(), host); err != nil {
		s.writeSiteError(w, r, err, "delete")
		return
	}

	s.recordSiteAudit(r, "site_delete", host)
	w.WriteHeader(http.StatusNoContent)
}

// writeSiteError maps store errors onto status codes. A validation failure is the
// caller's fault; a failed apply is ours, and the reason must reach the caller.
func (s *Server) writeSiteError(w http.ResponseWriter, r *http.Request, err error, action string) {
	var validation *sites.ValidationError
	switch {
	case errors.As(err, &validation):
		s.writeError(w, r, http.StatusBadRequest, "invalid site: "+validation.Error())
	case errors.Is(err, errSiteExists):
		s.writeError(w, r, http.StatusConflict, "site already exists")
	case errors.Is(err, errSiteNotFound):
		s.writeError(w, r, http.StatusNotFound, "site not found")
	default:
		logging.Error().Err(err).Str("action", action).Msg("site change rejected")
		s.writeError(w, r, http.StatusInternalServerError, "could not "+action+" site: "+err.Error())
	}
}

func (s *Server) recordSiteAudit(r *http.Request, action, host string) {
	if s.audit == nil {
		return
	}
	s.audit.Record(audit.Event{
		Actor:    UserFromContext(r.Context()),
		Action:   action,
		Resource: host,
		Result:   "success",
	})
}

// siteRenderOptions derives renderer settings from the loaded configuration.
func siteRenderOptions(cfg *config.Config) sites.RenderOptions {
	opts := sites.RenderOptions{
		SocketPath:  cfg.Sidecar.SocketPath,
		HTTPListen:  cfg.Nginx.HTTPListen,
		TLSListen:   cfg.Nginx.TLSListen,
		MaxBodySize: "64k",
		TimeoutMs:   cfg.Sidecar.TimeoutMs,
	}
	if opts.HTTPListen == "" {
		opts.HTTPListen = ":8080"
	}
	if opts.TLSListen == "" {
		opts.TLSListen = ":8443"
	}
	// The config may carry a bare port; the renderer writes a listen address.
	if !strings.Contains(opts.HTTPListen, ":") {
		opts.HTTPListen = ":" + opts.HTTPListen
	}
	if !strings.Contains(opts.TLSListen, ":") {
		opts.TLSListen = ":" + opts.TLSListen
	}
	return opts
}
