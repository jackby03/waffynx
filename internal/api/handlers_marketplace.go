package api

import (
	"net/http"
	"time"

	"github.com/jackby03/waffynx/internal/marketplace"
)

func (s *Server) seedMarketplace() {
	now := time.Now()
	pkgs := []*marketplace.Package{
		{
			ID:          "1",
			Name:        "rate-limit",
			Version:     "1.0.0",
			Description: "Token bucket rate limiting per IP or session with optional Redis backend",
			Author:      "Waffynx Team",
			License:     "MIT",
			Category:    "security",
			Tags:        []string{"rate-limit", "ddos", "redis"},
			Status:      marketplace.StatusPublished,
			PublishedAt: now,
			UpdatedAt:   now,
		},
		{
			ID:          "2",
			Name:        "geo-block",
			Version:     "1.0.0",
			Description: "Block or allow requests based on geographic location using MaxMind GeoLite2",
			Author:      "Waffynx Team",
			License:     "MIT",
			Category:    "security",
			Tags:        []string{"geo-block", "geolocation", "maxmind"},
			Status:      marketplace.StatusPublished,
			PublishedAt: now,
			UpdatedAt:   now,
		},
		{
			ID:          "3",
			Name:        "request-validation",
			Version:     "1.0.0",
			Description: "Validate request headers, query parameters, and JSON body schemas",
			Author:      "Waffynx Team",
			License:     "MIT",
			Category:    "validation",
			Tags:        []string{"validation", "schema", "headers"},
			Status:      marketplace.StatusPublished,
			PublishedAt: now,
			UpdatedAt:   now,
		},
	}
	for _, pkg := range pkgs {
		s.store.AddPackage(pkg)
	}
}

func (s *Server) handleMarketplaceList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := marketplace.Filter{
		Category: q.Get("category"),
		Query:    q.Get("q"),
		Status:   marketplace.PackageStatus(q.Get("status")),
	}
	pkgs, err := s.store.List(filter)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	if pkgs == nil {
		pkgs = []*marketplace.Package{}
	}
	s.writeJSON(w, r, http.StatusOK, pkgs)
}

func (s *Server) handleMarketplaceGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version := r.URL.Query().Get("version")
	if version == "" {
		version = "1.0.0"
	}
	pkg, err := s.store.Get(name, version)
	if err != nil {
		s.writeError(w, r, http.StatusNotFound, err.Error())
		return
	}
	s.writeJSON(w, r, http.StatusOK, pkg)
}

func (s *Server) handleMarketplaceInstall(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version := r.URL.Query().Get("version")
	if version == "" {
		version = "1.0.0"
	}
	if err := s.store.Install(name, version); err != nil {
		s.writeError(w, r, http.StatusNotFound, err.Error())
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"status":  "installed",
		"name":    name,
		"version": version,
	})
}

func (s *Server) handleMarketplaceUninstall(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.Uninstall(name); err != nil {
		s.writeError(w, r, http.StatusNotFound, err.Error())
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "uninstalled",
		"name":   name,
	})
}

func (s *Server) handleMarketplaceCategories(w http.ResponseWriter, r *http.Request) {
	cats, err := s.store.GetCategories()
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	if cats == nil {
		cats = []string{}
	}
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"categories": cats,
	})
}
