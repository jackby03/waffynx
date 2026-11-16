package api

import (
	"mime"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/jackby03/waffynx/internal/version"
	"github.com/jackby03/waffynx/ui"
)

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		s.handleUIAsset(w, r)
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"service":   "waf-api",
		"version":   version.Version,
		"endpoints": []string{"/health", "/metrics", "/api/v1/status", "/api/v1/config", "/api/v1/plugins", "/api/v1/audit", "/api/v1/events", "/debug/pprof/"},
	})
}

func (s *Server) handleUIAsset(w http.ResponseWriter, r *http.Request) {
	// path.Clean("/" + p) always returns an absolute path with no ".." elements,
	// so trimming the leading separator yields a path that cannot escape the
	// asset root once joined. This replaces a substring check on ".." with a
	// structural guarantee (gosec G703).
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}

	var data []byte
	var err error

	if s.uiDir != "" {
		filePath := path.Join(s.uiDir, name)
		//nolint:gosec // G703: name is path.Clean'd from an absolute root, so it
		// carries no ".." elements and path.Join cannot escape s.uiDir.
		data, err = os.ReadFile(filePath)
		if err != nil {
			indexPath := path.Join(s.uiDir, "index.html")
			data, err = os.ReadFile(indexPath)
			if err != nil {
				http.Error(w, "dashboard assets unavailable", http.StatusNotFound)
				return
			}
			name = "index.html"
		}
	} else {
		data, err = ui.DistFS.ReadFile("dist/" + name)
		if err != nil {
			data, err = ui.DistFS.ReadFile("dist/index.html")
			if err != nil {
				http.Error(w, "dashboard assets unavailable", http.StatusNotFound)
				return
			}
			name = "index.html"
		}
	}

	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}

	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: data is read from the embedded Vite build or uiDir,
	// never from the request. Only the extension-derived Content-Type is
	// request-influenced, and the served file always matches that extension.
	_, _ = w.Write(data)
}
