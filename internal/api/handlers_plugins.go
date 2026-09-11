package api

import (
	"net/http"
	"runtime"

	"github.com/jackby03/waffynx/internal/plugin"
)

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfig()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"go": map[string]interface{}{
			"goroutines":  runtime.NumGoroutine(),
			"heap_alloc":  mem.HeapAlloc,
			"heap_inuse":  mem.HeapInuse,
			"stack_inuse": mem.StackInuse,
			"gc_pause_ns": mem.PauseNs[(mem.NumGC+255)%256],
			"num_gc":      mem.NumGC,
		},
		"engine": map[string]interface{}{
			"appsec_enabled": cfg.AppSec.Enabled,
			"engine":         cfg.AppSec.Engine,
			"plugins_count":  len(plugin.GetRegistry().List()),
		},
	})
}

func (s *Server) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	plugins := plugin.GetRegistry().List()
	if plugins == nil {
		plugins = []*plugin.Metadata{}
	}
	s.writeJSON(w, r, http.StatusOK, plugins)
}

func (s *Server) handleGetPlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	meta, err := plugin.GetRegistry().Get(name)
	if err != nil {
		s.writeError(w, r, http.StatusNotFound, "plugin not found: "+name)
		return
	}

	s.writeJSON(w, r, http.StatusOK, meta)
}
