package api

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/jackby03/waffynx/internal/auth"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/version"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfig()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"version":    version.Version,
		"build_time": version.BuildTime,
		"git_commit": version.GitCommit,
		"go_version": runtime.Version(),
		"goroutines": runtime.NumGoroutine(),
		"memory": map[string]interface{}{
			"alloc_mb":       float64(mem.Alloc) / 1024 / 1024,
			"total_alloc_mb": float64(mem.TotalAlloc) / 1024 / 1024,
		},
		"config": map[string]interface{}{
			"name":           cfg.Name,
			"appsec_enabled": cfg.AppSec.Enabled,
			"engine":         cfg.AppSec.Engine,
			"plugins_count":  len(plugin.GetRegistry().List()),
		},
	})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfig()

	redacted := map[string]interface{}{
		"name":    cfg.Name,
		"version": cfg.Version,
		"listen":  cfg.Listen,
		"logging": cfg.Logging,
		"sidecar": cfg.Sidecar,
		"nginx":   cfg.Nginx,
		"appsec": map[string]interface{}{
			"enabled":       cfg.AppSec.Enabled,
			"engine":        cfg.AppSec.Engine,
			"rules_path":    cfg.AppSec.RulesPath,
			"ml_model_path": cfg.AppSec.MLModelPath,
			"learning_mode": cfg.AppSec.LearningMode,
			"timeout_ms":    cfg.AppSec.TimeoutMs,
		},
		"gateway": cfg.Gateway,
		"api": map[string]interface{}{
			"enabled": cfg.API.Enabled,
			"listen":  cfg.API.Listen,
			"auth": map[string]interface{}{
				"jwt_secret": "***",
				"token_ttl":  cfg.API.Auth.TokenTTL,
			},
		},
		"routes":  cfg.Routes,
		"plugins": cfg.Plugins,
	}

	s.writeJSON(w, r, http.StatusOK, redacted)
}

func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(updates) == 0 {
		s.writeError(w, r, http.StatusBadRequest, "empty update body")
		return
	}

	s.configMu.Lock()
	defer s.configMu.Unlock()

	yamlBytes, err := yaml.Marshal(s.cfg)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "failed to marshal current config")
		return
	}

	var current map[string]interface{}
	if err := yaml.Unmarshal(yamlBytes, &current); err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "failed to unmarshal current config")
		return
	}

	deepMerge(current, normalizeKeys(updates))

	merged, err := yaml.Marshal(current)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "failed to marshal merged config")
		return
	}

	newCfg, err := config.Parse(merged)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid config: "+err.Error())
		return
	}

	if err := os.WriteFile(s.configPath, merged, 0644); err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "failed to write config file: "+err.Error())
		return
	}

	s.cfg = newCfg
	s.authMgr = auth.NewManager(newCfg.API.Auth.JWTSecret, newCfg.API.Auth.TokenTTL)
	newOIDC := auth.NewOIDCManager()
	if len(newCfg.API.Auth.OIDC) > 0 {
		newOIDC.Configure(newCfg.API.Auth.OIDC)
	}
	s.oidcMgr = newOIDC

	logging.Info().Msg("config updated and written to disk")

	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "config updated",
	})
}

func deepMerge(target, source map[string]interface{}) {
	for key, srcVal := range source {
		if srcMap, ok := srcVal.(map[string]interface{}); ok {
			if tgtMap, ok := target[key].(map[string]interface{}); ok {
				deepMerge(tgtMap, srcMap)
				continue
			}
		}
		target[key] = srcVal
	}
}

func normalizeKeys(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		key := toSnakeCase(k)
		if sub, ok := v.(map[string]interface{}); ok {
			out[key] = normalizeKeys(sub)
		} else {
			out[key] = v
		}
	}
	return out
}

func toSnakeCase(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
