package api

import (
	"net/http"

	"github.com/jackby03/waffynx/internal/catalog"
	"github.com/jackby03/waffynx/internal/logging"
)

// ruleView is the wire shape the dashboard renders. It is deliberately a subset:
// the request path and the matcher internals are not the operator's business, but
// id, name, severity, action and tags explain every block.
type ruleView struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Action   string   `json:"action"`
	Tags     []string `json:"tags"`
	Fields   []string `json:"fields"`
}

// loadCatalog returns the embedded ruleset, or nil when it is invalid. Nil turns
// into a 503 from the handler rather than an empty list: "no rules" and "rules
// could not be loaded" must never look the same.
func loadCatalog() *catalog.Catalog {
	c, err := catalog.Embedded()
	if err != nil {
		logging.Error().Err(err).Msg("managed ruleset is invalid; /api/v1/rules will report it")
		return nil
	}
	return c
}

func (s *Server) handleRuleList(w http.ResponseWriter, r *http.Request) {
	if s.catalog == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "managed ruleset is unavailable")
		return
	}

	out := make([]ruleView, 0, s.catalog.Count())
	for _, rule := range s.catalog.Rules {
		fields := make([]string, 0, len(rule.Fields))
		if len(rule.Fields) == 0 {
			fields = []string{"path", "query", "body"}
		} else {
			for _, f := range rule.Fields {
				fields = append(fields, string(f))
			}
		}
		out = append(out, ruleView{
			ID:       rule.ID,
			Name:     rule.Name,
			Severity: string(rule.Severity),
			Action:   string(rule.Action),
			Tags:     rule.Tags,
			Fields:   fields,
		})
	}

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{"rules": out})
}

func (s *Server) handleAPINotFound(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, r, http.StatusNotFound, "unknown API endpoint")
}
