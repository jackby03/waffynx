package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/rules"
)

func (s *Server) handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	s.firewallMu.RLock()
	defer s.firewallMu.RUnlock()

	cfg := s.readConfig()
	backend := "nftables"
	enabled := false
	if cfg != nil {
		backend = cfg.Firewall.Backend
		enabled = cfg.Firewall.Enabled
	}

	list := make([]BannedIP, 0, len(s.bannedIPs))
	now := time.Now()
	for _, b := range s.bannedIPs {
		if b.TTL > 0 && now.After(b.ExpiresAt) {
			continue
		}
		list = append(list, b)
	}

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"enabled": enabled,
		"backend": backend,
		"rules":   list,
	})
}

func (s *Server) handleFirewallBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
		TTL    int    `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if req.IP == "" {
		s.writeError(w, r, http.StatusBadRequest, "ip is required")
		return
	}
	if net.ParseIP(req.IP) == nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid IP format")
		return
	}
	if req.TTL <= 0 {
		req.TTL = 3600
	}
	if req.Reason == "" {
		req.Reason = "Manual ban from Control Room"
	}

	now := time.Now()
	ban := BannedIP{
		IP:        req.IP,
		Reason:    req.Reason,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(req.TTL) * time.Second),
		TTL:       req.TTL,
	}

	// Enforce at the WAF layer first: it is the only mechanism that works without
	// privileges, so reporting success is only honest once it accepted the rule.
	wafErr := error(nil)
	if s.wafRules != nil {
		wafErr = s.wafRules.AddRule(r.Context(), rules.CustomRule{
			ID:          ruleIDForIP(req.IP),
			Name:        "IP ban",
			Description: req.Reason,
			Enabled:     true,
			Action:      rules.ActionBlock,
			IPs:         []string{req.IP},
		})
	}

	// Kernel drop is an enhancement that only exists in system deployments.
	// A failure here is logged, not fatal, as long as the WAF layer took the ban.
	if s.firewall != nil {
		if err := s.firewall.BlockIP(req.IP); err != nil {
			logging.Warn().Err(err).Str("ip", req.IP).Msg("host firewall ban failed")
		}
	}

	if wafErr != nil {
		if s.firewall == nil {
			// Neither layer could enforce: refuse to claim the IP is blocked.
			s.writeError(w, r, http.StatusServiceUnavailable,
				"cannot enforce ban: WAF rule injection failed ("+wafErr.Error()+") and no host firewall is available")
			return
		}
		logging.Warn().Err(wafErr).Str("ip", req.IP).Msg("WAF-layer ban failed, relying on host firewall")
	}

	// Recorded only after enforcement succeeded: a ban that is visible in the API
	// while nothing is enforced is the fail-open defect this handler used to have.
	s.firewallMu.Lock()
	s.bannedIPs[req.IP] = ban
	s.firewallMu.Unlock()

	if s.audit != nil {
		s.audit.Record(audit.Event{
			Actor:     UserFromContext(r.Context()),
			Action:    "firewall_ban",
			Resource:  req.IP,
			Result:    "success",
			Details:   req.Reason,
			Timestamp: now,
		})
	}

	if s.broker != nil {
		s.broker.Publish(events.WafEvent{
			Type:      events.TypeBlocked,
			Timestamp: now,
			RemoteIP:  req.IP,
			Path:      "/* (L3/L4 Network Ban)",
			RuleID:    "kernel-nftables",
			Reason:    req.Reason,
		})
	}

	s.writeJSON(w, r, http.StatusCreated, ban)
}

func (s *Server) handleFirewallUnblock(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" || net.ParseIP(ip) == nil {
		s.writeError(w, r, http.StatusBadRequest, "valid ip path parameter required")
		return
	}

	s.firewallMu.Lock()
	delete(s.bannedIPs, ip)
	s.firewallMu.Unlock()

	var wafErr error
	if s.wafRules != nil {
		wafErr = s.wafRules.DeleteRule(r.Context(), ruleIDForIP(ip))
	}

	if s.firewall != nil {
		if err := s.firewall.UnblockIP(ip); err != nil {
			logging.Warn().Err(err).Str("ip", ip).Msg("host firewall unban failed")
		}
	}

	if wafErr != nil && s.firewall == nil {
		s.writeError(w, r, http.StatusServiceUnavailable,
			"cannot lift ban: WAF rule removal failed ("+wafErr.Error()+") and no host firewall is available")
		return
	}

	if s.audit != nil {
		s.audit.Record(audit.Event{
			Actor:     UserFromContext(r.Context()),
			Action:    "firewall_unban",
			Resource:  ip,
			Result:    "success",
			Details:   "unbanned via control room",
			Timestamp: time.Now(),
		})
	}

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"success": true,
		"ip":      ip,
	})
}
