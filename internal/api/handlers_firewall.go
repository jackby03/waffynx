package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/events"
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

	s.firewallMu.Lock()
	s.bannedIPs[req.IP] = ban
	s.firewallMu.Unlock()

	if s.firewall != nil {
		_ = s.firewall.BlockIP(req.IP)
	}

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

	if s.firewall != nil {
		_ = s.firewall.UnblockIP(ip)
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
