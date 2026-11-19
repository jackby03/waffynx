// Package authz implements Zero-Trust continuous request authorization
// (NIST SP 800-207 / Envoy ext_authz) evaluated lock-free in the Data Plane.
package authz

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/jackby03/waffynx/internal/auth"
	"github.com/jackby03/waffynx/internal/storage"
)

// CountryLookup resolves an IP string to an ISO 3166-1 alpha-2 country code.
type CountryLookup func(ip string) string

// Request carries the normalized attributes extracted from Envoy ext_authz CheckRequest.
type Request struct {
	Method   string
	Host     string
	Path     string
	RemoteIP string
	Headers  map[string]string // lower-cased header keys
}

// Decision is the Zero-Trust authorization verdict.
type Decision struct {
	Allowed      bool
	ShadowDenied bool
	StatusCode   int // 200, 401, or 403
	PolicyID     string
	Reason       string
	Subject      string
	Role         string
	Scopes       []string
	CountryCode  string
}

type compiledPolicy struct {
	raw          storage.ZeroTrustPolicy
	allowedCIDRs []*net.IPNet
	blockedCC    map[string]struct{}
	deviceHdrKey string
	deviceHdrVal string
}

type compiledSnapshot struct {
	policies []compiledPolicy
}

// Evaluator evaluates compiled Zero-Trust policies lock-free via atomic.Pointer.
type Evaluator struct {
	jwtMgr        *auth.Manager
	countryLookup CountryLookup
	snap          atomic.Pointer[compiledSnapshot]
}

// NewEvaluator creates an empty Zero-Trust evaluator. Pass jwtMgr to enable
// JWT/OIDC bearer verification.
func NewEvaluator(jwtMgr *auth.Manager, countryLookup CountryLookup) *Evaluator {
	e := &Evaluator{
		jwtMgr:        jwtMgr,
		countryLookup: countryLookup,
	}
	e.snap.Store(&compiledSnapshot{})
	return e
}

// ReplacePolicies compiles policies off the hot path and swaps them atomically.
func (e *Evaluator) ReplacePolicies(policies []storage.ZeroTrustPolicy) {
	sorted := make([]storage.ZeroTrustPolicy, len(policies))
	copy(sorted, policies)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].ID < sorted[j].ID
	})

	compiled := make([]compiledPolicy, 0, len(sorted))
	for _, p := range sorted {
		if !p.Enabled {
			continue
		}
		cp := compiledPolicy{raw: p}
		for _, cidr := range p.AllowedCIDRs {
			if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil {
				cp.allowedCIDRs = append(cp.allowedCIDRs, ipNet)
			}
		}
		if len(p.BlockedCountries) > 0 {
			cp.blockedCC = make(map[string]struct{}, len(p.BlockedCountries))
			for _, cc := range p.BlockedCountries {
				cp.blockedCC[strings.ToUpper(strings.TrimSpace(cc))] = struct{}{}
			}
		}
		if p.RequireDeviceHeader != "" {
			k, v, hasVal := strings.Cut(p.RequireDeviceHeader, ":")
			cp.deviceHdrKey = strings.ToLower(strings.TrimSpace(k))
			if hasVal {
				cp.deviceHdrVal = strings.TrimSpace(v)
			}
		}
		compiled = append(compiled, cp)
	}
	e.snap.Store(&compiledSnapshot{policies: compiled})
}

// Evaluate checks all matching Zero-Trust policies for req.
func (e *Evaluator) Evaluate(req Request) Decision {
	snap := e.snap.Load()
	if snap == nil || len(snap.policies) == 0 {
		return Decision{Allowed: true, StatusCode: 200}
	}

	cleanPath := req.Path
	if idx := strings.IndexByte(cleanPath, '?'); idx >= 0 {
		cleanPath = cleanPath[:idx]
	}

	var country string
	if e.countryLookup != nil && req.RemoteIP != "" {
		country = strings.ToUpper(e.countryLookup(req.RemoteIP))
	}

	verdict := Decision{Allowed: true, StatusCode: 200, CountryCode: country}

	for i := range snap.policies {
		cp := &snap.policies[i]
		if !matchesTarget(&cp.raw, req.Host, cleanPath) {
			continue
		}
		d := e.evalPolicy(cp, req, country)
		if !d.Allowed {
			if cp.raw.ShadowMode {
				verdict.ShadowDenied = true
				verdict.PolicyID = cp.raw.ID
				verdict.Reason = d.Reason
				continue
			}
			return d
		}
		if d.Subject != "" {
			verdict.Subject = d.Subject
			verdict.Role = d.Role
			verdict.Scopes = d.Scopes
		}
	}

	return verdict
}

func matchesTarget(p *storage.ZeroTrustPolicy, host, cleanPath string) bool {
	if p.Host != "" && !strings.EqualFold(p.Host, host) {
		return false
	}
	if p.PathPrefix != "" && p.PathPrefix != "/" && !strings.HasPrefix(cleanPath, p.PathPrefix) {
		return false
	}
	return true
}

func (e *Evaluator) evalPolicy(cp *compiledPolicy, req Request, country string) Decision {
	p := &cp.raw
	d := Decision{Allowed: true, StatusCode: 200, PolicyID: p.ID, CountryCode: country}

	// 1. GeoIP country posture check.
	if len(cp.blockedCC) > 0 && country != "" {
		if _, blocked := cp.blockedCC[country]; blocked {
			return Decision{
				Allowed:     false,
				StatusCode:  403,
				PolicyID:    p.ID,
				Reason:      fmt.Sprintf("zero-trust policy %s: blocked country %s", p.ID, country),
				CountryCode: country,
			}
		}
	}

	// 2. Source IP CIDR allowlist.
	if len(cp.allowedCIDRs) > 0 {
		ip := net.ParseIP(req.RemoteIP)
		allowed := false
		if ip != nil {
			for _, ipNet := range cp.allowedCIDRs {
				if ipNet.Contains(ip) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return Decision{
				Allowed:     false,
				StatusCode:  403,
				PolicyID:    p.ID,
				Reason:      fmt.Sprintf("zero-trust policy %s: source IP %s outside allowed CIDRs", p.ID, req.RemoteIP),
				CountryCode: country,
			}
		}
	}

	// 3. Device / mTLS identity posture header.
	if cp.deviceHdrKey != "" {
		val := strings.TrimSpace(req.Headers[cp.deviceHdrKey])
		if val == "" || (cp.deviceHdrVal != "" && val != cp.deviceHdrVal) {
			return Decision{
				Allowed:     false,
				StatusCode:  403,
				PolicyID:    p.ID,
				Reason:      fmt.Sprintf("zero-trust policy %s: missing or invalid device posture header %s", p.ID, cp.deviceHdrKey),
				CountryCode: country,
			}
		}
	}

	// 4. Continuous JWT identity and scope verification (fail-closed if manager missing).
	if p.RequireJWT {
		if e.jwtMgr == nil {
			return Decision{
				Allowed:     false,
				StatusCode:  401,
				PolicyID:    p.ID,
				Reason:      fmt.Sprintf("zero-trust policy %s: JWT verifier unavailable (fail-closed)", p.ID),
				CountryCode: country,
			}
		}
		authHeader := strings.TrimSpace(req.Headers["authorization"])
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			return Decision{
				Allowed:     false,
				StatusCode:  401,
				PolicyID:    p.ID,
				Reason:      fmt.Sprintf("zero-trust policy %s: missing bearer token", p.ID),
				CountryCode: country,
			}
		}
		token := strings.TrimSpace(authHeader[7:])
		claims, err := e.jwtMgr.ValidateToken(token)
		if err != nil {
			return Decision{
				Allowed:     false,
				StatusCode:  401,
				PolicyID:    p.ID,
				Reason:      fmt.Sprintf("zero-trust policy %s: invalid JWT (%v)", p.ID, err),
				CountryCode: country,
			}
		}
		if len(p.AllowedIssuers) > 0 && !slices.Contains(p.AllowedIssuers, claims.Issuer) {
			return Decision{
				Allowed:     false,
				StatusCode:  403,
				PolicyID:    p.ID,
				Reason:      fmt.Sprintf("zero-trust policy %s: untrusted JWT issuer %q", p.ID, claims.Issuer),
				CountryCode: country,
			}
		}
		for _, wantScope := range p.RequiredScopes {
			if !slices.Contains(claims.Scopes, wantScope) {
				return Decision{
					Allowed:     false,
					StatusCode:  403,
					PolicyID:    p.ID,
					Reason:      fmt.Sprintf("zero-trust policy %s: missing required scope %q", p.ID, wantScope),
					CountryCode: country,
				}
			}
		}
		d.Subject = claims.Username
		d.Role = claims.Role
		d.Scopes = claims.Scopes
	}

	return d
}
