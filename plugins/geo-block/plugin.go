package geoblock

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/oschwald/maxminddb-golang"

	"github.com/jackby03/waffynx/internal/plugin"
)

var (
	PluginName = "geo-block"
	Version    = "1.0.0"
)

func init() {
	plugin.Register(PluginName, func() plugin.Plugin {
		return &GeoBlockPlugin{}
	}, &plugin.Metadata{
		Name:        PluginName,
		Version:     Version,
		Description: "Blocks or allows traffic based on geographic IP location",
		Author:      "Waffynx",
		License:     "MIT",
		Phase:       plugin.PhasePreRequest,
		Priority:    50,
		Tags:        []string{"security", "geoip", "blocking"},
	})
}

type GeoBlockPlugin struct {
	enabled          bool
	allowedCountries map[string]bool
	blockedCountries map[string]bool
	mode             string
	dbPath           string
	db               *maxminddb.Reader
}

func (p *GeoBlockPlugin) Name() string        { return PluginName }
func (p *GeoBlockPlugin) Version() string     { return Version }
func (p *GeoBlockPlugin) Description() string { return "Geo-blocking plugin" }
func (p *GeoBlockPlugin) Phase() plugin.Phase { return plugin.PhasePreRequest }
func (p *GeoBlockPlugin) Priority() int       { return 50 }

func (p *GeoBlockPlugin) Init(config map[string]interface{}) error {
	p.enabled = true
	p.mode = "block"
	p.allowedCountries = make(map[string]bool)
	p.blockedCountries = make(map[string]bool)

	if v, ok := config["mode"].(string); ok && v != "" {
		p.mode = v
	}
	if v, ok := config["db_path"].(string); ok && v != "" {
		p.dbPath = v
	} else {
		p.dbPath = "/opt/waffynx/geoip/GeoLite2-Country.mmdb"
	}

	if v, ok := config["allowed_countries"]; ok {
		p.parseCountryList(v, p.allowedCountries)
	}
	if v, ok := config["blocked_countries"]; ok {
		p.parseCountryList(v, p.blockedCountries)
	}

	if _, err := os.Stat(p.dbPath); err == nil {
		db, err := maxminddb.Open(p.dbPath)
		if err != nil {
			return fmt.Errorf("opening GeoIP database: %w", err)
		}
		p.db = db
	}

	return nil
}

func (p *GeoBlockPlugin) parseCountryList(raw interface{}, target map[string]bool) {
	if list, ok := raw.([]interface{}); ok {
		for _, c := range list {
			if s, ok := c.(string); ok {
				target[s] = true
			}
		}
	}
}

func (p *GeoBlockPlugin) Execute(ctx *plugin.Context) (*plugin.Context, error) {
	if !p.enabled {
		return ctx, nil
	}

	clientIP := p.extractIP(ctx)
	if clientIP == "" {
		return ctx, nil
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return ctx, nil
	}

	country := p.lookupCountry(ip)

	if p.mode == "allow" && len(p.allowedCountries) > 0 {
		if !p.allowedCountries[country] {
			ctx.StatusCode = http.StatusForbidden
			ctx.ResponseWriter.Header().Set("Content-Type", "application/json")
			ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
			ctx.ResponseWriter.Write([]byte(`{"error":"access denied: country not allowed"}`))
			return ctx, fmt.Errorf("geo-block: %s from %s not in allowed list", clientIP, country)
		}
		return ctx, nil
	}

	if len(p.blockedCountries) > 0 && p.blockedCountries[country] {
		ctx.StatusCode = http.StatusForbidden
		ctx.ResponseWriter.Header().Set("Content-Type", "application/json")
		ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
		ctx.ResponseWriter.Write([]byte(`{"error":"access denied: country blocked"}`))
		return ctx, fmt.Errorf("geo-block: %s from %s is blocked", clientIP, country)
	}

	return ctx, nil
}

func (p *GeoBlockPlugin) Close() error {
	if p.db != nil {
		p.db.Close()
	}
	return nil
}

func (p *GeoBlockPlugin) extractIP(ctx *plugin.Context) string {
	if v, ok := ctx.Values["wn_ip"].(string); ok && v != "" {
		return v
	}
	if ctx.Request != nil {
		ip := ctx.Request.RemoteAddr
		if forwarded := ctx.Request.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = forwarded
		}
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		return ip
	}
	return ""
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func (p *GeoBlockPlugin) lookupCountry(ip net.IP) string {
	if p.db == nil {
		return "XX"
	}

	var record countryRecord
	if err := p.db.Lookup(ip, &record); err != nil {
		return "XX"
	}

	if record.Country.ISOCode == "" {
		return "XX"
	}

	return record.Country.ISOCode
}
