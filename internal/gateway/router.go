package gateway

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/jackby03/waffynx/internal/config"
)

type Route struct {
	Name     string
	Host     string
	Path     string
	Methods  map[string]bool
	Upstream string
	TLS      *config.TLSConfig
	Plugins  []string
	Headers  map[string]string

	hostPattern *regexp.Regexp
	pathPattern *regexp.Regexp
}

type Router struct {
	mu     sync.RWMutex
	routes []*Route
}

func NewRouter() *Router {
	return &Router{}
}

func (r *Router) AddRoute(cfg *config.RouteConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route := &Route{
		Name:     cfg.Name,
		Host:     cfg.Host,
		Path:     cfg.Path,
		Methods:  make(map[string]bool),
		Upstream: cfg.Upstream,
		TLS:      cfg.TLS,
		Plugins:  cfg.Plugins,
		Headers:  cfg.Headers,
	}

	for _, m := range cfg.Methods {
		route.Methods[strings.ToUpper(m)] = true
	}

	hostPattern := strings.ReplaceAll(cfg.Host, ".", "\\.")
	hostPattern = strings.ReplaceAll(hostPattern, "*", "[^.]+")
	hp, err := regexp.Compile("^" + hostPattern + "$")
	if err != nil {
		return fmt.Errorf("invalid host pattern %s: %w", cfg.Host, err)
	}
	route.hostPattern = hp

	pathPattern := regexp.QuoteMeta(cfg.Path)
	pathPattern = strings.ReplaceAll(pathPattern, "\\*", ".*")
	pp, err := regexp.Compile("^" + pathPattern + "$")
	if err != nil {
		return fmt.Errorf("invalid path pattern %s: %w", cfg.Path, err)
	}
	route.pathPattern = pp

	r.routes = append(r.routes, route)
	return nil
}

func (r *Router) Match(host, path, method string) (*Route, map[string]string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, route := range r.routes {
		if !route.hostPattern.MatchString(host) {
			continue
		}
		if matches := route.pathPattern.FindStringSubmatch(path); matches != nil {
			if len(route.Methods) > 0 && !route.Methods[strings.ToUpper(method)] {
				continue
			}
			params := make(map[string]string)
			names := route.pathPattern.SubexpNames()
			for i, name := range names {
				if i > 0 && name != "" {
					params[name] = matches[i]
				}
			}
			params["path"] = path
			return route, params
		}
	}
	return nil, nil
}
