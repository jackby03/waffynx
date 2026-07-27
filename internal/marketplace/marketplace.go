package marketplace

import (
	"fmt"
	"sync"
	"time"

	"github.com/jackby03/waffynx/internal/plugin"
)

type PackageStatus string

const (
	StatusPublished PackageStatus = "published"
	StatusInstalled PackageStatus = "installed"
	StatusPending   PackageStatus = "pending"
	StatusDeprecated PackageStatus = "deprecated"
)

type Package struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	Description string             `json:"description"`
	Author      string             `json:"author"`
	License     string             `json:"license"`
	Category    string             `json:"category"`
	Tags        []string           `json:"tags"`
	Downloads   int64              `json:"downloads"`
	Rating      float64            `json:"rating"`
	Status      PackageStatus      `json:"status"`
	PublishedAt time.Time          `json:"published_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	Checksum    string             `json:"checksum"`
	Plugin      *plugin.Metadata   `json:"plugin,omitempty"`
}

type Filter struct {
	Category string
	Tag      string
	Query    string
	Status   PackageStatus
	Limit    int
	Offset   int
}

type Store interface {
	List(filter Filter) ([]*Package, error)
	Get(name, version string) (*Package, error)
	Install(name, version string) error
	Uninstall(name string) error
	Search(query string) ([]*Package, error)
	GetCategories() ([]string, error)
}

type InMemoryStore struct {
	mu       sync.RWMutex
	packages map[string]map[string]*Package
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		packages: make(map[string]map[string]*Package),
	}
}

func (s *InMemoryStore) List(filter Filter) ([]*Package, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Package
	for _, versions := range s.packages {
		for _, pkg := range versions {
			if filter.Status != "" && pkg.Status != filter.Status {
				continue
			}
			if filter.Category != "" && pkg.Category != filter.Category {
				continue
			}
			result = append(result, pkg)
		}
	}

	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}

	return result, nil
}

func (s *InMemoryStore) Get(name, version string) (*Package, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	versions, ok := s.packages[name]
	if !ok {
		return nil, fmt.Errorf("package %s not found", name)
	}

	pkg, ok := versions[version]
	if !ok {
		return nil, fmt.Errorf("version %s of package %s not found", version, name)
	}

	return pkg, nil
}

func (s *InMemoryStore) Install(name, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	versions, ok := s.packages[name]
	if !ok {
		return fmt.Errorf("package %s not found", name)
	}

	pkg, ok := versions[version]
	if !ok {
		return fmt.Errorf("version %s of package %s not found", version, name)
	}

	pkg.Status = StatusInstalled
	return nil
}

func (s *InMemoryStore) Uninstall(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	versions, ok := s.packages[name]
	if !ok {
		return fmt.Errorf("package %s not found", name)
	}

	for _, pkg := range versions {
		if pkg.Status == StatusInstalled {
			pkg.Status = StatusPublished
			return nil
		}
	}

	return fmt.Errorf("package %s is not installed", name)
}

func (s *InMemoryStore) Search(query string) ([]*Package, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Package
	for _, versions := range s.packages {
		for _, pkg := range versions {
			if contains(pkg.Name, query) || contains(pkg.Description, query) {
				result = append(result, pkg)
			}
		}
	}
	return result, nil
}

func (s *InMemoryStore) GetCategories() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	categories := make(map[string]bool)
	for _, versions := range s.packages {
		for _, pkg := range versions {
			categories[pkg.Category] = true
		}
	}

	var result []string
	for cat := range categories {
		result = append(result, cat)
	}
	return result, nil
}

func (s *InMemoryStore) AddPackage(pkg *Package) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.packages[pkg.Name]; !ok {
		s.packages[pkg.Name] = make(map[string]*Package)
	}
	s.packages[pkg.Name][pkg.Version] = pkg
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
