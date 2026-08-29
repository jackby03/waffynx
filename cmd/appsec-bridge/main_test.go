package main

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSocketPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "appsec_test.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on socket: %v", err)
	}
	defer ln.Close()

	if err := os.Chmod(socketPath, 0600); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected socket permissions 0600, got %o", perm)
	}
}

func TestParseQueryParams(t *testing.T) {
	tests := []struct {
		name     string
		rawURI   string
		expected map[string]string
	}{
		{
			name:     "no query",
			rawURI:   "/api/v1/resource",
			expected: map[string]string{},
		},
		{
			name:     "empty query",
			rawURI:   "/api/v1/resource?",
			expected: map[string]string{},
		},
		{
			name:   "simple query",
			rawURI: "/api/v1/resource?foo=bar&baz=qux",
			expected: map[string]string{
				"foo": "bar",
				"baz": "qux",
			},
		},
		{
			name:   "encoded characters and spaces",
			rawURI: "/api/v1/resource?search=hello+world&category=books%20and%20media",
			expected: map[string]string{
				"search":   "hello world",
				"category": "books and media",
			},
		},
		{
			name:   "valueless key and empty value",
			rawURI: "/api/v1/resource?flag&empty=",
			expected: map[string]string{
				"flag":  "",
				"empty": "",
			},
		},
		{
			name:   "multiple equal signs",
			rawURI: "/api/v1/resource?data=a=b=c&other=1",
			expected: map[string]string{
				"data":  "a=b=c",
				"other": "1",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseQueryParams(tc.rawURI)
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("parseQueryParams(%q) = %v; want %v", tc.rawURI, got, tc.expected)
			}
		})
	}
}

func BenchmarkParseQueryParams(b *testing.B) {
	uris := []string{
		"/api/v1/resource?foo=bar&baz=qux",
		"/api/v1/resource?search=hello+world&category=books%20and%20media&page=2&limit=50&sort=desc&filter=active",
		"/api/v1/resource?flag&empty=&data=a=b=c&other=1",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, uri := range uris {
			_ = parseQueryParams(uri)
		}
	}
}
