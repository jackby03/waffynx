package parsers

import (
	"net/http"
	"testing"
)

func TestInspectGraphQL_ValidQuery(t *testing.T) {
	body := []byte(`{"query":"{ users { id name } }"}`)
	result := InspectGraphQL("application/json", body)

	if !result.IsGraphQL {
		t.Error("expected IsGraphQL=true")
	}
	if result.QueryDepth != 2 {
		t.Errorf("expected depth 2, got %d", result.QueryDepth)
	}
	if result.IsIntrospection {
		t.Error("expected IsIntrospection=false")
	}
	if result.IsBatched {
		t.Error("expected IsBatched=false")
	}
}

func TestInspectGraphQL_Introspection(t *testing.T) {
	body := []byte(`{"query":"{ __schema { types { name } } }"}`)
	result := InspectGraphQL("application/json", body)

	if !result.IsIntrospection {
		t.Error("expected introspection detection")
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues for introspection")
	}
}

func TestInspectGraphQL_DeepQuery(t *testing.T) {
	query := "{"
	for i := 0; i < 25; i++ {
		query += "level" + string(rune('a'+i%26)) + "{"
	}
	for i := 0; i < 25; i++ {
		query += "}"
	}
	query += "}"
	body := []byte(`{"query":"` + query + `"}`)
	result := InspectGraphQL("application/json", body)

	if result.QueryDepth < 21 {
		t.Errorf("expected depth >=21, got %d", result.QueryDepth)
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues for depth > 20")
	}
}

func TestInspectGraphQL_Batched(t *testing.T) {
	body := []byte(`[{"query":"{ users { id } }"},{"query":"{ posts { title } }"}]`)
	result := InspectGraphQL("application/json", body)

	if !result.IsBatched {
		t.Error("expected IsBatched=true")
	}
	if !result.IsGraphQL {
		t.Error("expected IsGraphQL=true")
	}
}

func TestInspectGraphQL_SQLiInVariables(t *testing.T) {
	body := []byte(`{"query":"{ user(id: 1) { name } }","variables":{"id":"1 OR 1=1"}}`)
	result := InspectGraphQL("application/json", body)

	if len(result.Issues) == 0 {
		t.Error("expected SQLi detection in variables")
	}
}

func TestInspectGraphQL_NonGraphQL(t *testing.T) {
	body := []byte(`{"user":"admin","pass":"secret"}`)
	result := InspectGraphQL("application/json", body)

	if result.IsGraphQL {
		t.Error("expected IsGraphQL=false for non-GraphQL JSON")
	}
}

func TestInspectGraphQL_NotJSONContentType(t *testing.T) {
	result := InspectGraphQL("text/plain", []byte(`{"query":"{ users }"}`))

	if result.IsGraphQL {
		t.Error("expected IsGraphQL=false for non-JSON content type")
	}
}

func TestCalculateQueryDepth(t *testing.T) {
	tests := []struct {
		query    string
		expected int
	}{
		{"{ a { b } }", 2},
		{"{ a b c }", 1},
		{"{ a { b { c { d } } } }", 4},
		{"", 0},
		{"no braces", 0},
	}

	for _, tt := range tests {
		got := calculateQueryDepth(tt.query)
		if got != tt.expected {
			t.Errorf("calculateQueryDepth(%q) = %d, want %d", tt.query, got, tt.expected)
		}
	}
}

func TestInspectFileUpload_BlockedExtension(t *testing.T) {
	r, _ := http.NewRequest("POST", "/upload/shell.php", nil)
	r.Header.Set("Content-Type", "multipart/form-data")
	result := InspectFileUpload(r, []byte("<?php echo 'hi'; ?>"))

	if len(result.Issues) == 0 {
		t.Error("expected blocked extension")
	}
	if result.Extension != ".php" {
		t.Errorf("expected .php, got %s", result.Extension)
	}
}

func TestInspectFileUpload_MagicMismatch(t *testing.T) {
	r, _ := http.NewRequest("POST", "/upload/file.jpg", nil)
	r.Header.Set("Content-Type", "image/jpeg")
	result := InspectFileUpload(r, []byte("this is not a JPEG file!"))

	if !result.IsUpload {
		t.Error("expected IsUpload=true")
	}
	if result.MagicMatch {
		t.Error("expected magic mismatch for fake JPEG")
	}
	if len(result.Issues) == 0 {
		t.Error("expected issue for magic mismatch")
	}
}

func TestInspectFileUpload_ValidJPEG(t *testing.T) {
	r, _ := http.NewRequest("POST", "/upload/photo.jpg", nil)
	r.Header.Set("Content-Type", "image/jpeg")
	result := InspectFileUpload(r, []byte{0xFF, 0xD8, 0xFF, 0x00, 0x00, 0x00})

	if !result.IsUpload {
		t.Error("expected IsUpload=true")
	}
	if !result.MagicMatch {
		t.Error("expected magic match for valid JPEG")
	}
}

func TestInspectFileUpload_ValidPNG(t *testing.T) {
	r, _ := http.NewRequest("POST", "/upload/icon.png", nil)
	r.Header.Set("Content-Type", "image/png")
	result := InspectFileUpload(r, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A})

	if !result.MagicMatch {
		t.Error("expected magic match for valid PNG")
	}
}

func TestInspectFileUpload_NotUpload(t *testing.T) {
	r, _ := http.NewRequest("POST", "/api/login", nil)
	r.Header.Set("Content-Type", "application/json")
	result := InspectFileUpload(r, []byte(`{"user":"admin"}`))

	if result.IsUpload {
		t.Error("expected IsUpload=false for JSON POST")
	}
}

func TestInspectFileUpload_Oversized(t *testing.T) {
	r, _ := http.NewRequest("POST", "/upload/big.iso", nil)
	r.Header.Set("Content-Type", "application/octet-stream")
	big := make([]byte, 51*1024*1024+1)
	result := InspectFileUpload(r, big)

	hasSize := false
	for _, issue := range result.Issues {
		if issue == "file size exceeds limit (50MB)" {
			hasSize = true
		}
	}
	if !hasSize {
		t.Error("expected oversized file issue")
	}
}
