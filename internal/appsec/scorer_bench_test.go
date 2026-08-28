package appsec

import (
	"context"
	"testing"
)

func BenchmarkBasicScorer_Evaluate_Clean(b *testing.B) {
	s := NewBasicScorer()
	ctx := context.Background()

	feat := &Features{
		URI:       "/api/v1/users/profile?category=electronics&page=2&sort=asc",
		Host:      "example.com",
		Method:    "POST",
		ClientIP:  "192.168.1.100",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		QueryParams: map[string]string{
			"category": "electronics",
			"page":     "2",
			"sort":     "asc",
		},
		Body:       []byte(`{"username":"johndoe","email":"john@example.com","bio":"Software engineer based in NYC"}`),
		HasPayload: true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = s.Evaluate(ctx, feat)
	}
}

func BenchmarkBasicScorer_CheckPatterns(b *testing.B) {
	s := NewBasicScorer()
	uri := "/api/v1/users/profile"
	params := map[string]string{
		"category": "electronics",
		"page":     "2",
		"sort":     "asc",
	}
	body := []byte(`{"username":"johndoe","email":"john@example.com","bio":"Software engineer based in NYC"}`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = s.checkPatterns(uri, params, body, s.sqliPatterns)
		_, _ = s.checkPatterns(uri, params, body, s.xssPatterns)
		_, _ = s.checkPatterns(uri, params, body, s.pathTraversal)
		_, _ = s.checkPatterns(uri, params, body, s.cmdInjection)
	}
}
