package parsers

import (
	"encoding/json"
	"strings"
)

type GraphQLResult struct {
	IsGraphQL     bool     `json:"is_graphql"`
	IsIntrospection bool   `json:"is_introspection"`
	QueryDepth    int      `json:"query_depth"`
	IsBatched     bool     `json:"is_batched"`
	Issues        []string `json:"issues,omitempty"`
}

var introspectionFields = []string{
	"__schema", "__type", "__typename",
	"queryType", "mutationType", "subscriptionType",
	"types", "fields", "inputFields", "interfaces",
	"enumValues", "possibleTypes", "directives",
	"args", "defaultValue", "locations",
}

func InspectGraphQL(contentType string, body []byte) *GraphQLResult {
	result := &GraphQLResult{}

	if !isGraphQLContentType(contentType) {
		return result
	}

	var gql struct {
		Query         string         `json:"query"`
		OperationName string         `json:"operationName"`
		Variables     map[string]any `json:"variables"`
	}

	var batched []struct {
		Query         string         `json:"query"`
		OperationName string         `json:"operationName"`
		Variables     map[string]any `json:"variables"`
	}

	if err := json.Unmarshal(body, &gql); err == nil && gql.Query != "" {
		result.IsGraphQL = true
		result.QueryDepth = calculateQueryDepth(gql.Query)
		result.IsIntrospection = detectIntrospection(gql.Query)

		if result.QueryDepth > 20 {
			result.Issues = append(result.Issues, "query depth exceeds limit (>20)")
		}
		if result.IsIntrospection {
			result.Issues = append(result.Issues, "introspection query detected")
		}
		checkSuspiciousVariables(gql.Variables, &result.Issues)
		return result
	}

	if err := json.Unmarshal(body, &batched); err == nil && len(batched) > 0 {
		result.IsGraphQL = true
		result.IsBatched = true
		if len(batched) > 10 {
			result.Issues = append(result.Issues, "batched query exceeds limit (>10)")
		}
		for _, q := range batched {
			depth := calculateQueryDepth(q.Query)
			if depth > result.QueryDepth {
				result.QueryDepth = depth
			}
			if detectIntrospection(q.Query) {
				result.IsIntrospection = true
			}
			checkSuspiciousVariables(q.Variables, &result.Issues)
		}
		if result.IsIntrospection {
			result.Issues = append(result.Issues, "introspection query detected")
		}
		return result
	}

	return result
}

func isGraphQLContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "application/graphql") ||
		strings.Contains(ct, "application/json")
}

func calculateQueryDepth(query string) int {
	depth := 0
	maxDepth := 0
	query = strings.ToLower(query)

	for _, c := range query {
		switch c {
		case '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}':
			depth--
		}
	}

	return maxDepth
}

func detectIntrospection(query string) bool {
	lower := strings.ToLower(query)
	for _, field := range introspectionFields {
		if strings.Contains(lower, strings.ToLower(field)) {
			return true
		}
	}
	return false
}

func checkSuspiciousVariables(vars map[string]any, issues *[]string) {
	if vars == nil {
		return
	}
	for _, v := range vars {
		if str, ok := v.(string); ok {
			if detectSQLi(str) || detectXSS(str) {
				*issues = append(*issues, "suspicious variable value detected")
				return
			}
		}
	}
}

func detectSQLi(s string) bool {
	lower := strings.ToLower(s)
	patterns := []string{
		"union select", "' or ", "or 1=1", "or '1'='1",
		"--", "information_schema", "load_file(",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func detectXSS(s string) bool {
	lower := strings.ToLower(s)
	patterns := []string{
		"<script", "javascript:", "onerror=", "alert(",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
