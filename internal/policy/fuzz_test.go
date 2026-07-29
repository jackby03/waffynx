package policy

import (
	"context"
	"testing"
)

func FuzzPolicyEvaluate(f *testing.F) {
	f.Add("GET", "/api/users", "1.2.3.4", []byte(`{"user":"admin"}`))
	f.Add("POST", "/upload/shell.php", "10.0.0.1", []byte("<?php echo 'hi'; ?>"))
	f.Add("PUT", "/page?x=<script>alert(1)</script>", "192.168.1.1", []byte(""))

	f.Fuzz(func(t *testing.T, method, path, remoteIP string, body []byte) {
		engine := NewRuleEngine()
		
		engine.AddRule(Rule{
			ID: "rule1", Name: "block-post", Phase: PhaseRequest,
			Enabled: true, Action: ActionBlock,
			Match: func(ctx context.Context, req *Request) bool {
				return req.Method == "POST"
			},
		})
		
		req := &Request{
			Method:   method,
			Path:     path,
			RemoteIP: remoteIP,
			Body:     body,
		}
		
		engine.Evaluate(context.Background(), PhaseRequest, req)
	})
}
