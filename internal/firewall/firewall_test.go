package firewall

import (
	"strings"
	"testing"

	"github.com/jackby03/waffynx/internal/config"
)

type commandCall struct {
	Name string
	Args []string
}

func mockRunCmd(calls *[]commandCall, returns map[string]string) func(string, ...string) (string, error) {
	return func(name string, args ...string) (string, error) {
		*calls = append(*calls, commandCall{Name: name, Args: args})
		key := name + " " + strings.Join(args, " ")
		if out, ok := returns[key]; ok {
			return out, nil
		}
		// Prefix match lookup
		for k, out := range returns {
			if strings.HasPrefix(key, k) {
				return out, nil
			}
		}
		return "", nil
	}
}

func TestUFWBackend_AddRule(t *testing.T) {
	var calls []commandCall
	SetRunCmd(mockRunCmd(&calls, nil))

	ufw := &UFWBackend{}
	rule := Rule{
		Port:     80,
		Protocol: "tcp",
		Source:   "1.2.3.4",
		Action:   "drop",
		Comment:  "test rule",
	}

	err := ufw.AddRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	call := calls[0]
	if call.Name != "ufw" {
		t.Errorf("expected command 'ufw', got %s", call.Name)
	}

	expectedArgs := "deny 80 /tcp from 1.2.3.4 comment test rule"
	actualArgs := strings.Join(call.Args, " ")
	if actualArgs != expectedArgs {
		t.Errorf("expected args %q, got %q", expectedArgs, actualArgs)
	}
}

func TestUFWBackend_RemoveRule(t *testing.T) {
	var calls []commandCall
	SetRunCmd(mockRunCmd(&calls, nil))

	ufw := &UFWBackend{}
	rule := Rule{
		Port:     443,
		Protocol: "tcp",
		Source:   "192.168.1.50",
		Action:   "deny",
	}

	err := ufw.RemoveRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	call := calls[0]
	actualArgs := strings.Join(call.Args, " ")
	expectedArgs := "delete deny from 192.168.1.50 443 proto tcp"
	if actualArgs != expectedArgs {
		t.Errorf("expected args %q, got %q", expectedArgs, actualArgs)
	}
}

func TestUFWBackend_ListRules(t *testing.T) {
	mockOutput := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 80/tcp                     ALLOW IN    Anywhere
[ 2] Anywhere                   DENY IN     10.0.0.5
`
	var calls []commandCall
	SetRunCmd(mockRunCmd(&calls, map[string]string{"ufw status numbered": mockOutput}))

	ufw := &UFWBackend{}
	rules, err := ufw.ListRules()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].Port != 80 || rules[0].Protocol != "tcp" || rules[0].Action != "accept" {
		t.Errorf("rule 0 mismatch: %+v", rules[0])
	}

	if rules[1].Source != "10.0.0.5" || rules[1].Action != "deny" {
		t.Errorf("rule 1 mismatch: %+v", rules[1])
	}
}

func TestNFTablesBackend_AddRule(t *testing.T) {
	var calls []commandCall
	SetRunCmd(mockRunCmd(&calls, nil))

	nft := &NFTablesBackend{}
	rule := Rule{
		Port:     8080,
		Protocol: "tcp",
		Source:   "10.0.0.1",
		Action:   "drop",
		Comment:  "block bad actor",
	}

	err := nft.AddRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	actualArgs := strings.Join(calls[0].Args, " ")
	expectedArgs := `add rule ip waffynx input tcp dport 8080 ip saddr 10.0.0.1 drop comment "block bad actor"`
	if actualArgs != expectedArgs {
		t.Errorf("expected args %q, got %q", expectedArgs, actualArgs)
	}
}

func TestNFTablesBackend_RemoveRule(t *testing.T) {
	var calls []commandCall
	SetRunCmd(mockRunCmd(&calls, nil))

	nft := &NFTablesBackend{}
	rule := Rule{
		Source: "1.1.1.1",
		Action: "drop",
	}

	err := nft.RemoveRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	actualArgs := strings.Join(calls[0].Args, " ")
	expectedArgs := "delete rule ip waffynx input ip saddr 1.1.1.1 drop"
	if actualArgs != expectedArgs {
		t.Errorf("expected args %q, got %q", expectedArgs, actualArgs)
	}
}

func TestNFTablesBackend_SetDefaultPolicy(t *testing.T) {
	var calls []commandCall
	SetRunCmd(mockRunCmd(&calls, nil))

	nft := &NFTablesBackend{}
	err := nft.SetDefaultPolicy("input", "drop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	actualArgs := strings.Join(calls[0].Args, " ")
	expectedArgs := "add rule ip waffynx input counter drop"
	if actualArgs != expectedArgs {
		t.Errorf("expected args %q, got %q", expectedArgs, actualArgs)
	}
}

func TestManager_Start(t *testing.T) {
	var calls []commandCall
	SetRunCmd(mockRunCmd(&calls, nil))

	cfg := config.FirewallConfig{
		Enabled:      true,
		Backend:      "nftables",
		DefaultIn:    "drop",
		DefaultOut:   "accept",
		ManagedPorts: []int{80, 443},
		BlockList:    []string{"192.168.1.100"},
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating manager: %v", err)
	}

	err = mgr.Start()
	if err != nil {
		t.Fatalf("unexpected error starting manager: %v", err)
	}

	// Should have executed:
	// 2 calls for Initialize (add table, add chain)
	// 2 calls for SetDefaultPolicy (input, output)
	// 2 calls for ManagedPorts (80, 443)
	// 1 call for BlockList (192.168.1.100)
	// Total: 7 calls
	if len(calls) != 7 {
		t.Errorf("expected 7 command calls, got %d", len(calls))
		for i, c := range calls {
			t.Logf("call %d: %s %s", i, c.Name, strings.Join(c.Args, " "))
		}
	}
}

func TestManager_UnsupportedBackend(t *testing.T) {
	cfg := config.FirewallConfig{
		Backend: "invalid_backend",
	}

	_, err := NewManager(cfg)
	if err == nil {
		t.Error("expected error for unsupported backend, got nil")
	}
}

func TestManager_Disabled(t *testing.T) {
	var calls []commandCall
	SetRunCmd(mockRunCmd(&calls, nil))

	cfg := config.FirewallConfig{
		Enabled: false,
		Backend: "ufw",
	}

	mgr, _ := NewManager(cfg)
	err := mgr.Start()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 0 {
		t.Errorf("expected 0 command calls when disabled, got %d", len(calls))
	}
}
