package firewall

import (
	"strings"
	"testing"
)

func captureCmd(t *testing.T, fn func()) (name string, args []string) {
	t.Helper()
	orig := runCmd
	defer func() { runCmd = orig }()

	runCmd = func(n string, a ...string) (string, error) {
		name = n
		args = a
		return "", nil
	}
	fn()
	return
}

func TestUFWBackend_AddRule(t *testing.T) {
	u := &UFWBackend{}
	name, args := captureCmd(t, func() {
		u.AddRule(Rule{
			Action:   "deny",
			Source:   "10.0.0.1",
			Port:     80,
			Protocol: "tcp",
			Comment:  "test block",
		})
	})

	if name != "ufw" {
		t.Fatalf("expected ufw, got %s", name)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "deny") {
		t.Error("expected deny action")
	}
	if !strings.Contains(joined, "from 10.0.0.1") {
		t.Error("expected from 10.0.0.1")
	}
	if !strings.Contains(joined, "80") && !strings.Contains(joined, "/tcp") {
		t.Error("expected port 80 with protocol tcp")
	}
	if !strings.Contains(joined, "test block") {
		t.Error("expected comment 'test block'")
	}
}

func TestUFWBackend_RemoveRule(t *testing.T) {
	u := &UFWBackend{}
	name, args := captureCmd(t, func() {
		u.RemoveRule(Rule{
			Action:   "deny",
			Source:   "10.0.0.1",
			Port:     80,
			Protocol: "tcp",
			Comment:  "test block",
		})
	})

	if name != "ufw" {
		t.Fatalf("expected ufw, got %s", name)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "delete") {
		t.Error("expected delete command")
	}
	if !strings.Contains(joined, "deny") {
		t.Error("expected deny action")
	}
	if !strings.Contains(joined, "from 10.0.0.1") {
		t.Error("expected from 10.0.0.1")
	}
	if !strings.Contains(joined, "80") {
		t.Error("expected port 80")
	}
	if !strings.Contains(joined, "proto tcp") {
		t.Error("expected proto tcp")
	}
	if !strings.Contains(joined, "test block") {
		t.Error("expected comment 'test block'")
	}
}

func TestUFWBackend_RemoveRule_NoSource(t *testing.T) {
	u := &UFWBackend{}
	_, args := captureCmd(t, func() {
		u.RemoveRule(Rule{
			Action: "deny",
			Port:   443,
		})
	})

	joined := strings.Join(args, " ")
	if strings.Contains(joined, "from") {
		t.Error("expected no 'from' when source is empty")
	}
	if !strings.Contains(joined, "443") {
		t.Error("expected port 443")
	}
}

func TestNFTablesBackend_RemoveRule(t *testing.T) {
	n := &NFTablesBackend{}
	name, args := captureCmd(t, func() {
		n.RemoveRule(Rule{
			Action: "drop",
			Source: "192.168.0.1",
		})
	})

	if name != "nft" {
		t.Fatalf("expected nft, got %s", name)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "delete") {
		t.Error("expected delete command")
	}
	if !strings.Contains(joined, "ip saddr 192.168.0.1") {
		t.Error("expected ip saddr 192.168.0.1")
	}
	if !strings.Contains(joined, "drop") {
		t.Error("expected drop action")
	}
}

func TestUFWBackend_SetDefaultPolicy(t *testing.T) {
	u := &UFWBackend{}
	name, args := captureCmd(t, func() {
		u.SetDefaultPolicy("input", "deny")
	})

	if name != "ufw" {
		t.Fatalf("expected ufw, got %s", name)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "default") {
		t.Error("expected default command")
	}
	if !strings.Contains(joined, "deny") {
		t.Error("expected deny policy")
	}
	if !strings.Contains(joined, "input") {
		t.Error("expected input chain")
	}
}

func TestNFTablesBackend_SetDefaultPolicy(t *testing.T) {
	n := &NFTablesBackend{}
	name, args := captureCmd(t, func() {
		n.SetDefaultPolicy("input", "drop")
	})

	if name != "nft" {
		t.Fatalf("expected nft, got %s", name)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "add rule") {
		t.Error("expected add rule")
	}
	if !strings.Contains(joined, "waffynx") {
		t.Error("expected waffynx table")
	}
	if !strings.Contains(joined, "input") {
		t.Error("expected input chain")
	}
	if !strings.Contains(joined, "counter") {
		t.Error("expected counter")
	}
	if !strings.Contains(joined, "drop") {
		t.Error("expected drop policy")
	}
}
