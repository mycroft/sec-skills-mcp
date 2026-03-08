package whois

import (
	"os/exec"
	"testing"
)

func TestLookup_EmptyTarget(t *testing.T) {
	_, err := Lookup("")
	if err == nil {
		t.Fatal("expected error for empty target, got nil")
	}
}

func TestLookup_InvalidTarget(t *testing.T) {
	cases := []string{
		"domain; rm -rf /",
		"$(whoami)",
		"domain && cat /etc/passwd",
		"domain|evil",
	}
	for _, tc := range cases {
		_, err := Lookup(tc)
		if err == nil {
			t.Errorf("expected error for target %q, got nil", tc)
		}
	}
}

func TestLookup_WhoisNotFound(t *testing.T) {
	if _, err := exec.LookPath("whois"); err == nil {
		t.Skip("whois is available; skipping binary-not-found test")
	}
	_, err := Lookup("example.com")
	if err == nil {
		t.Fatal("expected error when whois binary is missing, got nil")
	}
}

func TestLookup_ValidDomain(t *testing.T) {
	if _, err := exec.LookPath("whois"); err != nil {
		t.Skip("whois not found, skipping integration test")
	}
	result, err := Lookup("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result for example.com")
	}
}

func TestLookup_ValidIP(t *testing.T) {
	if _, err := exec.LookPath("whois"); err != nil {
		t.Skip("whois not found, skipping integration test")
	}
	// 8.8.8.8 is Google's public DNS — safe to query in tests.
	result, err := Lookup("8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result for 8.8.8.8")
	}
}
