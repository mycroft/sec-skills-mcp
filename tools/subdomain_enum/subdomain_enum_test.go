package subdomain_enum

import (
	"os/exec"
	"strings"
	"testing"
)

func TestEnumerate_EmptyDomain(t *testing.T) {
	_, err := Enumerate("", EnumOptions{})
	if err == nil {
		t.Fatal("expected error for empty domain, got nil")
	}
}

func TestEnumerate_InvalidDomain(t *testing.T) {
	cases := []string{
		"domain; rm -rf /",
		"$(whoami)",
		"domain && cat /etc/passwd",
		"domain|id",
	}
	for _, tc := range cases {
		_, err := Enumerate(tc, EnumOptions{})
		if err == nil {
			t.Errorf("expected error for domain %q, got nil", tc)
		}
	}
}

func TestEnumerate_UnknownMethod(t *testing.T) {
	_, err := Enumerate("example.com", EnumOptions{Method: "nmap"})
	if err == nil {
		t.Fatal("expected error for unknown method, got nil")
	}
	if !strings.Contains(err.Error(), "unknown method") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEnumerate_GobusterMissingWordlist(t *testing.T) {
	if _, err := exec.LookPath("gobuster"); err != nil {
		t.Skip("gobuster not found, skipping")
	}
	_, err := Enumerate("example.com", EnumOptions{Method: "gobuster"})
	if err == nil {
		t.Fatal("expected error when wordlist is missing, got nil")
	}
	if !strings.Contains(err.Error(), "wordlist") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEnumerate_FfufMissingWordlist(t *testing.T) {
	if _, err := exec.LookPath("ffuf"); err != nil {
		t.Skip("ffuf not found, skipping")
	}
	_, err := Enumerate("example.com", EnumOptions{Method: "ffuf"})
	if err == nil {
		t.Fatal("expected error when wordlist is missing, got nil")
	}
	if !strings.Contains(err.Error(), "wordlist") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEnumerate_GobusterNotFound(t *testing.T) {
	if _, err := exec.LookPath("gobuster"); err == nil {
		t.Skip("gobuster found in PATH, skipping not-found test")
	}
	_, err := Enumerate("example.com", EnumOptions{Method: "gobuster", Wordlist: "/usr/share/wordlists/subdomains.txt"})
	if err == nil {
		t.Fatal("expected error when gobuster is not installed, got nil")
	}
	if !strings.Contains(err.Error(), "gobuster not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEnumerate_FfufNotFound(t *testing.T) {
	if _, err := exec.LookPath("ffuf"); err == nil {
		t.Skip("ffuf found in PATH, skipping not-found test")
	}
	_, err := Enumerate("example.com", EnumOptions{Method: "ffuf", Wordlist: "/usr/share/wordlists/subdomains.txt"})
	if err == nil {
		t.Fatal("expected error when ffuf is not installed, got nil")
	}
	if !strings.Contains(err.Error(), "ffuf not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEnumerate_InvalidWordlistPath(t *testing.T) {
	cases := []struct {
		method   string
		wordlist string
	}{
		{"gobuster", "/path/with spaces/wordlist.txt"},
		{"gobuster", "/path;rm -rf /"},
		{"ffuf", "/path/with spaces/wordlist.txt"},
		{"ffuf", "/path;rm -rf /"},
	}
	for _, tc := range cases {
		_, err := Enumerate("example.com", EnumOptions{Method: tc.method, Wordlist: tc.wordlist})
		if err == nil {
			t.Errorf("expected error for method %q with wordlist %q, got nil", tc.method, tc.wordlist)
		}
	}
}

func TestEnumCrtsh_DefaultMethod(t *testing.T) {
	// Verify that "crtsh" is the default method by checking no unknown-method error.
	// We can't make real network calls in unit tests, but we can confirm the routing.
	// This test exercises the validation path only; skip if no network is expected.
	result, err := Enumerate("this-domain-does-not-exist-xyzzy123.invalid", EnumOptions{})
	// We accept either a network error or a "no subdomains found" result.
	if err != nil {
		if strings.Contains(err.Error(), "unknown method") {
			t.Errorf("default method should be crtsh, not unknown: %v", err)
		}
		// Any other error (network, DNS, etc.) is acceptable in this unit test.
		return
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}
