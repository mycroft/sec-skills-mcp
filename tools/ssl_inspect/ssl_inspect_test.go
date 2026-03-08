package ssl_inspect

import (
	"strings"
	"testing"
)

func TestInspect_EmptyHost(t *testing.T) {
	_, err := Inspect("", "443")
	if err == nil {
		t.Fatal("expected error for empty host, got nil")
	}
}

func TestInspect_InvalidHost(t *testing.T) {
	cases := []string{
		"host; rm -rf /",
		"$(whoami)",
		"host && cat /etc/passwd",
		"host\x00null",
	}
	for _, tc := range cases {
		_, err := Inspect(tc, "443")
		if err == nil {
			t.Errorf("expected error for host %q, got nil", tc)
		}
	}
}

func TestInspect_InvalidPort(t *testing.T) {
	cases := []struct {
		port string
		desc string
	}{
		{"not-a-port", "non-numeric port"},
		{"0", "port zero"},
		{"65536", "port out of range"},
		{"-1", "negative port"},
	}
	for _, tc := range cases {
		_, err := Inspect("example.com", tc.port)
		if err == nil {
			t.Errorf("expected error for %s (%q), got nil", tc.desc, tc.port)
		}
	}
}

func TestInspect_DefaultPort(t *testing.T) {
	// Passing an empty port should not return a validation error; a connection
	// error is acceptable (the test environment may not have network access).
	// We just verify no input-validation error is returned.
	_, err := Inspect("example.com", "")
	if err != nil && strings.Contains(err.Error(), "invalid port") {
		t.Errorf("empty port should default to 443, not return an invalid-port error: %v", err)
	}
}

func TestInspect_Integration(t *testing.T) {
	result, err := Inspect("example.com", "443")
	if err != nil {
		t.Skipf("network unavailable or connection failed: %v", err)
	}

	checks := []string{
		"SSL/TLS Inspection",
		"Leaf Certificate",
		"Protocol Version Support",
		"Weak Cipher Suite",
	}
	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("expected %q in result; got:\n%s", check, result)
		}
	}
}
