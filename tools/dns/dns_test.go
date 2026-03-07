package dns

import (
	"strings"
	"testing"
)

func TestLookup_EmptyDomain(t *testing.T) {
	_, err := Lookup("")
	if err == nil {
		t.Fatal("expected error for empty domain, got nil")
	}
}

func TestLookup_InvalidDomain(t *testing.T) {
	cases := []string{
		"domain; rm -rf /",
		"$(whoami)",
		"domain && cat /etc/passwd",
	}
	for _, tc := range cases {
		_, err := Lookup(tc)
		if err == nil {
			t.Errorf("expected error for domain %q, got nil", tc)
		}
	}
}

func TestLookup_ValidFormat(t *testing.T) {
	// localhost should resolve on any system; if it doesn't, just check no panic.
	result, err := Lookup("localhost")
	if err != nil {
		t.Fatalf("unexpected error for localhost: %v", err)
	}
	// Result should either contain records or the "No DNS records" message.
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestLookup_NoRecordsMessage(t *testing.T) {
	// A domain that is unlikely to resolve.
	result, err := Lookup("this-domain-does-not-exist-xyzzy123.invalid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "No DNS records") && !strings.HasPrefix(result, "A/AAAA") {
		t.Errorf("unexpected result: %q", result)
	}
}
