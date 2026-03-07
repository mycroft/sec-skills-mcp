package nmap

import (
	"os/exec"
	"testing"
)

func TestScan_MissingTarget(t *testing.T) {
	_, err := Scan("", "")
	if err == nil {
		t.Fatal("expected error for empty target, got nil")
	}
}

func TestScan_InvalidTarget(t *testing.T) {
	cases := []string{
		"host; rm -rf /",
		"$(whoami)",
		"host && cat /etc/passwd",
		"host\x00name",
	}
	for _, tc := range cases {
		_, err := Scan(tc, "")
		if err == nil {
			t.Errorf("expected error for target %q, got nil", tc)
		}
	}
}

func TestScan_InvalidPorts(t *testing.T) {
	cases := []string{
		"80; rm -rf /",
		"$(whoami)",
		"80 443",
	}
	for _, tc := range cases {
		_, err := Scan("localhost", tc)
		if err == nil {
			t.Errorf("expected error for ports %q, got nil", tc)
		}
	}
}

func TestScan_Integration(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not found, skipping integration test")
	}

	out, err := Scan("127.0.0.1", "80")
	if err != nil {
		// nmap may exit non-zero on some systems without root; just check output.
		t.Logf("nmap returned error (may be expected without root): %v", err)
	}
	if out == "" {
		t.Error("expected non-empty output from nmap")
	}
}
