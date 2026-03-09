package port_service_banner

import (
	"net"
	"strings"
	"testing"
)

// --- parsePorts ---

func TestParsePorts_Single(t *testing.T) {
	ports, err := parsePorts("80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 80 {
		t.Errorf("expected [80], got %v", ports)
	}
}

func TestParsePorts_Multiple(t *testing.T) {
	ports, err := parsePorts("80,443,8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(ports))
	}
}

func TestParsePorts_Range(t *testing.T) {
	ports, err := parsePorts("8000-8003")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 4 {
		t.Errorf("expected 4 ports, got %d: %v", len(ports), ports)
	}
}

func TestParsePorts_InvalidRange(t *testing.T) {
	cases := []string{
		"8080-80",      // low > high
		"0-100",        // port 0 invalid
		"100-70000",    // port > 65535
		"abc-def",      // non-numeric
	}
	for _, tc := range cases {
		_, err := parsePorts(tc)
		if err == nil {
			t.Errorf("expected error for ports %q, got nil", tc)
		}
	}
}

func TestParsePorts_InvalidPort(t *testing.T) {
	cases := []string{"0", "65536", "abc", "-1"}
	for _, tc := range cases {
		_, err := parsePorts(tc)
		if err == nil {
			t.Errorf("expected error for port %q, got nil", tc)
		}
	}
}

func TestParsePorts_Deduplication(t *testing.T) {
	ports, err := parsePorts("80,80,80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 {
		t.Errorf("expected 1 unique port, got %d", len(ports))
	}
}

// --- sanitizeBanner ---

func TestSanitizeBanner_Empty(t *testing.T) {
	if sanitizeBanner([]byte{}) != "" {
		t.Error("expected empty string for empty input")
	}
}

func TestSanitizeBanner_SimpleText(t *testing.T) {
	banner := sanitizeBanner([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	if banner != "SSH-2.0-OpenSSH_8.9" {
		t.Errorf("unexpected banner: %q", banner)
	}
}

func TestSanitizeBanner_MultiLine(t *testing.T) {
	banner := sanitizeBanner([]byte("220 smtp.example.com ESMTP\r\n250 more stuff\r\n"))
	if banner != "220 smtp.example.com ESMTP" {
		t.Errorf("unexpected banner: %q", banner)
	}
}

func TestSanitizeBanner_NonPrintable(t *testing.T) {
	banner := sanitizeBanner([]byte("hello\x01\x02world"))
	if !strings.Contains(banner, "hello") || !strings.Contains(banner, "world") {
		t.Errorf("unexpected banner: %q", banner)
	}
}

// --- GrabBanners input validation ---

func TestGrabBanners_EmptyTarget(t *testing.T) {
	_, err := GrabBanners("", "80", 0)
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestGrabBanners_EmptyPorts(t *testing.T) {
	_, err := GrabBanners("localhost", "", 0)
	if err == nil {
		t.Fatal("expected error for empty ports")
	}
}

func TestGrabBanners_InvalidTarget(t *testing.T) {
	cases := []string{
		"host; rm -rf /",
		"$(whoami)",
		"host && cat /etc/passwd",
	}
	for _, tc := range cases {
		_, err := GrabBanners(tc, "80", 0)
		if err == nil {
			t.Errorf("expected error for target %q, got nil", tc)
		}
	}
}

func TestGrabBanners_InvalidPorts(t *testing.T) {
	cases := []string{
		"80; rm -rf /",
		"$(whoami)",
		"80 443",
	}
	for _, tc := range cases {
		_, err := GrabBanners("localhost", tc, 0)
		if err == nil {
			t.Errorf("expected error for ports %q, got nil", tc)
		}
	}
}

// --- Integration test using a local listener ---

func TestGrabBanners_Integration(t *testing.T) {
	// Start a local TCP server that sends a banner.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()

	portStr := strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("TEST-BANNER-1.0\r\n")) //nolint:errcheck
	}()

	out, err := GrabBanners("127.0.0.1", portStr, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "TEST-BANNER-1.0") {
		t.Errorf("expected banner in output, got:\n%s", out)
	}
}

func TestGrabBanners_ClosedPort(t *testing.T) {
	// Use a port that is very unlikely to be open.
	out, err := GrabBanners("127.0.0.1", "19999", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "closed/filtered") {
		t.Errorf("expected closed/filtered in output, got:\n%s", out)
	}
}
