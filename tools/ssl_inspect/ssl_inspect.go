package ssl_inspect

import (
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// validHost restricts input to safe hostname characters.
var validHost = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// Inspect performs TLS/SSL inspection on the given host and port and returns a
// human-readable summary covering:
//   - Leaf certificate details (subject, issuer, expiry, SANs)
//   - Certificate chain
//   - Supported TLS protocol versions (with warnings for TLS 1.0/1.1)
//   - Weak cipher suite support
func Inspect(host, port string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("host must not be empty")
	}
	if !validHost.MatchString(host) {
		return "", fmt.Errorf("invalid host %q: only alphanumeric characters, dots, and hyphens are allowed", host)
	}

	if port == "" {
		port = "443"
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("invalid port %q: must be a number between 1 and 65535", port)
	}

	addr := net.JoinHostPort(host, port)
	var sb strings.Builder

	fmt.Fprintf(&sb, "SSL/TLS Inspection: %s\n\n", addr)

	// Connect with verification first; fall back to InsecureSkipVerify so we
	// can still inspect the certificate even when it is self-signed or expired.
	conn, certErr := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		addr,
		&tls.Config{ServerName: host},
	)
	if certErr != nil {
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp",
			addr,
			&tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true, //nolint:gosec
			},
		)
		if err != nil {
			return "", fmt.Errorf("failed to connect to %s: %w", addr, err)
		}
		fmt.Fprintf(&sb, "WARNING: Certificate verification failed: %v\n\n", certErr)
	}

	state := conn.ConnectionState()
	conn.Close()

	// --- Leaf certificate ---
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]

		sb.WriteString("=== Leaf Certificate ===\n")
		fmt.Fprintf(&sb, "Subject CN:  %s\n", leaf.Subject.CommonName)
		fmt.Fprintf(&sb, "Issuer CN:   %s\n", leaf.Issuer.CommonName)
		fmt.Fprintf(&sb, "Valid From:  %s\n", leaf.NotBefore.UTC().Format(time.RFC3339))
		fmt.Fprintf(&sb, "Valid Until: %s\n", leaf.NotAfter.UTC().Format(time.RFC3339))

		daysLeft := time.Until(leaf.NotAfter).Hours() / 24
		switch {
		case daysLeft < 0:
			fmt.Fprintf(&sb, "Expiry:      EXPIRED (%.0f days ago)\n", -daysLeft)
		case daysLeft < 14:
			fmt.Fprintf(&sb, "Expiry:      CRITICAL – expires in %.0f days\n", daysLeft)
		case daysLeft < 30:
			fmt.Fprintf(&sb, "Expiry:      WARNING – expires in %.0f days\n", daysLeft)
		default:
			fmt.Fprintf(&sb, "Expiry:      OK (%.0f days remaining)\n", daysLeft)
		}

		// Subject Alternative Names
		var sans []string
		sans = append(sans, leaf.DNSNames...)
		for _, ip := range leaf.IPAddresses {
			sans = append(sans, ip.String())
		}
		for _, uri := range leaf.URIs {
			sans = append(sans, uri.String())
		}
		if len(sans) > 0 {
			sb.WriteString("SANs:\n")
			for _, san := range sans {
				fmt.Fprintf(&sb, "  %s\n", san)
			}
		}

		// --- Certificate chain ---
		if len(state.PeerCertificates) > 1 {
			sb.WriteString("\n=== Certificate Chain ===\n")
			for i, cert := range state.PeerCertificates {
				role := "Intermediate CA"
				if i == 0 {
					role = "Leaf"
				} else if cert.IsCA && i == len(state.PeerCertificates)-1 {
					role = "Root CA"
				}
				fmt.Fprintf(&sb, "[%d] %-15s %s\n", i, role, cert.Subject.CommonName)
				if cert.Issuer.CommonName != cert.Subject.CommonName {
					fmt.Fprintf(&sb, "         Issuer: %s\n", cert.Issuer.CommonName)
				}
			}
		}
	}

	// --- Protocol version support ---
	sb.WriteString("\n=== Protocol Version Support ===\n")
	protos := []struct {
		name     string
		version  uint16
		insecure bool
	}{
		{"TLS 1.0", tls.VersionTLS10, true},
		{"TLS 1.1", tls.VersionTLS11, true},
		{"TLS 1.2", tls.VersionTLS12, false},
		{"TLS 1.3", tls.VersionTLS13, false},
	}
	for _, p := range protos {
		if checkProtocolVersion(addr, host, p.version) {
			if p.insecure {
				fmt.Fprintf(&sb, "  %-8s SUPPORTED (INSECURE – should be disabled)\n", p.name)
			} else {
				fmt.Fprintf(&sb, "  %-8s Supported\n", p.name)
			}
		} else {
			fmt.Fprintf(&sb, "  %-8s Not supported\n", p.name)
		}
	}

	// --- Weak cipher suite detection ---
	sb.WriteString("\n=== Weak Cipher Suite Detection ===\n")
	weakFound := false
	for _, cs := range tls.InsecureCipherSuites() {
		if checkCipherSuite(addr, host, cs.ID) {
			fmt.Fprintf(&sb, "  WEAK: %s\n", cs.Name)
			weakFound = true
		}
	}
	if !weakFound {
		sb.WriteString("  No weak cipher suites detected\n")
	}

	return sb.String(), nil
}

// checkProtocolVersion attempts a TLS handshake pinned to exactly version and
// returns true if the server accepts it.
func checkProtocolVersion(addr, host string, version uint16) bool {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec
			MinVersion:         version,
			MaxVersion:         version,
		},
	)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// checkCipherSuite attempts a TLS 1.2 handshake offering only cipherID and
// returns true if the server negotiates it.  TLS 1.3 has fixed cipher suites
// so weak-cipher testing only applies to TLS 1.2 and below.
func checkCipherSuite(addr, host string, cipherID uint16) bool {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,            //nolint:gosec
			MinVersion:         tls.VersionTLS10, //nolint:gosec
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{cipherID},
		},
	)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
