package dns

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// validDomain restricts input to safe domain name characters.
var validDomain = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// Lookup performs A/AAAA, MX, NS, and TXT DNS lookups for domain and returns
// a human-readable summary. An error is returned only for invalid input; DNS
// resolution failures for individual record types are silently skipped so that
// partial results are still returned.
func Lookup(domain string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("domain must not be empty")
	}
	if !validDomain.MatchString(domain) {
		return "", fmt.Errorf("invalid domain %q: only alphanumeric characters, dots, hyphens are allowed", domain)
	}

	var sb strings.Builder

	// A / AAAA records
	addrs, err := net.LookupHost(domain)
	if err == nil && len(addrs) > 0 {
		sb.WriteString("A/AAAA records:\n")
		for _, addr := range addrs {
			fmt.Fprintf(&sb, "  %s\n", addr)
		}
	}

	// MX records
	mxRecords, err := net.LookupMX(domain)
	if err == nil && len(mxRecords) > 0 {
		sb.WriteString("MX records:\n")
		for _, mx := range mxRecords {
			fmt.Fprintf(&sb, "  %s (priority %d)\n", mx.Host, mx.Pref)
		}
	}

	// NS records
	nsRecords, err := net.LookupNS(domain)
	if err == nil && len(nsRecords) > 0 {
		sb.WriteString("NS records:\n")
		for _, ns := range nsRecords {
			fmt.Fprintf(&sb, "  %s\n", ns.Host)
		}
	}

	// TXT records
	txtRecords, err := net.LookupTXT(domain)
	if err == nil && len(txtRecords) > 0 {
		sb.WriteString("TXT records:\n")
		for _, txt := range txtRecords {
			fmt.Fprintf(&sb, "  %s\n", txt)
		}
	}

	if sb.Len() == 0 {
		return fmt.Sprintf("No DNS records found for %s\n", domain), nil
	}
	return sb.String(), nil
}
