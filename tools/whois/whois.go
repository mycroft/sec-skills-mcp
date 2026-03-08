package whois

import (
	"fmt"
	"regexp"

	internexec "github.com/mycroft/sec-skills-mcp/internal/exec"
)

// validTarget allows domain names and IP addresses (IPv4/IPv6).
var validTarget = regexp.MustCompile(`^[a-zA-Z0-9._:\[\]-]+$`)

// Lookup runs a whois query against target (domain or IP address) and returns
// the raw whois output. Returns an error if the target is invalid or if the
// whois binary is not available.
func Lookup(target string) (string, error) {
	if err := internexec.LookPath("whois"); err != nil {
		return "", fmt.Errorf("whois not found in PATH: %w", err)
	}

	if target == "" {
		return "", fmt.Errorf("target must not be empty")
	}
	if !validTarget.MatchString(target) {
		return "", fmt.Errorf("invalid target %q: only alphanumeric characters, dots, hyphens, colons, and brackets are allowed", target)
	}

	return internexec.Run("whois", target)
}
