package nmap

import (
	"fmt"
	"regexp"

	internexec "github.com/mycroft/sec-skills-mcp/internal/exec"
)

// validTarget allows hostnames and IP addresses (IPv4/IPv6 basic check).
var validTarget = regexp.MustCompile(`^[a-zA-Z0-9._:\[\]-]+$`)

// validPorts allows port numbers, ranges, and comma-separated lists.
var validPorts = regexp.MustCompile(`^[0-9,\-]+$`)

// Scan runs an nmap port scan against target. If ports is non-empty it is
// passed as the -p argument. Returns combined nmap output or an error.
func Scan(target, ports string) (string, error) {
	if err := internexec.LookPath("nmap"); err != nil {
		return "", fmt.Errorf("nmap not found in PATH: %w", err)
	}

	if target == "" {
		return "", fmt.Errorf("target must not be empty")
	}
	if !validTarget.MatchString(target) {
		return "", fmt.Errorf("invalid target %q: only alphanumeric characters, dots, hyphens, colons, and brackets are allowed", target)
	}

	args := []string{target}
	if ports != "" {
		if !validPorts.MatchString(ports) {
			return "", fmt.Errorf("invalid port range %q: only digits, commas, and hyphens are allowed", ports)
		}
		args = append([]string{"-p", ports}, args...)
	}

	return internexec.Run("nmap", args...)
}
