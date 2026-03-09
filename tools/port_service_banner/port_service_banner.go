package port_service_banner

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// validTarget allows hostnames and IP addresses.
var validTarget = regexp.MustCompile(`^[a-zA-Z0-9._:\[\]-]+$`)

// validPorts allows port numbers, ranges, and comma-separated lists.
var validPorts = regexp.MustCompile(`^[0-9,\-]+$`)

// defaultTimeout is the default connection and read timeout.
const defaultTimeout = 5 * time.Second

// maxBannerBytes is the maximum number of bytes to read per banner.
const maxBannerBytes = 4096

// BannerResult holds the result for a single port.
type BannerResult struct {
	Port   int
	Banner string
	Err    error
}

// GrabBanners connects to each port on target and reads the service banner.
// ports is a comma-separated list of port numbers or ranges (e.g. "22,80,8080" or "8000-8010").
// timeoutSecs controls the TCP connect and read deadline; 0 uses the default of 5 seconds.
func GrabBanners(target, ports string, timeoutSecs int) (string, error) {
	if target == "" {
		return "", fmt.Errorf("target must not be empty")
	}
	if !validTarget.MatchString(target) {
		return "", fmt.Errorf("invalid target %q: only alphanumeric characters, dots, hyphens, colons, and brackets are allowed", target)
	}
	if ports == "" {
		return "", fmt.Errorf("ports must not be empty")
	}
	if !validPorts.MatchString(ports) {
		return "", fmt.Errorf("invalid ports %q: only digits, commas, and hyphens are allowed", ports)
	}

	timeout := defaultTimeout
	if timeoutSecs > 0 {
		timeout = time.Duration(timeoutSecs) * time.Second
	}

	portList, err := parsePorts(ports)
	if err != nil {
		return "", err
	}
	if len(portList) == 0 {
		return "", fmt.Errorf("no valid ports specified")
	}
	if len(portList) > 256 {
		return "", fmt.Errorf("too many ports: maximum 256 ports per call")
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Banner Grab: %s\n\n", target)

	for _, port := range portList {
		result := grabBanner(target, port, timeout)
		fmt.Fprintf(&sb, "Port %d/tcp\n", result.Port)
		if result.Err != nil {
			fmt.Fprintf(&sb, "  Status: closed/filtered (%v)\n", result.Err)
		} else if result.Banner == "" {
			fmt.Fprintf(&sb, "  Status: open (no banner received)\n")
		} else {
			fmt.Fprintf(&sb, "  Status: open\n")
			fmt.Fprintf(&sb, "  Banner: %s\n", result.Banner)
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

// grabBanner connects to target:port, reads the initial banner, and returns the result.
// For ports that don't send a banner spontaneously a generic probe is sent.
func grabBanner(target string, port int, timeout time.Duration) BannerResult {
	addr := net.JoinHostPort(target, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return BannerResult{Port: port, Err: err}
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return BannerResult{Port: port, Err: fmt.Errorf("set deadline: %w", err)}
	}

	// Read initial banner.
	buf := make([]byte, maxBannerBytes)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		// Many services don't send a banner first — send a generic probe and try again.
		conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck
		_, writeErr := fmt.Fprintf(conn, "\r\n")
		if writeErr != nil {
			// Port is open but unresponsive — that's still interesting.
			return BannerResult{Port: port, Banner: ""}
		}
		n, err = conn.Read(buf)
		if err != nil && err != io.EOF {
			return BannerResult{Port: port, Banner: ""}
		}
	}

	banner := sanitizeBanner(buf[:n])
	return BannerResult{Port: port, Banner: banner}
}

// sanitizeBanner cleans up raw banner bytes into a single, printable line.
// Non-printable characters are replaced with dots; leading/trailing whitespace
// is trimmed. A multi-line banner is collapsed to its first non-empty line.
func sanitizeBanner(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	// Replace non-printable characters (except common whitespace) with dots.
	cleaned := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return '\n'
		}
		if unicode.IsPrint(r) || r == '\t' {
			return r
		}
		return '.'
	}, string(raw))

	// Return the first non-empty line.
	for _, line := range strings.Split(cleaned, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

// parsePorts parses a port specification string into a sorted list of port numbers.
// Supports individual ports ("80"), ranges ("8000-8010"), and comma-separated lists.
func parsePorts(spec string) ([]int, error) {
	seen := make(map[int]bool)
	var ports []int

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid port range %q: ports must be between 1 and 65535 with low <= high", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port %q: must be a number between 1 and 65535", part)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	return ports, nil
}
