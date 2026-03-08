package subdomain_enum

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	internexec "github.com/mycroft/sec-skills-mcp/internal/exec"
)

// validDomain restricts input to safe domain name characters.
var validDomain = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// validPath allows safe file system path characters for wordlist paths.
var validPath = regexp.MustCompile(`^[a-zA-Z0-9._/\-]+$`)

// crtshEntry represents a single entry from the crt.sh JSON response.
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// EnumOptions holds configuration for subdomain enumeration.
type EnumOptions struct {
	// Method selects the enumeration method: "crtsh", "gobuster", or "ffuf".
	// Defaults to "crtsh" if empty.
	Method string
	// Wordlist is the path to the wordlist file (required for gobuster and ffuf).
	Wordlist string
}

// Enumerate discovers subdomains for domain using the configured method.
func Enumerate(domain string, opts EnumOptions) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("domain must not be empty")
	}
	if !validDomain.MatchString(domain) {
		return "", fmt.Errorf("invalid domain %q: only alphanumeric characters, dots, and hyphens are allowed", domain)
	}

	method := opts.Method
	if method == "" {
		method = "crtsh"
	}

	switch method {
	case "crtsh":
		return enumCrtsh(domain)
	case "gobuster":
		return enumGobuster(domain, opts.Wordlist)
	case "ffuf":
		return enumFfuf(domain, opts.Wordlist)
	default:
		return "", fmt.Errorf("unknown method %q: must be one of crtsh, gobuster, ffuf", method)
	}
}

// enumCrtsh queries the crt.sh certificate transparency log API to discover subdomains.
func enumCrtsh(domain string) (string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("crt.sh returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading crt.sh response: %w", err)
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return "", fmt.Errorf("parsing crt.sh JSON response: %w", err)
	}

	// Deduplicate and collect subdomains.
	seen := make(map[string]struct{})
	for _, e := range entries {
		// name_value can contain multiple names separated by newlines.
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			// Skip wildcards and entries that are not subdomains of the target.
			if strings.HasPrefix(name, "*.") {
				name = name[2:]
			}
			if name == "" || name == domain {
				continue
			}
			// Only keep actual subdomains of the target domain.
			if !strings.HasSuffix(name, "."+domain) {
				continue
			}
			seen[name] = struct{}{}
		}
	}

	if len(seen) == 0 {
		return fmt.Sprintf("No subdomains found for %s via crt.sh\n", domain), nil
	}

	subdomains := make([]string, 0, len(seen))
	for s := range seen {
		subdomains = append(subdomains, s)
	}
	sort.Strings(subdomains)

	var sb strings.Builder
	fmt.Fprintf(&sb, "Subdomains found for %s via crt.sh (%d):\n", domain, len(subdomains))
	for _, s := range subdomains {
		fmt.Fprintf(&sb, "  %s\n", s)
	}
	return sb.String(), nil
}

// enumGobuster runs gobuster in DNS mode to brute-force subdomains.
func enumGobuster(domain, wordlist string) (string, error) {
	if err := internexec.LookPath("gobuster"); err != nil {
		return "", fmt.Errorf("gobuster not found in PATH: %w", err)
	}
	if wordlist == "" {
		return "", fmt.Errorf("wordlist path is required for gobuster method")
	}
	if !validPath.MatchString(wordlist) {
		return "", fmt.Errorf("invalid wordlist path %q", wordlist)
	}

	output, err := internexec.Run("gobuster", "dns", "-d", domain, "-w", wordlist, "--no-color")
	if err != nil {
		// gobuster exits non-zero even on partial results; return output regardless.
		if output != "" {
			return fmt.Sprintf("gobuster output (exit error: %v):\n%s", err, output), nil
		}
		return "", fmt.Errorf("gobuster failed: %w", err)
	}
	if output == "" {
		return fmt.Sprintf("No subdomains found for %s via gobuster\n", domain), nil
	}
	return output, nil
}

// enumFfuf runs ffuf to brute-force subdomains via DNS resolution.
func enumFfuf(domain, wordlist string) (string, error) {
	if err := internexec.LookPath("ffuf"); err != nil {
		return "", fmt.Errorf("ffuf not found in PATH: %w", err)
	}
	if wordlist == "" {
		return "", fmt.Errorf("wordlist path is required for ffuf method")
	}
	if !validPath.MatchString(wordlist) {
		return "", fmt.Errorf("invalid wordlist path %q", wordlist)
	}

	// Use ffuf with a virtual-host style URL pattern. The -fs flag filters by
	// response size to reduce false positives; we keep all responses here and
	// let the caller decide. -mc all captures all status codes.
	url := fmt.Sprintf("http://FUZZ.%s", domain)
	output, err := internexec.Run("ffuf", "-w", wordlist+":FUZZ", "-u", url, "-mc", "all", "-of", "json")
	if err != nil {
		if output != "" {
			return fmt.Sprintf("ffuf output (exit error: %v):\n%s", err, output), nil
		}
		return "", fmt.Errorf("ffuf failed: %w", err)
	}
	if output == "" {
		return fmt.Sprintf("No subdomains found for %s via ffuf\n", domain), nil
	}
	return output, nil
}
