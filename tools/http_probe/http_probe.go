package http_probe

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// commonPaths is the list of paths probed when check_paths is requested.
var commonPaths = []string{
	"/robots.txt",
	"/.git/HEAD",
	"/admin",
	"/admin/",
	"/.env",
	"/wp-login.php",
	"/phpmyadmin",
	"/config.php",
	"/.htaccess",
	"/sitemap.xml",
	"/crossdomain.xml",
	"/server-status",
	"/api",
	"/api/v1",
	"/.well-known/security.txt",
}

// techHeaders maps header names to technology labels.
var techHeaders = map[string]string{
	"server":           "Server",
	"x-powered-by":     "X-Powered-By",
	"x-generator":      "Generator",
	"x-drupal-cache":   "Drupal",
	"x-wordpress-id":   "WordPress",
	"x-shopify-stage":  "Shopify",
	"x-magento-vary":   "Magento",
	"cf-ray":           "Cloudflare",
	"x-amz-cf-id":      "AWS CloudFront",
	"x-amz-request-id": "AWS",
	"x-azure-ref":      "Azure CDN",
	"x-varnish":        "Varnish",
	"via":              "Proxy/CDN",
}

// newClient returns an HTTP client configured with a timeout and optional TLS
// verification skip.
func newClient(skipTLS bool) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS}, //nolint:gosec
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		// Do not follow redirects automatically; we report them explicitly.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ProbeOptions controls the behaviour of Probe.
type ProbeOptions struct {
	// CheckPaths probes commonPaths when true.
	CheckPaths bool
	// SkipTLSVerify disables TLS certificate validation.
	SkipTLSVerify bool
}

// Probe performs an HTTP/HTTPS probe against target and returns a formatted
// summary. target must be an http or https URL. Returns an error for invalid
// input; network errors for individual path checks are reported inline.
func Probe(target string, opts ProbeOptions) (string, error) {
	if target == "" {
		return "", fmt.Errorf("target URL must not be empty")
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", target, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid URL scheme %q: only http and https are supported", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid URL %q: host is missing", target)
	}

	client := newClient(opts.SkipTLSVerify)

	var sb strings.Builder

	// --- Main request ---
	fmt.Fprintf(&sb, "Target: %s\n\n", target)

	resp, err := client.Get(target) //nolint:noctx
	if err != nil {
		return "", fmt.Errorf("HTTP request to %q failed: %w", target, err)
	}
	defer resp.Body.Close()

	fmt.Fprintf(&sb, "Status: %s\n", resp.Status)

	// Redirect location
	if loc := resp.Header.Get("Location"); loc != "" {
		fmt.Fprintf(&sb, "Redirect: %s\n", loc)
	}

	// --- Response Headers ---
	sb.WriteString("\nResponse Headers:\n")
	for key, vals := range resp.Header {
		fmt.Fprintf(&sb, "  %s: %s\n", key, strings.Join(vals, ", "))
	}

	// --- Technology Detection ---
	detected := detectTechnologies(resp)
	if len(detected) > 0 {
		sb.WriteString("\nDetected Technologies:\n")
		for _, tech := range detected {
			fmt.Fprintf(&sb, "  %s\n", tech)
		}
	}

	// --- Cookies ---
	if cookies := resp.Cookies(); len(cookies) > 0 {
		sb.WriteString("\nCookies:\n")
		for _, c := range cookies {
			attrs := []string{}
			if c.HttpOnly {
				attrs = append(attrs, "HttpOnly")
			}
			if c.Secure {
				attrs = append(attrs, "Secure")
			}
			if c.SameSite != http.SameSiteDefaultMode {
				attrs = append(attrs, fmt.Sprintf("SameSite=%s", sameSiteString(c.SameSite)))
			}
			attrStr := ""
			if len(attrs) > 0 {
				attrStr = " [" + strings.Join(attrs, ", ") + "]"
			}
			fmt.Fprintf(&sb, "  %s=%s%s\n", c.Name, c.Value, attrStr)
		}
	}

	// --- Common Path Probing ---
	if opts.CheckPaths {
		sb.WriteString("\nCommon Path Probe:\n")
		base := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
		for _, path := range commonPaths {
			pathURL := base + path
			presp, perr := client.Get(pathURL) //nolint:noctx
			if perr != nil {
				fmt.Fprintf(&sb, "  %s -> ERROR (%v)\n", path, perr)
				continue
			}
			presp.Body.Close()
			fmt.Fprintf(&sb, "  %s -> %s\n", path, presp.Status)
		}
	}

	return sb.String(), nil
}

// detectTechnologies inspects the response headers and cookies for technology
// fingerprints and returns a deduplicated list of human-readable labels.
func detectTechnologies(resp *http.Response) []string {
	seen := map[string]bool{}
	var result []string

	add := func(label string) {
		if !seen[label] {
			seen[label] = true
			result = append(result, label)
		}
	}

	for header, label := range techHeaders {
		if val := resp.Header.Get(header); val != "" {
			if label == "Server" || label == "X-Powered-By" || label == "Proxy/CDN" || label == "Generator" {
				add(fmt.Sprintf("%s: %s", label, val))
			} else {
				add(label)
			}
		}
	}

	// Cookie-based tech fingerprinting
	for _, c := range resp.Cookies() {
		name := strings.ToLower(c.Name)
		switch {
		case strings.HasPrefix(name, "phpsessid"):
			add("PHP")
		case strings.HasPrefix(name, "laravel_session"):
			add("Laravel (PHP)")
		case strings.HasPrefix(name, "asp.net_sessionid"), strings.HasPrefix(name, "aspsessionid"):
			add("ASP.NET")
		case strings.HasPrefix(name, "jsessionid"):
			add("Java/J2EE")
		case strings.HasPrefix(name, "wordpress_"):
			add("WordPress")
		case name == "drupal_uid":
			add("Drupal")
		}
	}

	return result
}

func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Default"
	}
}
