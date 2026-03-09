package server

import (
	"context"
	"fmt"
	"strconv"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/mycroft/sec-skills-mcp/tools/dns"
	http_probe "github.com/mycroft/sec-skills-mcp/tools/http_probe"
	"github.com/mycroft/sec-skills-mcp/tools/nmap"
	port_service_banner "github.com/mycroft/sec-skills-mcp/tools/port_service_banner"
	ssl_inspect "github.com/mycroft/sec-skills-mcp/tools/ssl_inspect"
	subdomain_enum "github.com/mycroft/sec-skills-mcp/tools/subdomain_enum"
	"github.com/mycroft/sec-skills-mcp/tools/whois"
)

// New creates and returns a configured MCP server with all security tools registered.
func New() *server.MCPServer {
	s := server.NewMCPServer(
		"sec-skills-mcp",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	s.AddTool(mcp.NewTool("nmap_scan",
		mcp.WithDescription("Scan ports on a target host using nmap. Only use against hosts you are authorized to scan."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Target IP address or hostname to scan"),
		),
		mcp.WithString("ports",
			mcp.Description("Port range to scan (e.g. '80', '1-1024', '80,443,8080'). Scans common ports if omitted."),
		),
	), nmapHandler)

	s.AddTool(mcp.NewTool("dns_lookup",
		mcp.WithDescription("Perform DNS lookups for a domain, returning A, AAAA, MX, NS, and TXT records."),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("Domain name to query (e.g. 'example.com')"),
		),
	), dnsHandler)

	s.AddTool(mcp.NewTool("whois_lookup",
		mcp.WithDescription("Query WHOIS data for a domain or IP address to gather registrant info, creation dates, and ASN details. Useful for recon. Only use against targets you are authorized to investigate."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Domain name or IP address to query (e.g. 'example.com' or '8.8.8.8')"),
		),
	), whoisHandler)

	s.AddTool(mcp.NewTool("ssl_inspect",
		mcp.WithDescription("Analyze TLS/SSL certificates and configuration for a host: check certificate expiry, issuer chain, Subject Alternative Names (SANs), weak cipher suites, and supported protocol versions including TLS 1.0/1.1 detection. Only use against hosts you are authorized to test."),
		mcp.WithString("host",
			mcp.Required(),
			mcp.Description("Hostname to inspect (e.g. 'example.com')"),
		),
		mcp.WithString("port",
			mcp.Description("TCP port to connect to (default: 443)"),
		),
	), sslInspectHandler)

	s.AddTool(mcp.NewTool("http_probe",
		mcp.WithDescription("Probe an HTTP/HTTPS target to fingerprint web servers: detect technologies via response headers and cookies, record status codes, and optionally check common paths for sensitive resources. Only use against targets you are authorized to test."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Full URL to probe (e.g. 'https://example.com')"),
		),
		mcp.WithBoolean("check_paths",
			mcp.Description("When true, probe common paths such as /robots.txt, /.git/HEAD, /admin, /.env, etc. Defaults to false."),
		),
		mcp.WithBoolean("skip_tls_verify",
			mcp.Description("When true, skip TLS certificate verification (useful for self-signed certs). Defaults to false."),
		),
	), httpProbeHandler)

	s.AddTool(mcp.NewTool("port_service_banner",
		mcp.WithDescription("Connect to open TCP ports and grab service banners to identify running software and versions. Faster than nmap -sV for targeted banner collection. Only use against hosts you are authorized to test."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Target IP address or hostname"),
		),
		mcp.WithString("ports",
			mcp.Required(),
			mcp.Description("Ports to probe: single port ('22'), comma-separated ('22,80,443'), or range ('8000-8010'). Maximum 256 ports per call."),
		),
		mcp.WithString("timeout",
			mcp.Description("Connection and read timeout in seconds (default: 5)"),
		),
	), portServiceBannerHandler)

	s.AddTool(mcp.NewTool("subdomain_enum",
		mcp.WithDescription("Enumerate subdomains for a domain using certificate transparency logs (crt.sh) or wordlist brute-forcing (gobuster/ffuf). Only use against domains you are authorized to test."),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("Target domain to enumerate subdomains for (e.g. 'example.com')"),
		),
		mcp.WithString("method",
			mcp.Description("Enumeration method: 'crtsh' (certificate transparency logs, default), 'gobuster' (DNS brute-force), or 'ffuf' (HTTP brute-force)"),
		),
		mcp.WithString("wordlist",
			mcp.Description("Path to wordlist file (required for gobuster and ffuf methods)"),
		),
	), subdomainEnumHandler)

	return s
}

func sslInspectHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	host, ok := req.Params.Arguments["host"].(string)
	if !ok || host == "" {
		return mcp.NewToolResultError("host parameter is required"), nil
	}

	port, _ := req.Params.Arguments["port"].(string)

	result, err := ssl_inspect.Inspect(host, port)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("SSL inspection failed: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func nmapHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, ok := req.Params.Arguments["target"].(string)
	if !ok || target == "" {
		return mcp.NewToolResultError("target parameter is required"), nil
	}

	ports, _ := req.Params.Arguments["ports"].(string)

	result, err := nmap.Scan(target, ports)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("nmap scan failed: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func whoisHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, ok := req.Params.Arguments["target"].(string)
	if !ok || target == "" {
		return mcp.NewToolResultError("target parameter is required"), nil
	}

	result, err := whois.Lookup(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("whois lookup failed: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func dnsHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	domain, ok := req.Params.Arguments["domain"].(string)
	if !ok || domain == "" {
		return mcp.NewToolResultError("domain parameter is required"), nil
	}

	result, err := dns.Lookup(domain)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("DNS lookup failed: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func subdomainEnumHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	domain, ok := req.Params.Arguments["domain"].(string)
	if !ok || domain == "" {
		return mcp.NewToolResultError("domain parameter is required"), nil
	}

	method, _ := req.Params.Arguments["method"].(string)
	wordlist, _ := req.Params.Arguments["wordlist"].(string)

	opts := subdomain_enum.EnumOptions{
		Method:   method,
		Wordlist: wordlist,
	}

	result, err := subdomain_enum.Enumerate(domain, opts)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("subdomain enumeration failed: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func httpProbeHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, ok := req.Params.Arguments["target"].(string)
	if !ok || target == "" {
		return mcp.NewToolResultError("target parameter is required"), nil
	}

	checkPaths, _ := req.Params.Arguments["check_paths"].(bool)
	skipTLS, _ := req.Params.Arguments["skip_tls_verify"].(bool)

	opts := http_probe.ProbeOptions{
		CheckPaths:    checkPaths,
		SkipTLSVerify: skipTLS,
	}

	result, err := http_probe.Probe(target, opts)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("HTTP probe failed: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func portServiceBannerHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, ok := req.Params.Arguments["target"].(string)
	if !ok || target == "" {
		return mcp.NewToolResultError("target parameter is required"), nil
	}

	ports, ok := req.Params.Arguments["ports"].(string)
	if !ok || ports == "" {
		return mcp.NewToolResultError("ports parameter is required"), nil
	}

	var timeoutSecs int
	if t, ok := req.Params.Arguments["timeout"].(string); ok && t != "" {
		if n, err := strconv.Atoi(t); err == nil && n > 0 {
			timeoutSecs = n
		}
	}

	result, err := port_service_banner.GrabBanners(target, ports, timeoutSecs)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("banner grab failed: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}
