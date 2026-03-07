package server

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/mycroft/sec-skills-mcp/tools/dns"
	"github.com/mycroft/sec-skills-mcp/tools/nmap"
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

	return s
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
