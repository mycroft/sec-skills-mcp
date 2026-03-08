# sec-skills-mcp

An MCP (Model Context Protocol) server written in Go that provides security tools and skills for penetration testers. It exposes capabilities such as port scanning via `nmap` and DNS enumeration to AI assistants.

> **Important**: Only use these tools against systems you own or have explicit written authorization to test. Unauthorized scanning is illegal.

## Prerequisites

- Go 1.22 or later
- `nmap` installed and available in `PATH` (for the `nmap_scan` tool)
- `whois` installed and available in `PATH` (for the `whois_lookup` tool)

## Installation

### Build from source

```bash
git clone https://github.com/mycroft/sec-skills-mcp.git
cd sec-skills-mcp
go build -o sec-skills-mcp .
```

### Install via `go install`

```bash
go install github.com/mycroft/sec-skills-mcp@latest
```

## Configuration

The server communicates over stdio using the MCP protocol. Configure it in your MCP client (e.g. Claude Desktop) by adding an entry like:

```json
{
  "mcpServers": {
    "sec-skills-mcp": {
      "command": "/path/to/sec-skills-mcp"
    }
  }
}
```

## Tools

### `nmap_scan`

Scan ports on a target host using `nmap`.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target`  | Yes      | Target IP address or hostname |
| `ports`   | No       | Port range (e.g. `80`, `1-1024`, `80,443,8080`). Scans common ports if omitted. |

**Example prompt**: "Scan ports 80 and 443 on 192.168.1.1"

### `dns_lookup`

Perform DNS lookups for a domain, returning A, AAAA, MX, NS, and TXT records.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `domain`  | Yes      | Domain name to query (e.g. `example.com`) |

**Example prompt**: "Look up DNS records for example.com"

### `whois_lookup`

Query WHOIS data for a domain or IP address to gather registrant info, creation dates, and ASN details.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target`  | Yes      | Domain name or IP address to query (e.g. `example.com` or `8.8.8.8`) |

**Example prompt**: "Get WHOIS information for example.com"

### `http_probe`

Probe an HTTP/HTTPS URL to fingerprint web servers: detect technologies via response headers and cookies, record status codes and headers, and optionally check common paths for sensitive resources.

| Parameter        | Required | Description |
|-----------------|----------|-------------|
| `target`         | Yes      | Full URL to probe (e.g. `https://example.com`) |
| `check_paths`    | No       | When `true`, probe common paths such as `/robots.txt`, `/.git/HEAD`, `/admin`, `/.env`, etc. |
| `skip_tls_verify`| No       | When `true`, skip TLS certificate verification (useful for self-signed certificates). |

**Example prompt**: "Probe https://example.com and check common paths for sensitive files"

### `ssl_inspect`

Analyze TLS/SSL certificates and configuration for a host: check certificate expiry, issuer chain, Subject Alternative Names (SANs), weak cipher suites, and supported protocol versions (TLS 1.0/1.1 detection).

| Parameter | Required | Description |
|-----------|----------|-------------|
| `host`    | Yes      | Hostname to inspect (e.g. `example.com`) |
| `port`    | No       | TCP port to connect to (default: `443`) |

**Example prompt**: "Inspect the TLS configuration of example.com"

## Development

```bash
# Install dependencies
go mod tidy

# Build
go build -o sec-skills-mcp .

# Run tests
go test ./...

# Run tests with verbose output
go test -v ./...
```

## Responsible Use

This tool is intended for authorized security testing only. Users are solely responsible for obtaining proper written authorization before scanning any target. Unauthorized use may violate laws including the Computer Fraud and Abuse Act (CFAA) and similar regulations in other jurisdictions.
