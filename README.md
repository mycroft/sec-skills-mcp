# sec-skills-mcp

An MCP (Model Context Protocol) server written in Go that provides security tools and skills for penetration testers. It exposes capabilities such as port scanning via `nmap` and DNS enumeration to AI assistants.

> **Important**: Only use these tools against systems you own or have explicit written authorization to test. Unauthorized scanning is illegal.

## Prerequisites

- Go 1.22 or later
- `nmap` installed and available in `PATH` (for the `nmap_scan` tool)

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
