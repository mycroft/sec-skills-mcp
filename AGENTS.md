# AGENTS.md - AI Agent Guidelines for sec-skills-mcp

This document guides AI agents in building and maintaining the `sec-skills-mcp` project.

## Project Overview

`sec-skills-mcp` is an MCP (Model Context Protocol) server written in Go that provides security tools and skills for penetration testers. It exposes capabilities such as:

- Port scanning via `nmap`
- Domain enumeration (DNS, subdomains)
- Other reconnaissance and security assessment tools

The server follows the [MCP specification](https://modelcontextprotocol.io/) and is designed to be used by AI assistants to perform authorized security testing.

## Project Principles

- **Simple**: Keep code straightforward. Avoid over-engineering. Prefer clarity over cleverness.
- **Go idiomatic**: Follow standard Go conventions and project layout.
- **Tested**: All tools and significant logic must have unit and/or integration tests.
- **Documented**: README must make installation and use easy for end users.
- **Security-conscious**: Never introduce vulnerabilities. Validate inputs at system boundaries.

## Repository Structure

```
sec-skills-mcp/
├── AGENTS.md           # This file
├── README.md           # User-facing documentation
├── go.mod              # Go module definition
├── go.sum              # Dependency checksums
├── main.go             # Entry point
├── server/             # MCP server setup and tool registration
│   └── server.go
├── tools/              # Individual security tool implementations
│   ├── nmap/
│   │   ├── nmap.go
│   │   └── nmap_test.go
│   └── dns/
│       ├── dns.go
│       └── dns_test.go
└── internal/           # Shared utilities (command execution, output parsing)
    └── exec/
        └── exec.go
```

## Language and Runtime

- **Language**: Go (latest stable version)
- **Module path**: `github.com/mycroft/sec-skills-mcp`
- **MCP SDK**: Use `github.com/mark3labs/mcp-go` for MCP server implementation

## Development Setup

```bash
# Install dependencies
go mod tidy

# Build the binary
go build -o sec-skills-mcp .

# Run tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run the server
./sec-skills-mcp
```

## Adding a New Tool

To add a new security tool:

1. Create a new directory under `tools/<toolname>/`
2. Implement the tool in `tools/<toolname>/<toolname>.go`:
   - Define an `Execute(params map[string]string) (string, error)` function (or equivalent)
   - Validate all user-supplied inputs before passing to system calls
   - Use `internal/exec` utilities for running external commands
3. Write tests in `tools/<toolname>/<toolname>_test.go`
4. Register the tool in `server/server.go` using the MCP SDK
5. Update `README.md` with usage instructions for the new tool

## Code Conventions

- Use `gofmt` formatting (enforced by default Go tooling)
- Error handling: always return errors; do not panic in tool code
- Avoid global state; pass configuration explicitly
- External binaries (e.g., `nmap`) must be checked for presence at startup or gracefully return an error if missing
- Keep functions small and focused; prefer composition

## Testing Requirements

- Each tool package must have a `_test.go` file
- Tests should cover:
  - Valid inputs produce expected output format
  - Invalid inputs return errors (not panics)
  - Missing external binaries are handled gracefully
- Use `go test ./...` to run the full suite
- Integration tests that require external tools (nmap, etc.) should be skipped if the binary is not available:
  ```go
  if _, err := exec.LookPath("nmap"); err != nil {
      t.Skip("nmap not found, skipping integration test")
  }
  ```

## MCP Tool Registration Pattern

```go
// Example tool registration in server/server.go
s.AddTool(mcp.NewTool("nmap_scan",
    mcp.WithDescription("Scan ports on a target host using nmap"),
    mcp.WithString("target", mcp.Required(), mcp.Description("Target IP or hostname")),
    mcp.WithString("ports", mcp.Description("Port range (e.g. '1-1024', '80,443')")),
), nmapHandler)
```

## Security Guidelines

- **Input validation**: Always validate and sanitize tool parameters before use in shell commands. Never pass raw user input to `exec.Command` as a shell string — always use argument arrays.
- **No shell injection**: Use `exec.Command("nmap", args...)` not `exec.Command("sh", "-c", "nmap "+input)`.
- **Least privilege**: The server should be run with minimal OS privileges.
- **Scope**: Only implement tools useful for authorized penetration testing. Document that users are responsible for obtaining proper authorization.

## README Requirements

The `README.md` must include:

1. Project description
2. Prerequisites (Go version, external tools like nmap)
3. Installation instructions (`go install` or build from source)
4. Configuration (if any)
5. Usage examples for each tool
6. A note about responsible and authorized use

## Commit and PR Guidelines

- Use conventional commit messages: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`
- Keep commits focused; one logical change per commit
- All tests must pass before opening a PR (`go test ./...`)
- PRs should update `README.md` if user-facing behavior changes
