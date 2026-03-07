package main

import (
	"log"

	"github.com/mark3labs/mcp-go/server"

	mcpserver "github.com/mycroft/sec-skills-mcp/server"
)

func main() {
	s := mcpserver.New()
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
