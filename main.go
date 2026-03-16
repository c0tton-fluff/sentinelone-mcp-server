package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/c0tton-fluff/sentinelone-mcp-server/config"
)

func main() {
	if _, err := config.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	startWatchdog()

	ctx := context.Background()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}

		resp := HandleRequest(ctx, req)
		if resp == nil {
			continue
		}

		if err := encoder.Encode(resp); err != nil {
			fmt.Fprintf(os.Stderr, "encode response: %v\n", err)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "stdin read error: %v\n", err)
	}
}

// startWatchdog auto-exits when the parent process dies, preventing zombie MCP servers.
func startWatchdog() {
	ppid := os.Getppid()
	go func() {
		for {
			time.Sleep(5 * time.Second)
			if err := syscall.Kill(ppid, 0); err != nil {
				os.Exit(0)
			}
		}
	}()
}
