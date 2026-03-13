package tools

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
	"github.com/mark3labs/mcp-go/mcp"
)

var hexPattern = regexp.MustCompile(`^[a-fA-F0-9]+$`)

var hashReputationTool = mcp.NewTool("s1_hash_reputation",
	mcp.WithDescription("Hunt a SHA1/SHA256 hash across the fleet via Deep Visibility. Returns endpoints, processes, and file paths where the hash was seen in the last 14 days."),
	mcp.WithString("hash",
		mcp.Required(),
		mcp.Description("SHA1 (40 chars) or SHA256 (64 chars) hash to hunt across the fleet via Deep Visibility"),
	),
)

func summarizeHashEvent(e map[string]any) string {
	timeStr := "unknown"
	if d := getStr(e, "eventTime"); d != "" {
		timeStr = formatTimeAgo(d)
	}
	eventType := fallback(getStr(e, "eventType"), "Unknown")
	process := fallback(getStr(e, "processName"), "N/A")
	agent := fallback(getStr(e, "agentName"), "Unknown")

	user := getStr(e, "processUser")
	if user == "" {
		user = getStr(e, "user")
	}

	var details string
	if fp := getStr(e, "filePath"); fp != "" {
		details += " | " + truncatePath(fp, 60)
	}
	if cmd := getStr(e, "processCommandLine"); cmd != "" {
		if len(cmd) > 80 {
			cmd = cmd[:80]
		}
		details += " | cmd: " + cmd
	}
	if user != "" {
		details += " | " + user
	}

	return fmt.Sprintf("- %s | %s | %s | %s%s", agent, eventType, process, timeStr, details)
}

func handleHashReputation(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	hash, err := req.RequireString("hash")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if len(hash) != 40 && len(hash) != 64 {
		return mcp.NewToolResultError(
			fmt.Sprintf("Invalid hash format. Expected SHA1 (40 chars) or SHA256 (64 chars), got %d chars", len(hash)),
		), nil
	}
	if !hexPattern.MatchString(hash) {
		return mcp.NewToolResultError("Invalid hash format. Hash must be hexadecimal characters only."), nil
	}

	hashField := "SHA1"
	if len(hash) == 64 {
		hashField = "SHA256"
	}
	dvQuery := fmt.Sprintf(`%s = "%s"`, hashField, hash)

	now := time.Now().UTC()
	toDate := now.Format(time.RFC3339)
	fromDate := now.Add(-14 * 24 * time.Hour).Format(time.RFC3339)

	// Retry on 409 (S1 limits concurrent DV queries per token)
	var queryID string
	for attempt := 0; attempt < 6; attempt++ {
		queryID, err = client.CreateDVQuery(dvQuery, fromDate, toDate, nil, nil, nil)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "409") || attempt == 5 {
			return mcp.NewToolResultError(fmt.Sprintf("Error hunting hash: %v", err)), nil
		}
		time.Sleep(3 * time.Second)
	}

	if queryID == "" {
		return mcp.NewToolResultError(
			"DV query slot busy - another query is still processing. Try again shortly.",
		), nil
	}

	// Poll for completion
	var status *client.DVStatus
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		status, err = client.GetDVQueryStatus(queryID)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error hunting hash: %v", err)), nil
		}
		if status.Status != "RUNNING" {
			break
		}
	}

	if status.Status == "FAILED" {
		return mcp.NewToolResultError(
			fmt.Sprintf("DV hash query failed: %s", fallback(status.ResponseError, "Unknown error")),
		), nil
	}

	if status.Status == "RUNNING" {
		return mcp.NewToolResultText(
			fmt.Sprintf("Query still running after 30s. Use s1_dv_get_events with queryId: %s", queryID),
		), nil
	}

	// Fetch events with 409 retry
	var events *client.PaginatedResponse
	for attempt := 0; attempt < 5; attempt++ {
		events, err = client.GetDVEvents(queryID, 50, "")
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "409") || attempt == 4 {
			return mcp.NewToolResultError(fmt.Sprintf("Error hunting hash: %v", err)), nil
		}
		time.Sleep(2 * time.Second)
	}

	if events == nil {
		return mcp.NewToolResultText(
			fmt.Sprintf("Query completed but events not available after retries. Use s1_dv_get_events with queryId: %s", queryID),
		), nil
	}

	if len(events.Data) == 0 {
		return mcp.NewToolResultText(
			fmt.Sprintf("No activity found for %s %s in the last 14 days.", hashField, hash),
		), nil
	}

	// Deduplicate by agent to show fleet spread
	agents := make(map[string]struct{})
	for _, e := range events.Data {
		agents[fallback(getStr(e, "agentName"), "Unknown")] = struct{}{}
	}

	lines := make([]string, len(events.Data))
	for i, e := range events.Data {
		lines[i] = summarizeHashEvent(e)
	}

	header := fmt.Sprintf("Hash %s %s\nSeen on %d endpoint(s) | %d event(s) in last 14 days:\n\n",
		hashField, hash, len(agents), len(events.Data))
	text := header + strings.Join(lines, "\n")

	return mcp.NewToolResultText(text), nil
}
