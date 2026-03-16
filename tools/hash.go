package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
)

var hexPattern = regexp.MustCompile(`^[a-fA-F0-9]+$`)

var hashReputationTool = ToolDef{
	Name:        "s1_hash_reputation",
	Description: "Hunt a SHA1/SHA256 hash across the fleet via Deep Visibility. Returns endpoints, processes, and file paths where the hash was seen in the last 14 days.",
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"hash"},
		"properties": map[string]any{
			"hash": map[string]any{
				"type":        "string",
				"description": "SHA1 (40 chars) or SHA256 (64 chars) hash to hunt across the fleet via Deep Visibility",
			},
		},
	},
}

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

func handleHashReputation(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		Hash string `json:"hash"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if p.Hash == "" {
		return toolError("hash is required")
	}

	if len(p.Hash) != 40 && len(p.Hash) != 64 {
		return toolError(
			fmt.Sprintf("Invalid hash format. Expected SHA1 (40 chars) or SHA256 (64 chars), got %d chars", len(p.Hash)),
		)
	}
	if !hexPattern.MatchString(p.Hash) {
		return toolError("Invalid hash format. Hash must be hexadecimal characters only.")
	}

	hashField := "SHA1"
	if len(p.Hash) == 64 {
		hashField = "SHA256"
	}
	dvQuery := fmt.Sprintf(`%s = "%s"`, hashField, p.Hash)

	now := time.Now().UTC()
	toDate := now.Format(time.RFC3339)
	fromDate := now.Add(-14 * 24 * time.Hour).Format(time.RFC3339)

	// Retry on 409 (S1 limits concurrent DV queries per token)
	var queryID string
	var err error
	for attempt := range 6 {
		queryID, err = client.CreateDVQuery(ctx, dvQuery, fromDate, toDate, nil, nil, nil)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "409") || attempt == 5 {
			return toolError(fmt.Sprintf("Error hunting hash: %v", err))
		}
		time.Sleep(3 * time.Second)
	}

	if queryID == "" {
		return toolError("DV query slot busy - another query is still processing. Try again shortly.")
	}

	// Poll for completion -- only break on known terminal states.
	var status *client.DVStatus
	for range 30 {
		time.Sleep(1 * time.Second)
		status, err = client.GetDVQueryStatus(ctx, queryID)
		if err != nil {
			return toolError(fmt.Sprintf("Error hunting hash: %v", err))
		}
		switch status.Status {
		case "FINISHED", "FAILED", "CANCELED":
			goto pollDone
		}
	}
pollDone:

	switch status.Status {
	case "FAILED":
		return toolError(fmt.Sprintf("DV hash query failed: %s", fallback(status.ResponseError, "Unknown error")))
	case "CANCELED":
		return toolError("DV hash query was canceled")
	case "FINISHED":
		// continue to fetch events below
	default:
		return toolText(fmt.Sprintf("Query still running after 30s. Use s1_dv_get_events with queryId: %s", queryID))
	}

	// Fetch events with 409 retry
	var events *client.PaginatedResponse
	for attempt := range 5 {
		events, err = client.GetDVEvents(ctx, queryID, 50, "")
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "409") || attempt == 4 {
			return toolError(fmt.Sprintf("Error hunting hash: %v", err))
		}
		time.Sleep(2 * time.Second)
	}

	if events == nil {
		return toolText(fmt.Sprintf("Query completed but events not available after retries. Use s1_dv_get_events with queryId: %s", queryID))
	}

	if len(events.Data) == 0 {
		return toolText(fmt.Sprintf("No activity found for %s %s in the last 14 days.", hashField, p.Hash))
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
		hashField, p.Hash, len(agents), len(events.Data))
	return toolText(header + strings.Join(lines, "\n"))
}
