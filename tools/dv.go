package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
	"github.com/mark3labs/mcp-go/mcp"
)

var dvQueryTool = mcp.NewTool("s1_dv_query",
	mcp.WithDescription(`Run a Deep Visibility query. Returns queryId when complete.

Query syntax:
  <Field> <Operator> "<Value>" [AND|OR <Field> <Operator> "<Value>" ...]

Operators: Contains, ContainsCIS (case-insensitive), =, !=, In, NotIn, StartsWith, EndsWith, RegExp

Common fields:
  Process:  ProcessName, SrcProcImagePath, TgtProcImagePath, SrcProcCmdLine, SrcProcUser
  File:     FilePath, FileFullName, FileSHA256, FileMD5
  Network:  SrcIP, DstIP, DstPort, DnsRequest, Url
  Event:    EventType (values: "Process Creation", "File Creation", "File Modification",
            "File Deletion", "File Rename", "DNS Resolved", "IP Connect",
            "Behavioral Indicators", "Registry Key Creation", "Registry Value Modified")

Examples:
  ProcessName Contains "python"
  SrcProcImagePath Contains "/Downloads/" AND EventType = "Process Creation"
  DnsRequest Contains "evil.com" OR DstIP = "1.2.3.4"

Query strategy:
  - Combine related conditions into ONE query using OR instead of running multiple
    parallel queries. The S1 API rate-limits query creation aggressively.
    Bad:  3 separate queries for /tmp/, /Downloads/, /Desktop/
    Good: SrcProcImagePath Contains "/tmp/" OR SrcProcImagePath Contains "/Downloads/" OR SrcProcImagePath Contains "/Desktop/"
  - Use AND to narrow broad queries (e.g., add EventType = "Process Creation")
  - Use In/NotIn for matching against a list of values:
    ProcessName In ("cmd.exe","powershell.exe","pwsh.exe")
  - For exclusions, prefer NotIn over multiple != conditions:
    ProcessName NotIn ("chrome.exe","bash","node","svchost.exe")

Limitations:
  - Do NOT use ObjectType as a field (not supported in DV queries)
  - Avoid trailing backslashes in values (e.g., "\\Desktop\\" breaks the parser).
    Use "\\Desktop" or ContainsCIS instead
  - Complex nested parentheses may fail — prefer flat AND/OR chains
  - Max query window is 14 days`),
	mcp.WithString("query",
		mcp.Required(),
		mcp.Description(`Deep Visibility query string. See tool description for syntax and valid fields.`),
	),
	mcp.WithString("fromDate",
		mcp.Required(),
		mcp.Description("Start date in ISO format (e.g., 2024-01-01T00:00:00Z)"),
	),
	mcp.WithString("toDate",
		mcp.Required(),
		mcp.Description("End date in ISO format (e.g., 2024-01-02T00:00:00Z)"),
	),
	mcp.WithArray("siteIds",
		mcp.Description("Filter by site IDs"),
		mcp.Items(map[string]any{"type": "string"}),
	),
	mcp.WithArray("groupIds",
		mcp.Description("Filter by group IDs"),
		mcp.Items(map[string]any{"type": "string"}),
	),
	mcp.WithArray("accountIds",
		mcp.Description("Filter by account IDs"),
		mcp.Items(map[string]any{"type": "string"}),
	),
)

var dvGetEventsTool = mcp.NewTool("s1_dv_get_events",
	mcp.WithDescription("Get events from a completed Deep Visibility query"),
	mcp.WithString("queryId",
		mcp.Required(),
		mcp.Description("Query ID returned from s1_dv_query"),
	),
	mcp.WithNumber("limit",
		mcp.Description("Max results (default 50, max 100)"),
	),
	mcp.WithString("cursor",
		mcp.Description("Pagination cursor"),
	),
)

func summarizeEvent(e map[string]any) string {
	timeStr := "unknown"
	if d := getStr(e, "eventTime"); d != "" {
		timeStr = formatTimeAgo(d)
	}
	eventType := fallback(getStr(e, "eventType"), "Unknown")
	process := fallback(getStr(e, "processName"), "N/A")
	agent := fallback(getStr(e, "agentName"), "Unknown")

	var details string
	srcIP := getStr(e, "srcIp")
	dstIP := getStr(e, "dstIp")
	dstPort := getStr(e, "dstPort")
	if dstPort == "" {
		dstPort = "?"
	}

	if srcIP != "" && dstIP != "" {
		details += fmt.Sprintf(" | %s -> %s:%s", srcIP, dstIP, dstPort)
	} else if dstIP != "" {
		details += fmt.Sprintf(" -> %s:%s", dstIP, dstPort)
	}
	if fp := getStr(e, "filePath"); fp != "" {
		details += " | " + truncatePath(fp, 60)
	}
	if dns := getStr(e, "dnsRequest"); dns != "" {
		details += " | DNS: " + dns
	}
	if user := getStr(e, "user"); user != "" {
		details += " | User: " + user
	}

	return fmt.Sprintf("- %s | %s | %s | %s%s", eventType, agent, process, timeStr, details)
}

// invalidDVFields lists field names that are commonly confused with valid DV fields.
var invalidDVFields = []string{"ObjectType", "ObjectName"}

// validateDVQuery checks for common query mistakes before sending to the API.
func validateDVQuery(query string) error {
	for _, field := range invalidDVFields {
		// Check for "FieldName <operator>" pattern (field used as a query field)
		if strings.Contains(query, field+" ") {
			return fmt.Errorf("%q is not a valid Deep Visibility field. Use EventType to filter by event type, or SrcProcImagePath / ProcessName for process filtering", field)
		}
	}

	// Check for trailing backslash before closing quote (breaks S1 parser)
	if strings.Contains(query, `\"`) {
		return fmt.Errorf("query contains backslash-quote sequence which will break the S1 parser. Avoid trailing backslashes in quoted values")
	}

	return nil
}

func handleDVQuery(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	fromDate, err := req.RequireString("fromDate")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	toDate, err := req.RequireString("toDate")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if err := validateDVQuery(query); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid query: %v", err)), nil
	}

	siteIDs := req.GetStringSlice("siteIds", nil)
	groupIDs := req.GetStringSlice("groupIds", nil)
	accountIDs := req.GetStringSlice("accountIds", nil)

	queryID, err := client.CreateDVQuery(query, fromDate, toDate, siteIDs, groupIDs, accountIDs)
	if err != nil {
		return mcp.NewToolResultError(
			fmt.Sprintf("Error running Deep Visibility query: %v", err),
		), nil
	}

	// Poll for completion
	var status *client.DVStatus
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		status, err = client.GetDVQueryStatus(queryID)
		if err != nil {
			return mcp.NewToolResultError(
				fmt.Sprintf("Error running Deep Visibility query: %v", err),
			), nil
		}
		if status.Status != "RUNNING" {
			break
		}
	}

	if status.Status == "FAILED" {
		return mcp.NewToolResultError(
			fmt.Sprintf("Deep Visibility query failed: %s", fallback(status.ResponseError, "Unknown error")),
		), nil
	}

	if status.Status == "RUNNING" {
		return mcp.NewToolResultText(
			fmt.Sprintf("Query still running after 30 seconds. Use s1_dv_get_events with queryId: %s to retrieve results later.", queryID),
		), nil
	}

	result := map[string]string{
		"queryId": queryID,
		"status":  status.Status,
		"message": "Query completed. Use s1_dv_get_events to retrieve results.",
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(b)), nil
}

func handleDVGetEvents(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	queryID, err := req.RequireString("queryId")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	limit := int(req.GetFloat("limit", 50))
	if limit < 1 || limit > 100 {
		limit = 50
	}
	cursor := req.GetString("cursor", "")

	// Check query status first
	status, err := client.GetDVQueryStatus(queryID)
	if err != nil {
		return mcp.NewToolResultError(
			fmt.Sprintf("Error getting Deep Visibility events: %v", err),
		), nil
	}

	switch status.Status {
	case "RUNNING":
		return mcp.NewToolResultText(
			fmt.Sprintf("Query %s is still running (%d%% complete). Please wait and try again.",
				queryID, status.ProgressStatus),
		), nil
	case "FAILED":
		return mcp.NewToolResultError(
			fmt.Sprintf("Query %s failed: %s", queryID, fallback(status.ResponseError, "Unknown error")),
		), nil
	case "CANCELED":
		return mcp.NewToolResultError(
			fmt.Sprintf("Query %s was canceled", queryID),
		), nil
	}

	result, err := client.GetDVEvents(queryID, limit, cursor)
	if err != nil {
		return mcp.NewToolResultError(
			fmt.Sprintf("Error getting Deep Visibility events: %v", err),
		), nil
	}

	if len(result.Data) == 0 {
		return mcp.NewToolResultText("No events found for this query."), nil
	}

	lines := make([]string, len(result.Data))
	for i, e := range result.Data {
		lines[i] = summarizeEvent(e)
	}

	text := fmt.Sprintf("Found %d event(s):\n\n%s", len(result.Data), strings.Join(lines, "\n"))
	if result.Pagination != nil && result.Pagination.NextCursor != "" {
		text += fmt.Sprintf("\n\n[More results available - use cursor: %s]", result.Pagination.NextCursor)
	}

	return mcp.NewToolResultText(text), nil
}
