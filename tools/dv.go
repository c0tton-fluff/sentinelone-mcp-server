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

IMPORTANT: Do NOT run multiple s1_dv_query calls in parallel. The S1 API
aggressively rate-limits query creation per token. Run DV queries sequentially
and combine related searches into a single query using OR chains.

Query syntax:
  <Field> <Operator> "<Value>" [AND|OR <Field> <Operator> "<Value>" ...]

Operators: Contains, Contains Anycase (case-insensitive), ContainsCIS (alias),
            =, !=, In, In Anycase, In Contains Anycase, NotIn, StartsWith, EndsWith, RegExp

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
    Use "\\Desktop" or Contains Anycase instead
  - Use parentheses to group when mixing AND/OR: A AND (B OR C OR D)
  - Nested parentheses are supported: A AND (B OR (C AND D))
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
	mcp.WithDescription(`Get events from a completed Deep Visibility query.

IMPORTANT: Run s1_dv_get_events calls sequentially, not in parallel. The S1 API
shares rate limits across all endpoints per token.`),
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

// fixBackslashesInDVValues strips backslashes from quoted string values in a
// DV query. The S1 DV query parser has no backslash escape mechanism in string
// literals, so bare backslashes cause parse errors — especially trailing \"
// which swallows the closing quote. Stripping backslashes makes Contains matches
// slightly broader (e.g., "\Temp" → "Temp") but never narrower.
//
// Backslashes inside RegExp values are preserved (regex syntax needs them).
func fixBackslashesInDVValues(query string) (string, bool) {
	var b strings.Builder
	b.Grow(len(query))
	modified := false
	i := 0
	isRegExp := false

	for i < len(query) {
		// Detect RegExp operator immediately before a quoted value.
		if i+7 <= len(query) && query[i:i+7] == "RegExp " {
			b.WriteString("RegExp ")
			i += 7
			isRegExp = true
			continue
		}

		if query[i] == '"' {
			b.WriteByte('"')
			i++
			// Inside a quoted value — strip backslashes unless RegExp.
			for i < len(query) && query[i] != '"' {
				if query[i] == '\\' && !isRegExp {
					modified = true
					i++
					continue
				}
				b.WriteByte(query[i])
				i++
			}
			if i < len(query) {
				b.WriteByte('"')
				i++
			}
			isRegExp = false
		} else {
			b.WriteByte(query[i])
			i++
		}
	}

	return b.String(), modified
}

// validateDVQuery checks for common query mistakes and auto-fixes what it can.
// Returns the (possibly sanitized) query, a warning (empty if none), and an
// error for unfixable issues.
func validateDVQuery(query string) (string, string, error) {
	for _, field := range invalidDVFields {
		// Check for "FieldName <operator>" pattern (field used as a query field)
		if strings.Contains(query, field+" ") {
			return "", "", fmt.Errorf("%q is not a valid Deep Visibility field. Use EventType to filter by event type, or SrcProcImagePath / ProcessName for process filtering", field)
		}
	}

	// Strip backslashes from quoted values (S1 DV parser doesn't support them).
	var warning string
	query, changed := fixBackslashesInDVValues(query)
	if changed {
		warning = "Backslashes were stripped from query values (S1 DV parser does not support them). Use forward slashes or omit path separators for reliable matching."
	}

	// Check for mixed AND/OR at the top level (outside parentheses).
	// S1 supports parenthesized grouping like "A AND (B OR C)", but cannot
	// handle ambiguous "A AND B OR C" without grouping.
	upper := strings.ToUpper(query)
	depth := 0
	hasTopAND := false
	hasTopOR := false
	for i := 0; i < len(upper); i++ {
		switch upper[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				if i+5 <= len(upper) && upper[i:i+5] == " AND " {
					hasTopAND = true
				}
				if i+4 <= len(upper) && upper[i:i+4] == " OR " {
					hasTopOR = true
				}
			}
		}
	}
	if hasTopAND && hasTopOR {
		return "", "", fmt.Errorf("query mixes AND and OR at the top level. Group conditions with parentheses, e.g. A AND (B OR C), or split into separate queries")
	}

	return query, warning, nil
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

	var dvWarning string
	query, dvWarning, err = validateDVQuery(query)
	if err != nil {
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

	// Poll for completion — only break on known terminal states.
	var status *client.DVStatus
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		status, err = client.GetDVQueryStatus(queryID)
		if err != nil {
			return mcp.NewToolResultError(
				fmt.Sprintf("Error running Deep Visibility query: %v", err),
			), nil
		}
		switch status.Status {
		case "FINISHED", "FAILED", "CANCELED":
			goto done
		}
	}
done:

	switch status.Status {
	case "FAILED":
		return mcp.NewToolResultError(
			fmt.Sprintf("Deep Visibility query failed: %s", fallback(status.ResponseError, "Unknown error")),
		), nil
	case "CANCELED":
		return mcp.NewToolResultError(
			fmt.Sprintf("Deep Visibility query was canceled"),
		), nil
	case "FINISHED":
		result := map[string]string{
			"queryId": queryID,
			"status":  status.Status,
			"message": "Query completed. Use s1_dv_get_events to retrieve results.",
			"warning": "Do NOT run another s1_dv_query in parallel. Combine related searches into one query using OR chains to avoid 429 rate-limit errors.",
		}
		if dvWarning != "" {
			result["queryFixup"] = dvWarning
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	default:
		msg := fmt.Sprintf("Query still running after 30 seconds (status: %s). Use s1_dv_get_events with queryId: %s to retrieve results later.\n\nWARNING: Do NOT run another s1_dv_query in parallel. Combine related searches into one query using OR chains to avoid 429 rate-limit errors.",
			fallback(status.Status, "unknown"), queryID)
		if dvWarning != "" {
			msg += "\n\nNOTE: " + dvWarning
		}
		return mcp.NewToolResultText(msg), nil
	}
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

	// Wait for query to finish if still running.
	for i := 0; i < 30; i++ {
		status, err := client.GetDVQueryStatus(queryID)
		if err != nil {
			return mcp.NewToolResultError(
				fmt.Sprintf("Error getting Deep Visibility events: %v", err),
			), nil
		}
		switch status.Status {
		case "FINISHED":
			goto ready
		case "FAILED":
			return mcp.NewToolResultError(
				fmt.Sprintf("Query %s failed: %s", queryID, fallback(status.ResponseError, "Unknown error")),
			), nil
		case "CANCELED":
			return mcp.NewToolResultError(
				fmt.Sprintf("Query %s was canceled", queryID),
			), nil
		}
		time.Sleep(1 * time.Second)
	}
	return mcp.NewToolResultText(
		fmt.Sprintf("Query %s is still running after 30 seconds. Try again later.", queryID),
	), nil
ready:

	// Fetch events, retrying on 409 (S1 race: status says FINISHED but events not yet available).
	var result *client.PaginatedResponse
	for i := 0; i < 5; i++ {
		result, err = client.GetDVEvents(queryID, limit, cursor)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "409") {
			return mcp.NewToolResultError(
				fmt.Sprintf("Error getting Deep Visibility events: %v", err),
			), nil
		}
		time.Sleep(2 * time.Second)
	}
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
