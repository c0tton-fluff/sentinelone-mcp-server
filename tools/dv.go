package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
)

var dvQueryTool = ToolDef{
	Name: "s1_dv_query",
	Description: `Run a Deep Visibility query. Returns queryId when complete.

IMPORTANT: Do NOT run multiple s1_dv_query calls in parallel. The S1 API
aggressively rate-limits query creation per token. Run DV queries sequentially
and combine related searches into a single query using OR chains.

Query syntax:
  <Field> <Operator> "<Value>" [AND|OR <Field> <Operator> "<Value>" ...]

Operators: Contains, Contains Anycase (case-insensitive), ContainsCIS (alias),
            =, !=, In, In Anycase, In Contains Anycase, NotIn, StartsWith, EndsWith, RegExp

Common fields:
  Source process (the process performing the action):
    SrcProcName, SrcProcImagePath, SrcProcCmdLine, SrcProcUser
  Target process (the process being created/acted upon):
    TgtProcName, TgtProcImagePath, TgtProcCmdLine
  File:     FilePath, FileFullName, FileSHA256, FileMD5
  Network:  SrcIP, DstIP, DstPort, DnsRequest, DnsResponse, Url
  Event:    EventType (values: "Process Creation", "File Creation", "File Modification",
            "File Deletion", "File Rename", "DNS Resolved", "IP Connect",
            "Behavioral Indicators", "Registry Key Creation", "Registry Value Modified")

Additional syntax:
  - "not" prefix negates a condition: not TgtProcName In Anycase ("wermgr.exe")
  - "Anycase" suffix for case-insensitive: Contains Anycase, In Anycase
  - Operators are case-insensitive: and/And/AND all work

Examples:
  TgtProcImagePath ContainsCIS "/usr/bin/security" AND EventType = "Process Creation"
  SrcProcName In Anycase ("w3wp.exe") AND TgtProcCmdLine Contains Anycase "cmd"
  DnsRequest Contains "evil.com" OR DstIP = "1.2.3.4"

Query strategy:
  - Combine related conditions into ONE query using OR instead of running multiple
    parallel queries. The S1 API rate-limits query creation aggressively.
    Bad:  3 separate queries for /tmp/, /Downloads/, /Desktop/
    Good: SrcProcImagePath Contains "/tmp/" OR SrcProcImagePath Contains "/Downloads/" OR SrcProcImagePath Contains "/Desktop/"
  - Use AND to narrow broad queries (e.g., add EventType = "Process Creation")
  - Use In/NotIn for matching against a list of values:
    TgtProcName In Anycase ("cmd.exe","powershell.exe","pwsh.exe")
  - For exclusions, prefer NotIn over multiple != conditions:
    TgtProcName NotIn ("chrome.exe","bash","node","svchost.exe")

Limitations:
  - Do NOT use ObjectType as a field (not supported in DV queries)
  - Avoid trailing backslashes in values (e.g., "\\Desktop\\" breaks the parser).
    Use "\\Desktop" or Contains Anycase instead
  - Use parentheses to group when mixing AND/OR: A AND (B OR C OR D)
  - Nested parentheses are supported: A AND (B OR (C AND D))
  - Max query window is 14 days`,
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"query", "fromDate", "toDate"},
		"properties": map[string]any{
			"query": map[string]any{
				"type":        "string",
				"description": "Deep Visibility query string. See tool description for syntax and valid fields.",
			},
			"fromDate": map[string]any{
				"type":        "string",
				"description": "Start date in ISO format (e.g., 2024-01-01T00:00:00Z)",
			},
			"toDate": map[string]any{
				"type":        "string",
				"description": "End date in ISO format (e.g., 2024-01-02T00:00:00Z)",
			},
			"siteIds": map[string]any{
				"type":        "array",
				"description": "Filter by site IDs",
				"items":       map[string]any{"type": "string"},
			},
			"accountIds": map[string]any{
				"type":        "array",
				"description": "Filter by account IDs",
				"items":       map[string]any{"type": "string"},
			},
		},
	},
}

var dvGetEventsTool = ToolDef{
	Name: "s1_dv_get_events",
	Description: `Get events from a completed Deep Visibility query.

IMPORTANT: Run s1_dv_get_events calls sequentially, not in parallel. The S1 API
shares rate limits across all endpoints per token.`,
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"queryId"},
		"properties": map[string]any{
			"queryId": map[string]any{
				"type":        "string",
				"description": "Query ID returned from s1_dv_query",
			},
			"limit": map[string]any{
				"type":        "number",
				"description": "Max results (default 100, max 100)",
			},
		},
	},
}

func summarizeEvent(e map[string]any) string {
	timeStr := "unknown"
	if d := getStr(e, "eventTime"); d != "" {
		timeStr = formatTimeAgo(d)
	} else if d := getStr(e, "createdAt"); d != "" {
		timeStr = formatTimeAgo(d)
	}
	eventType := fallback(getStr(e, "eventType"), "Unknown")
	agent := fallback(getStr(e, "agentName"), "Unknown")

	// Process name: prefer tgtProcName (target of the action), fall back to
	// srcProcName, then the legacy processName field.
	process := firstNonEmpty(
		getStr(e, "tgtProcName"),
		getStr(e, "srcProcName"),
		getStr(e, "processName"),
	)
	if process == "" {
		process = "N/A"
	}

	var details string

	// Command line: prefer tgt, fall back to src, then legacy.
	cmd := firstNonEmpty(
		getStr(e, "tgtProcCmdLine"),
		getStr(e, "srcProcCmdLine"),
		getStr(e, "processCmd"),
	)
	if cmd != "" {
		if len(cmd) > 120 {
			cmd = cmd[:120] + "..."
		}
		details += " | Cmd: " + cmd
	}

	imgPath := firstNonEmpty(
		getStr(e, "tgtProcImagePath"),
		getStr(e, "srcProcImagePath"),
		getStr(e, "processImagePath"),
	)
	if imgPath != "" {
		details += " | Path: " + truncatePath(imgPath, 60)
	}

	// User info.
	if user := firstNonEmpty(getStr(e, "srcProcUser"), getStr(e, "tgtProcUser"), getStr(e, "user")); user != "" {
		details += " | User: " + user
	}

	// Network details.
	srcIP := getStr(e, "srcIp")
	dstIP := getStr(e, "dstIp")
	dstPort := getStr(e, "dstPort")
	if srcIP != "" && dstIP != "" {
		if dstPort == "" {
			dstPort = "?"
		}
		details += fmt.Sprintf(" | %s -> %s:%s", srcIP, dstIP, dstPort)
	} else if dstIP != "" {
		if dstPort == "" {
			dstPort = "?"
		}
		details += fmt.Sprintf(" -> %s:%s", dstIP, dstPort)
	}

	if fp := getStr(e, "fileFullName"); fp != "" {
		details += " | File: " + truncatePath(fp, 60)
	}
	if dns := getStr(e, "dnsRequest"); dns != "" {
		details += " | DNS: " + dns
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
		// Detect RegExp operator immediately before a quoted value (case-insensitive).
		if i+7 <= len(query) && strings.EqualFold(query[i:i+7], "RegExp ") {
			b.WriteString(query[i : i+7])
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

	// Check for mixed AND/OR at the top level (outside parentheses and quotes).
	// S1 supports parenthesized grouping like "A AND (B OR C)", but cannot
	// handle ambiguous "A AND B OR C" without grouping.
	upper := strings.ToUpper(query)
	depth := 0
	hasTopAND := false
	hasTopOR := false
	inQuote := false
	for i := 0; i < len(upper); i++ {
		if upper[i] == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
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

// pollDVQuery polls a DV query until it reaches a terminal state or
// times out after 30 seconds. Returns the final status or an error.
func pollDVQuery(
	ctx context.Context, queryID string,
) (*client.DVStatus, error) {
	for range 30 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
		}
		status, err := client.GetDVQueryStatus(ctx, queryID)
		if err != nil {
			return nil, err
		}
		switch status.Status {
		case "RUNNING", "PROCESS_RUNNING", "EVENTS_RUNNING":
			// still running
		default:
			return status, nil
		}
	}
	// Final check after timeout.
	return client.GetDVQueryStatus(ctx, queryID)
}

func handleDVQuery(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		Query      string   `json:"query"`
		FromDate   string   `json:"fromDate"`
		ToDate     string   `json:"toDate"`
		SiteIDs    []string `json:"siteIds"`
		AccountIDs []string `json:"accountIds"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if p.Query == "" {
		return toolError("query is required")
	}
	if p.FromDate == "" {
		return toolError("fromDate is required")
	}
	if p.ToDate == "" {
		return toolError("toDate is required")
	}

	query, dvWarning, err := validateDVQuery(p.Query)
	if err != nil {
		return toolError(fmt.Sprintf("Invalid query: %v", err))
	}

	queryID, err := client.CreateDVQuery(ctx, query, p.FromDate, p.ToDate, p.SiteIDs, p.AccountIDs)
	if err != nil {
		return toolError(fmt.Sprintf("Error running Deep Visibility query: %v", err))
	}

	status, err := pollDVQuery(ctx, queryID)
	if err != nil {
		return toolError(fmt.Sprintf("Error running Deep Visibility query: %v", err))
	}

	switch status.Status {
	case "FAILED", "FAILED_CLIENT", "ERROR":
		return toolError(
			fmt.Sprintf("Deep Visibility query failed: %s", fallback(status.ResponseError, "Unknown error")),
		)
	case "QUERY_CANCELLED":
		return toolError("Deep Visibility query was canceled")
	case "TIMED_OUT", "QUERY_EXPIRED":
		return toolError(fmt.Sprintf("Deep Visibility query %s", status.Status))
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
		return toolText(string(b))
	default:
		msg := fmt.Sprintf("Query still running after 30 seconds (status: %s). Use s1_dv_get_events with queryId: %s to retrieve results later.\n\nWARNING: Do NOT run another s1_dv_query in parallel. Combine related searches into one query using OR chains to avoid 429 rate-limit errors.",
			fallback(status.Status, "unknown"), queryID)
		if dvWarning != "" {
			msg += "\n\nNOTE: " + dvWarning
		}
		return toolText(msg)
	}
}

func handleDVGetEvents(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		QueryID string `json:"queryId"`
		Limit   int    `json:"limit"`
	}
	p.Limit = 100
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if p.QueryID == "" {
		return toolError("queryId is required")
	}
	if p.Limit < 1 || p.Limit > 100 {
		p.Limit = 100
	}

	// Wait for query to finish if still running.
	status, err := pollDVQuery(ctx, p.QueryID)
	if err != nil {
		return toolError(fmt.Sprintf("Error getting Deep Visibility events: %v", err))
	}
	switch status.Status {
	case "FINISHED":
		// continue to fetch events
	case "FAILED", "FAILED_CLIENT", "ERROR":
		return toolError(fmt.Sprintf("Query %s failed: %s", p.QueryID, fallback(status.ResponseError, "Unknown error")))
	case "QUERY_CANCELLED":
		return toolError(fmt.Sprintf("Query %s was canceled", p.QueryID))
	case "TIMED_OUT", "QUERY_EXPIRED":
		return toolError(fmt.Sprintf("Query %s expired or timed out", p.QueryID))
	case "RUNNING", "PROCESS_RUNNING", "EVENTS_RUNNING":
		return toolText(fmt.Sprintf("Query %s is still running after 30 seconds. Try again later.", p.QueryID))
	default:
		return toolError(fmt.Sprintf("Query %s unexpected status: %s", p.QueryID, status.Status))
	}

	// Fetch events, retrying on 409 (S1 race: status says FINISHED but events not yet available).
	var result *client.PaginatedResponse
	for attempt := range 5 {
		result, err = client.GetDVEvents(ctx, p.QueryID, p.Limit, "")
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "409") || attempt == 4 {
			return toolError(fmt.Sprintf("Error getting Deep Visibility events: %v", err))
		}
		select {
		case <-ctx.Done():
			return toolError(fmt.Sprintf("Error getting Deep Visibility events: %v", ctx.Err()))
		case <-time.After(2 * time.Second):
		}
	}

	if len(result.Data) == 0 {
		return toolText("No events found for this query.")
	}

	lines := make([]string, len(result.Data))
	for i, e := range result.Data {
		lines[i] = summarizeEvent(e)
	}

	return toolText(fmt.Sprintf("Found %d event(s):\n\n%s", len(result.Data), strings.Join(lines, "\n")))
}
