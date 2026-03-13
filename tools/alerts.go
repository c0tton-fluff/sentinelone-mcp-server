package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
	"github.com/mark3labs/mcp-go/mcp"
)

var listAlertsTool = mcp.NewTool("s1_list_alerts",
	mcp.WithDescription("List unified alerts via GraphQL. Use storylineId to correlate with threats."),
	mcp.WithNumber("limit",
		mcp.Description("Max results (default 20, max 50)"),
	),
	mcp.WithString("cursor",
		mcp.Description("Pagination cursor (endCursor from previous response)"),
	),
	mcp.WithString("severity",
		mcp.Description("Filter by severity: LOW, MEDIUM, HIGH, CRITICAL (case-insensitive)"),
	),
	mcp.WithString("analystVerdict",
		mcp.Description("Filter by analyst verdict: TRUE_POSITIVE, FALSE_POSITIVE, SUSPICIOUS, UNDEFINED (case-insensitive)"),
	),
	mcp.WithString("incidentStatus",
		mcp.Description("Filter by incident status: NEW, IN_PROGRESS, RESOLVED (case-insensitive). 'Unresolved' is accepted as alias for NEW."),
	),
	mcp.WithArray("siteIds",
		mcp.Description("Filter by site IDs"),
		mcp.Items(map[string]any{"type": "string"}),
	),
	mcp.WithString("storylineId",
		mcp.Description("Filter by storyline ID (correlate with threat)"),
	),
)

func summarizeAlert(a map[string]any) string {
	severity := fallback(getStr(a, "severity"), "Unknown")
	status := fallback(getStr(a, "status"), "Unknown")
	verdict := strings.ReplaceAll(fallback(getStr(a, "analystVerdict"), "UNDEFINED"), "_", " ")
	classification := fallback(getStr(a, "classification"), "N/A")
	confidence := fallback(getStr(a, "confidenceLevel"), "N/A")
	name := fallback(getStr(a, "name"), "Unknown")
	id := getStr(a, "id")
	storylineID := fallback(getStr(a, "storylineId"), "N/A")

	timeStr := "unknown"
	if d := getStr(a, "detectedAt"); d != "" {
		timeStr = formatTimeAgo(d)
	}

	return fmt.Sprintf("- %s | %s | %s | %s\n  ID: %s | Verdict: %s\n  Classification: %s | Confidence: %s\n  Storyline: %s",
		name, severity, status, timeStr, id, verdict, classification, confidence, storylineID)
}

func handleListAlerts(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := int(req.GetFloat("limit", 20))
	if limit < 1 || limit > 50 {
		limit = 20
	}

	result, err := client.QueryAlerts(
		limit,
		req.GetString("cursor", ""),
		req.GetString("severity", ""),
		req.GetString("analystVerdict", ""),
		req.GetString("incidentStatus", ""),
		req.GetString("storylineId", ""),
		req.GetStringSlice("siteIds", nil),
	)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error listing alerts: %v", err)), nil
	}

	if len(result.Alerts) == 0 {
		return mcp.NewToolResultText("No alerts found matching criteria."), nil
	}

	lines := make([]string, len(result.Alerts))
	for i, a := range result.Alerts {
		lines[i] = summarizeAlert(a)
	}

	text := fmt.Sprintf("Found %d alert(s):\n\n%s", len(result.Alerts), strings.Join(lines, "\n\n"))
	if result.PageInfo.HasNextPage {
		text += fmt.Sprintf("\n\n[More results available - use cursor: %s]", result.PageInfo.EndCursor)
	}

	return mcp.NewToolResultText(text), nil
}
