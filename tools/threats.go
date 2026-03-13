package tools

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
	"github.com/mark3labs/mcp-go/mcp"
)

var listThreatsTool = mcp.NewTool("s1_list_threats",
	mcp.WithDescription("List SentinelOne threats with optional filters"),
	mcp.WithString("computerName",
		mcp.Description("Search by computer/endpoint name (partial match)"),
	),
	mcp.WithString("threatName",
		mcp.Description("Search by threat name (partial match)"),
	),
	mcp.WithNumber("limit",
		mcp.Description("Max results (default 50, max 200)"),
	),
	mcp.WithArray("mitigationStatuses",
		mcp.Description("Filter: not_mitigated, mitigated, marked_as_benign"),
		mcp.Items(map[string]any{"type": "string"}),
	),
	mcp.WithArray("classifications",
		mcp.Description("Filter: Malware, PUA, Suspicious"),
		mcp.Items(map[string]any{"type": "string"}),
	),
)

var getThreatTool = mcp.NewTool("s1_get_threat",
	mcp.WithDescription("Get a specific SentinelOne threat by ID"),
	mcp.WithString("threatId",
		mcp.Required(),
		mcp.Description("The threat ID to retrieve"),
	),
)

var mitigateThreatTool = mcp.NewTool("s1_mitigate_threat",
	mcp.WithDescription("Mitigate a threat: kill (terminate process), quarantine (isolate file), remediate (full cleanup), rollback-remediation (undo)"),
	mcp.WithString("threatId",
		mcp.Required(),
		mcp.Description("The threat ID to mitigate"),
	),
	mcp.WithString("action",
		mcp.Required(),
		mcp.Enum("kill", "quarantine", "remediate", "rollback-remediation"),
		mcp.Description("Action: kill, quarantine, remediate, rollback-remediation"),
	),
)

func summarizeThreat(t map[string]any) string {
	computer := fallback(getStr(t, "agentRealtimeInfo", "agentComputerName"), "Unknown")
	threat := fallback(getStr(t, "threatInfo", "threatName"), "Unknown")
	classification := fallback(getStr(t, "threatInfo", "classification"), "Unknown")
	status := fallback(getStr(t, "threatInfo", "mitigationStatus"), "unknown")
	user := fallback(getStr(t, "agentDetectionInfo", "agentLastLoggedInUserName"), "unknown")
	filePath := getStr(t, "threatInfo", "filePath")
	id := getStr(t, "id")

	timeStr := "unknown"
	if created := getStr(t, "threatInfo", "createdAt"); created != "" {
		timeStr = formatTimeAgo(created)
	}

	return fmt.Sprintf("- %s | %s | %s | %s | %s\n  ID: %s | User: %s\n  Path: %s",
		computer, threat, classification, status, timeStr, id, user, filePath)
}

func handleListThreats(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := int(req.GetFloat("limit", 50))
	if limit < 1 || limit > 200 {
		limit = 50
	}

	q := url.Values{}
	q.Set("limit", "50")

	if v := req.GetString("computerName", ""); v != "" {
		q.Set("computerName__contains", v)
	}
	if v := req.GetString("threatName", ""); v != "" {
		q.Set("threatDetails__contains", v)
	}
	if v := req.GetStringSlice("mitigationStatuses", nil); len(v) > 0 {
		q.Set("mitigationStatuses", strings.Join(v, ","))
	}
	if v := req.GetStringSlice("classifications", nil); len(v) > 0 {
		q.Set("classifications", strings.Join(v, ","))
	}

	var allThreats []map[string]any
	for {
		result, err := client.ListThreats(q)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}
		allThreats = append(allThreats, result.Data...)
		if len(allThreats) >= limit || result.Pagination == nil || result.Pagination.NextCursor == "" {
			break
		}
		q.Set("cursor", result.Pagination.NextCursor)
	}

	if len(allThreats) > limit {
		allThreats = allThreats[:limit]
	}

	if len(allThreats) == 0 {
		return mcp.NewToolResultText("No threats found matching criteria."), nil
	}

	lines := make([]string, len(allThreats))
	for i, t := range allThreats {
		lines[i] = summarizeThreat(t)
	}

	text := fmt.Sprintf("Found %d threat(s):\n\n%s", len(allThreats), strings.Join(lines, "\n\n"))
	return mcp.NewToolResultText(text), nil
}

func handleGetThreat(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	threatID, err := req.RequireString("threatId")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := client.GetThreat(threatID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
	}

	if len(result.Data) == 0 {
		return mcp.NewToolResultError(fmt.Sprintf("Threat %s not found", threatID)), nil
	}

	t := result.Data[0]
	text := fmt.Sprintf(`Threat Details:
---
Computer: %s
Threat: %s
Classification: %s
Confidence: %s
Status: %s
Analyst Verdict: %s
---
ID: %s
Storyline ID: %s
Created: %s
---
User: %s
Agent ID: %s
OS: %s
---
File Path: %s
SHA256: %s
SHA1: %s
MD5: %s`,
		fallback(getStr(t, "agentRealtimeInfo", "agentComputerName"), "Unknown"),
		fallback(getStr(t, "threatInfo", "threatName"), "Unknown"),
		fallback(getStr(t, "threatInfo", "classification"), "Unknown"),
		fallback(getStr(t, "threatInfo", "confidenceLevel"), "Unknown"),
		fallback(getStr(t, "threatInfo", "mitigationStatus"), "Unknown"),
		fallback(getStr(t, "threatInfo", "analystVerdict"), "undefined"),
		getStr(t, "id"),
		fallback(getStr(t, "threatInfo", "storyline"), "N/A"),
		fallback(getStr(t, "threatInfo", "createdAt"), "Unknown"),
		fallback(getStr(t, "agentDetectionInfo", "agentLastLoggedInUserName"), "Unknown"),
		fallback(getStr(t, "agentRealtimeInfo", "agentId"), "Unknown"),
		fallback(getStr(t, "agentDetectionInfo", "agentOsName"), "Unknown"),
		fallback(getStr(t, "threatInfo", "filePath"), "N/A"),
		fallback(getStr(t, "threatInfo", "sha256"), "N/A"),
		fallback(getStr(t, "threatInfo", "sha1"), "N/A"),
		fallback(getStr(t, "threatInfo", "md5"), "N/A"),
	)

	return mcp.NewToolResultText(text), nil
}

func handleMitigateThreat(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	threatID, err := req.RequireString("threatId")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	action, err := req.RequireString("action")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	affected, err := client.MitigateThreat(threatID, action)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
	}

	return mcp.NewToolResultText(
		fmt.Sprintf("Done: %s applied to threat %s. Affected: %d", action, threatID, affected),
	), nil
}
