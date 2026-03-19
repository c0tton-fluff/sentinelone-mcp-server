package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
)

var listAlertsTool = ToolDef{
	Name:        "s1_list_alerts",
	Description: "List unified alerts via GraphQL. Use storylineId to correlate with threats.",
	InputSchema: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"limit": map[string]any{
				"type":        "number",
				"description": "Max results (default 50, max 200)",
			},
			"severity": map[string]any{
				"type":        "string",
				"description": "Filter by severity: LOW, MEDIUM, HIGH, CRITICAL (case-insensitive)",
			},
			"analystVerdict": map[string]any{
				"type":        "string",
				"description": "Filter by analyst verdict: TRUE_POSITIVE, FALSE_POSITIVE, SUSPICIOUS, UNDEFINED (case-insensitive)",
			},
			"incidentStatus": map[string]any{
				"type":        "string",
				"description": "Filter by incident status: NEW, IN_PROGRESS, RESOLVED (case-insensitive). 'Unresolved' is accepted as alias for NEW.",
			},
			"siteIds": map[string]any{
				"type":        "array",
				"description": "Filter by site IDs",
				"items":       map[string]any{"type": "string"},
			},
			"storylineId": map[string]any{
				"type":        "string",
				"description": "Filter by storyline ID (correlate with threat)",
			},
		},
	},
}

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

	// Process info
	var processLine string
	if proc, ok := a["process"].(map[string]any); ok {
		cmdLine := getStr(proc, "cmdLine")
		parentName := getStr(proc, "parentName")
		var fileName, filePath string
		if f, ok := proc["file"].(map[string]any); ok {
			fileName = getStr(f, "name")
			filePath = getStr(f, "path")
		}
		if cmdLine != "" || fileName != "" {
			processLine = "\n  Process: " + fallback(fileName, "N/A")
			if filePath != "" {
				processLine += " (" + filePath + ")"
			}
			if cmdLine != "" {
				processLine += "\n  Cmd: " + cmdLine
			}
			if parentName != "" {
				processLine += "\n  Parent: " + parentName
			}
		}
	}

	// Asset/endpoint info
	var assetLine string
	if assets, ok := a["assets"].([]any); ok && len(assets) > 0 {
		if asset, ok := assets[0].(map[string]any); ok {
			assetName := getStr(asset, "name")
			user := getStr(asset, "lastLoggedInUser")
			osType := getStr(asset, "osType")
			if assetName != "" {
				assetLine = "\n  Endpoint: " + assetName
				if user != "" {
					assetLine += " | User: " + user
				}
				if osType != "" {
					assetLine += " | OS: " + osType
				}
			}
		}
	}

	return fmt.Sprintf("- %s | %s | %s | %s\n  ID: %s | Verdict: %s\n  Classification: %s | Confidence: %s\n  Storyline: %s",
		name, severity, status, timeStr, id, verdict, classification, confidence, storylineID) + assetLine + processLine
}

func handleListAlerts(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		Limit          int      `json:"limit"`
		Severity       string   `json:"severity"`
		AnalystVerdict string   `json:"analystVerdict"`
		IncidentStatus string   `json:"incidentStatus"`
		SiteIDs        []string `json:"siteIds"`
		StorylineID    string   `json:"storylineId"`
	}
	p.Limit = 50
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if p.Limit < 1 || p.Limit > 200 {
		p.Limit = 50
	}

	const pageSize = 50
	var allAlerts []map[string]any
	cursor := ""
	for {
		result, err := client.QueryAlerts(
			ctx,
			pageSize,
			cursor,
			p.Severity,
			p.AnalystVerdict,
			p.IncidentStatus,
			p.StorylineID,
			p.SiteIDs,
		)
		if err != nil {
			return toolError(fmt.Sprintf("Error listing alerts: %v", err))
		}
		allAlerts = append(allAlerts, result.Alerts...)
		if !result.PageInfo.HasNextPage || len(allAlerts) >= p.Limit {
			break
		}
		cursor = result.PageInfo.EndCursor
	}

	if len(allAlerts) > p.Limit {
		allAlerts = allAlerts[:p.Limit]
	}

	if len(allAlerts) == 0 {
		return toolText("No alerts found matching criteria.")
	}

	lines := make([]string, len(allAlerts))
	for i, a := range allAlerts {
		lines[i] = summarizeAlert(a)
	}

	return toolText(fmt.Sprintf("Found %d alert(s):\n\n%s", len(allAlerts), strings.Join(lines, "\n\n")))
}
