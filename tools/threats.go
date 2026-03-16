package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
)

var listThreatsTool = ToolDef{
	Name:        "s1_list_threats",
	Description: "List SentinelOne threats with optional filters",
	InputSchema: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"computerName": map[string]any{
				"type":        "string",
				"description": "Search by computer/endpoint name (partial match)",
			},
			"threatName": map[string]any{
				"type":        "string",
				"description": "Search by threat name (partial match)",
			},
			"limit": map[string]any{
				"type":        "number",
				"description": "Max results (default 50, max 200)",
			},
			"mitigationStatuses": map[string]any{
				"type":        "array",
				"description": "Filter: not_mitigated, mitigated, marked_as_benign",
				"items":       map[string]any{"type": "string"},
			},
			"classifications": map[string]any{
				"type":        "array",
				"description": "Filter: Malware, PUA, Suspicious",
				"items":       map[string]any{"type": "string"},
			},
		},
	},
}

var getThreatTool = ToolDef{
	Name:        "s1_get_threat",
	Description: "Get a specific SentinelOne threat by ID",
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"threatId"},
		"properties": map[string]any{
			"threatId": map[string]any{
				"type":        "string",
				"description": "The threat ID to retrieve",
			},
		},
	},
}

var mitigateThreatTool = ToolDef{
	Name:        "s1_mitigate_threat",
	Description: "Mitigate a threat: kill (terminate process), quarantine (isolate file), un-quarantine (undo quarantine), remediate (full cleanup), rollback-remediation (undo remediation)",
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"threatId", "action"},
		"properties": map[string]any{
			"threatId": map[string]any{
				"type":        "string",
				"description": "The threat ID to mitigate",
			},
			"action": map[string]any{
				"type":        "string",
				"description": "Action: kill, quarantine, un-quarantine, remediate, rollback-remediation",
				"enum":        []string{"kill", "quarantine", "un-quarantine", "remediate", "rollback-remediation"},
			},
		},
	},
}

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

func handleListThreats(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		ComputerName       string   `json:"computerName"`
		ThreatName         string   `json:"threatName"`
		Limit              int      `json:"limit"`
		MitigationStatuses []string `json:"mitigationStatuses"`
		Classifications    []string `json:"classifications"`
	}
	p.Limit = 50
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if p.Limit < 1 || p.Limit > 200 {
		p.Limit = 50
	}

	q := url.Values{}
	q.Set("limit", "50")
	q.Set("sortBy", "createdAt")
	q.Set("sortOrder", "desc")

	if p.ComputerName != "" {
		q.Set("computerName__contains", p.ComputerName)
	}
	if p.ThreatName != "" {
		q.Set("threatDetails__contains", p.ThreatName)
	}
	if len(p.MitigationStatuses) > 0 {
		q.Set("mitigationStatuses", strings.Join(p.MitigationStatuses, ","))
	}
	if len(p.Classifications) > 0 {
		q.Set("classifications", strings.Join(p.Classifications, ","))
	}

	var allThreats []map[string]any
	for {
		result, err := client.ListThreats(ctx, q)
		if err != nil {
			return toolError(fmt.Sprintf("Error: %v", err))
		}
		allThreats = append(allThreats, result.Data...)
		if len(allThreats) >= p.Limit || result.Pagination == nil || result.Pagination.NextCursor == "" {
			break
		}
		q.Set("cursor", result.Pagination.NextCursor)
	}

	if len(allThreats) > p.Limit {
		allThreats = allThreats[:p.Limit]
	}

	if len(allThreats) == 0 {
		return toolText("No threats found matching criteria.")
	}

	lines := make([]string, len(allThreats))
	for i, t := range allThreats {
		lines[i] = summarizeThreat(t)
	}

	return toolText(fmt.Sprintf("Found %d threat(s):\n\n%s", len(allThreats), strings.Join(lines, "\n\n")))
}

func handleGetThreat(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		ThreatID string `json:"threatId"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if p.ThreatID == "" {
		return toolError("threatId is required")
	}

	result, err := client.GetThreat(ctx, p.ThreatID)
	if err != nil {
		return toolError(fmt.Sprintf("Error: %v", err))
	}

	if len(result.Data) == 0 {
		return toolError(fmt.Sprintf("Threat %s not found", p.ThreatID))
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

	return toolText(text)
}

func handleMitigateThreat(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		ThreatID string `json:"threatId"`
		Action   string `json:"action"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if p.ThreatID == "" {
		return toolError("threatId is required")
	}
	if p.Action == "" {
		return toolError("action is required")
	}

	affected, err := client.MitigateThreat(ctx, p.ThreatID, p.Action)
	if err != nil {
		return toolError(fmt.Sprintf("Error: %v", err))
	}

	return toolText(fmt.Sprintf("Done: %s applied to threat %s. Affected: %d", p.Action, p.ThreatID, affected))
}
