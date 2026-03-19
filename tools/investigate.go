package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
)

var investigateThreatTool = ToolDef{
	Name: "s1_investigate_threat",
	Description: `Full threat investigation in one call. Fetches threat details,
correlated alerts by storyline, and the threat timeline. Replaces 3+
sequential tool calls.`,
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"threatId"},
		"properties": map[string]any{
			"threatId": map[string]any{
				"type":        "string",
				"description": "The threat ID to investigate",
			},
		},
	},
}

func handleInvestigateThreat(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		ThreatID string `json:"threatId"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
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
	computer := getStr(t, "agentRealtimeInfo", "agentComputerName")
	storylineID := getStr(t, "threatInfo", "storyline")
	createdAt := getStr(t, "threatInfo", "createdAt")
	osName := fallback(getStr(t, "agentDetectionInfo", "agentOsName"), "Unknown")
	timeStr := createdAt
	if createdAt != "" {
		timeStr = formatTimeAgo(createdAt)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "THREAT: %s | %s | %s | %s\n",
		fallback(getStr(t, "threatInfo", "threatName"), "Unknown"),
		fallback(getStr(t, "threatInfo", "classification"), "Unknown"),
		fallback(getStr(t, "threatInfo", "mitigationStatus"), "Unknown"),
		timeStr)
	fmt.Fprintf(&sb, "Agent: %s | %s | User: %s | Verdict: %s\n",
		fallback(computer, "Unknown"),
		osName,
		fallback(getStr(t, "agentDetectionInfo", "agentLastLoggedInUserName"), "Unknown"),
		fallback(getStr(t, "threatInfo", "analystVerdict"), "undefined"))
	fmt.Fprintf(&sb, "ID: %s | Storyline: %s\n", p.ThreatID, fallback(storylineID, "N/A"))
	if fp := getStr(t, "threatInfo", "filePath"); fp != "" {
		fmt.Fprintf(&sb, "Path: %s\n", fp)
	}
	if h := getStr(t, "threatInfo", "sha256"); h != "" {
		fmt.Fprintf(&sb, "SHA256: %s\n", h)
	}

	// Fetch correlated alerts.
	sb.WriteString("\nALERTS")
	if storylineID == "" {
		sb.WriteString("\n---\nNo storyline ID available.")
	} else {
		alerts, alertErr := client.QueryAlerts(ctx, client.AlertQueryOpts{
			Limit:       20,
			StorylineID: storylineID,
		})
		if alertErr != nil {
			fmt.Fprintf(&sb, "\n---\nError: %v", alertErr)
		} else if len(alerts.Alerts) == 0 {
			sb.WriteString("\n---\nNo alerts for this storyline.")
		} else {
			fmt.Fprintf(&sb, " (%d)\n---\n", len(alerts.Alerts))
			for i, a := range alerts.Alerts {
				if i > 0 {
					sb.WriteString("\n\n")
				}
				sb.WriteString(summarizeAlert(a))
			}
		}
	}

	// Fetch threat timeline via dedicated API (faster than DV, no rate-limit impact).
	sb.WriteString("\n\nTIMELINE")
	timeline, tlErr := client.GetThreatTimeline(ctx, p.ThreatID, 50)
	if tlErr != nil {
		fmt.Fprintf(&sb, "\n---\nError: %v", tlErr)
	} else if len(timeline.Data) == 0 {
		sb.WriteString("\n---\nNo timeline events.")
	} else {
		fmt.Fprintf(&sb, " (%d events)\n---\n", len(timeline.Data))
		for _, e := range timeline.Data {
			sb.WriteString(summarizeTimelineEvent(e))
			sb.WriteByte('\n')
		}
	}

	return toolText(sb.String())
}

func summarizeTimelineEvent(e map[string]any) string {
	activityType := fallback(getStr(e, "activityType"), "")
	primary := fallback(getStr(e, "primaryDescription"), "")
	secondary := getStr(e, "secondaryDescription")

	timeStr := "unknown"
	if d := getStr(e, "createdAt"); d != "" {
		timeStr = formatTimeAgo(d)
	}

	line := fmt.Sprintf("- [%s] %s", timeStr, primary)
	if activityType != "" && activityType != primary {
		line = fmt.Sprintf("- [%s] %s: %s", timeStr, activityType, primary)
	}
	if secondary != "" {
		line += " -- " + secondary
	}
	return line
}
