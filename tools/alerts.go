package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
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

// alertSummaryHeader builds a grouped overview: counts by rule name with severity and affected users.
func alertSummaryHeader(alerts []map[string]any) string {
	// Count by status.
	statusCounts := map[string]int{}
	for _, a := range alerts {
		statusCounts[fallback(getStr(a, "status"), "Unknown")]++
	}
	var statusParts []string
	for _, s := range []string{"NEW", "IN_PROGRESS", "RESOLVED"} {
		if c, ok := statusCounts[s]; ok {
			statusParts = append(statusParts, fmt.Sprintf("%d %s", c, s))
		}
	}

	// Group by rule name.
	type ruleGroup struct {
		severity string
		count    int
		users    map[string]struct{}
	}
	groups := map[string]*ruleGroup{}
	var order []string
	for _, a := range alerts {
		name := fallback(getStr(a, "name"), "Unknown")
		if _, exists := groups[name]; !exists {
			groups[name] = &ruleGroup{
				severity: fallback(getStr(a, "severity"), "?"),
				users:    map[string]struct{}{},
			}
			order = append(order, name)
		}
		g := groups[name]
		g.count++
		if assets, ok := a["assets"].([]any); ok && len(assets) > 0 {
			if asset, ok := assets[0].(map[string]any); ok {
				if user := getStr(asset, "lastLoggedInUser"); user != "" {
					g.users[user] = struct{}{}
				}
			}
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%d alert(s) (%s):\n\nBy rule:\n", len(alerts), strings.Join(statusParts, ", "))
	for _, name := range order {
		g := groups[name]
		users := slices.Sorted(maps.Keys(g.users))
		fmt.Fprintf(&sb, "  %-50s %8s  %3d  [%s]\n", name, g.severity, g.count, strings.Join(users, ", "))
	}
	return sb.String()
}

// summarizeAlertCompact returns a one-liner suitable for large result sets.
func summarizeAlertCompact(a map[string]any) string {
	severity := fallback(getStr(a, "severity"), "?")
	status := fallback(getStr(a, "status"), "?")
	verdict := fallback(getStr(a, "analystVerdict"), "UNDEFINED")
	name := fallback(getStr(a, "name"), "Unknown")
	id := getStr(a, "id")

	timeStr := "?"
	if d := getStr(a, "detectedAt"); d != "" {
		timeStr = formatTimeAgo(d)
	}

	var user string
	if assets, ok := a["assets"].([]any); ok && len(assets) > 0 {
		if asset, ok := assets[0].(map[string]any); ok {
			user = getStr(asset, "lastLoggedInUser")
			if user == "" {
				user = getStr(asset, "name")
			}
		}
	}

	return fmt.Sprintf("- [%s] %s | %s | %s | %s | %s (%s)",
		severity, name, user, verdict, status, timeStr, id)
}

var setAlertVerdictTool = ToolDef{
	Name:        "s1_set_alert_verdict",
	Description: "Set the analyst verdict on alerts matching the given filters. At least one filter is required to avoid accidentally affecting all alerts.",
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"verdict"},
		"properties": map[string]any{
			"verdict": map[string]any{
				"type":        "string",
				"description": "Analyst verdict to set",
				"enum":        []string{"TRUE_POSITIVE", "FALSE_POSITIVE", "SUSPICIOUS", "UNDEFINED"},
			},
			"query": map[string]any{
				"type":        "string",
				"description": "Free-text search across all alert fields (agent name, user, rule, etc.)",
			},
			"ruleName": map[string]any{
				"type":        "array",
				"description": "Filter by rule name (partial match, multiple values)",
				"items":       map[string]any{"type": "string"},
			},
			"agentName": map[string]any{
				"type":        "array",
				"description": "Filter by agent/endpoint name (partial match, multiple values)",
				"items":       map[string]any{"type": "string"},
			},
			"incidentStatus": map[string]any{
				"type":        "array",
				"description": "Filter by current incident status: UNRESOLVED, IN_PROGRESS, RESOLVED",
				"items":       map[string]any{"type": "string"},
			},
			"siteIds": map[string]any{
				"type":        "array",
				"description": "Filter by site IDs",
				"items":       map[string]any{"type": "string"},
			},
			"alertIds": map[string]any{
				"type":        "array",
				"description": "Target specific alert IDs",
				"items":       map[string]any{"type": "string"},
			},
		},
	},
}

var setAlertStatusTool = ToolDef{
	Name:        "s1_set_alert_status",
	Description: "Set the incident status on alerts matching the given filters. Optionally set the analyst verdict at the same time. At least one filter is required.",
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"status"},
		"properties": map[string]any{
			"status": map[string]any{
				"type":        "string",
				"description": "Incident status to set",
				"enum":        []string{"UNRESOLVED", "IN_PROGRESS", "RESOLVED"},
			},
			"verdict": map[string]any{
				"type":        "string",
				"description": "Optional: also set analyst verdict in the same operation (makes two API calls)",
				"enum":        []string{"TRUE_POSITIVE", "FALSE_POSITIVE", "SUSPICIOUS", "UNDEFINED"},
			},
			"query": map[string]any{
				"type":        "string",
				"description": "Free-text search across all alert fields (agent name, user, rule, etc.)",
			},
			"ruleName": map[string]any{
				"type":        "array",
				"description": "Filter by rule name (partial match, multiple values)",
				"items":       map[string]any{"type": "string"},
			},
			"agentName": map[string]any{
				"type":        "array",
				"description": "Filter by agent/endpoint name (partial match, multiple values)",
				"items":       map[string]any{"type": "string"},
			},
			"incidentStatus": map[string]any{
				"type":        "array",
				"description": "Filter by current incident status: UNRESOLVED, IN_PROGRESS, RESOLVED",
				"items":       map[string]any{"type": "string"},
			},
			"siteIds": map[string]any{
				"type":        "array",
				"description": "Filter by site IDs",
				"items":       map[string]any{"type": "string"},
			},
			"alertIds": map[string]any{
				"type":        "array",
				"description": "Target specific alert IDs",
				"items":       map[string]any{"type": "string"},
			},
		},
	},
}

// alertFilterParams holds the common filter parameters for alert bulk operations.
type alertFilterParams struct {
	Query          string   `json:"query"`
	RuleName       []string `json:"ruleName"`
	AgentName      []string `json:"agentName"`
	IncidentStatus []string `json:"incidentStatus"`
	SiteIDs        []string `json:"siteIds"`
	AlertIDs       []string `json:"alertIds"`
}

func (p alertFilterParams) hasFilter() bool {
	return p.Query != "" || len(p.RuleName) > 0 || len(p.AgentName) > 0 ||
		len(p.IncidentStatus) > 0 || len(p.SiteIDs) > 0 || len(p.AlertIDs) > 0
}

func (p alertFilterParams) toClientFilter() client.AlertFilter {
	return client.AlertFilter{
		Query:            p.Query,
		RuleNameContains: p.RuleName,
		AgentNameContains: p.AgentName,
		IncidentStatus:   p.IncidentStatus,
		SiteIDs:          p.SiteIDs,
		IDs:              p.AlertIDs,
	}
}

func handleSetAlertVerdict(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		alertFilterParams
		Verdict string `json:"verdict"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if p.Verdict == "" {
		return toolError("verdict is required")
	}
	if !p.hasFilter() {
		return toolError("at least one filter is required (query, ruleName, agentName, incidentStatus, siteIds, or alertIds)")
	}

	affected, err := client.SetAlertVerdict(ctx, p.toClientFilter(), p.Verdict)
	if err != nil {
		return toolError(fmt.Sprintf("Error: %v", err))
	}

	return toolText(fmt.Sprintf("Done: analyst verdict set to %s on %d alert(s).", p.Verdict, affected))
}

func handleSetAlertStatus(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		alertFilterParams
		Status  string `json:"status"`
		Verdict string `json:"verdict"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if p.Status == "" {
		return toolError("status is required")
	}
	if !p.hasFilter() {
		return toolError("at least one filter is required (query, ruleName, agentName, incidentStatus, siteIds, or alertIds)")
	}

	filter := p.toClientFilter()

	// Set verdict first if requested (separate API call).
	var verdictMsg string
	if p.Verdict != "" {
		vAffected, err := client.SetAlertVerdict(ctx, filter, p.Verdict)
		if err != nil {
			return toolError(fmt.Sprintf("Error setting verdict: %v", err))
		}
		verdictMsg = fmt.Sprintf(" Analyst verdict set to %s on %d alert(s).", p.Verdict, vAffected)
	}

	affected, err := client.SetAlertStatus(ctx, filter, p.Status)
	if err != nil {
		msg := fmt.Sprintf("Error setting status: %v", err)
		if verdictMsg != "" {
			msg += fmt.Sprintf(" (note: verdict was already applied:%s)", verdictMsg)
		}
		return toolError(msg)
	}

	return toolText(fmt.Sprintf("Done: incident status set to %s on %d alert(s).%s", p.Status, affected, verdictMsg))
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
		result, err := client.QueryAlerts(ctx, client.AlertQueryOpts{
			Limit:          pageSize,
			Cursor:         cursor,
			Severity:       p.Severity,
			AnalystVerdict: p.AnalystVerdict,
			IncidentStatus: p.IncidentStatus,
			StorylineID:    p.StorylineID,
			SiteIDs:        p.SiteIDs,
		})
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

	// Use detailed format for small result sets, compact for large ones.
	if len(allAlerts) <= 10 {
		lines := make([]string, len(allAlerts))
		for i, a := range allAlerts {
			lines[i] = summarizeAlert(a)
		}
		return toolText(fmt.Sprintf("Found %d alert(s):\n\n%s", len(allAlerts), strings.Join(lines, "\n\n")))
	}

	header := alertSummaryHeader(allAlerts)
	lines := make([]string, len(allAlerts))
	for i, a := range allAlerts {
		lines[i] = summarizeAlertCompact(a)
	}
	return toolText(header + "\n" + strings.Join(lines, "\n"))
}
