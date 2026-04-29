package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
)

var listApplicationsTool = ToolDef{
	Name:        "s1_list_applications",
	Description: "List installed applications on endpoints. Useful for checking software versions, identifying risky software, or verifying installations.",
	InputSchema: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "Filter by application name (partial match, e.g. \"Chrome\", \"T3 Code\")",
			},
			"agentName": map[string]any{
				"type":        "string",
				"description": "Filter by endpoint/computer name (partial match, e.g. \"Benedict\")",
			},
			"limit": map[string]any{
				"type":        "number",
				"description": "Max results (default 50, max 1000)",
			},
		},
	},
}

func handleListApplications(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		Name      string `json:"name"`
		AgentName string `json:"agentName"`
		Limit     int    `json:"limit"`
	}
	p.Limit = 50
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if p.Limit < 1 || p.Limit > 1000 {
		p.Limit = 50
	}
	if p.Name == "" && p.AgentName == "" {
		return toolError("at least one of 'name' or 'agentName' is required")
	}

	q := url.Values{}
	q.Set("limit", fmt.Sprintf("%d", p.Limit))
	if p.Name != "" {
		q.Set("name__contains", p.Name)
	}
	if p.AgentName != "" {
		q.Set("agentComputerName__contains", p.AgentName)
	}

	result, err := client.ListInstalledApplications(ctx, q)
	if err != nil {
		return toolError(fmt.Sprintf("Error listing applications: %v", err))
	}

	if len(result.Data) == 0 {
		return toolText("No applications found matching criteria.")
	}

	lines := make([]string, 0, len(result.Data))
	for _, app := range result.Data {
		name := fallback(getStr(app, "name"), "Unknown")
		version := fallback(getStr(app, "version"), "?")
		publisher := fallback(getStr(app, "publisher"), "?")
		endpoint := fallback(getStr(app, "agentComputerName"), "?")
		riskLevel := getStr(app, "riskLevel")

		line := fmt.Sprintf("- %s v%s | %s | %s", name, version, publisher, endpoint)
		if riskLevel != "" && riskLevel != "none" {
			line += " | Risk: " + riskLevel
		}
		lines = append(lines, line)
	}

	return toolText(fmt.Sprintf("Found %d application(s):\n\n%s", len(result.Data), strings.Join(lines, "\n")))
}
