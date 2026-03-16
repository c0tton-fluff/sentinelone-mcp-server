package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
)

var listAgentsTool = ToolDef{
	Name:        "s1_list_agents",
	Description: "List SentinelOne agents with optional filters",
	InputSchema: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"computerName": map[string]any{
				"type":        "string",
				"description": "Search by computer name (partial match)",
			},
			"limit": map[string]any{
				"type":        "number",
				"description": "Max results (default 50, max 200)",
			},
			"osTypes": map[string]any{
				"type":        "array",
				"description": "Filter by OS: windows, macos, linux",
				"items":       map[string]any{"type": "string"},
			},
			"isActive": map[string]any{
				"type":        "boolean",
				"description": "Filter by active status",
			},
			"isInfected": map[string]any{
				"type":        "boolean",
				"description": "Filter by infected status",
			},
			"networkStatuses": map[string]any{
				"type":        "array",
				"description": "Filter: connected, disconnected",
				"items":       map[string]any{"type": "string"},
			},
			"countBy": map[string]any{
				"type":        "string",
				"description": "Fetch all agents and group counts by field: user, os, site, group",
			},
		},
	},
}

var getAgentTool = ToolDef{
	Name:        "s1_get_agent",
	Description: "Get a specific SentinelOne agent by ID",
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"agentId"},
		"properties": map[string]any{
			"agentId": map[string]any{
				"type":        "string",
				"description": "The agent ID to retrieve",
			},
		},
	},
}

var isolateAgentTool = ToolDef{
	Name:        "s1_isolate_agent",
	Description: "Network isolate an agent (disconnect from network while maintaining S1 communication)",
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"agentId"},
		"properties": map[string]any{
			"agentId": map[string]any{
				"type":        "string",
				"description": "The agent ID to network isolate",
			},
		},
	},
}

var reconnectAgentTool = ToolDef{
	Name:        "s1_reconnect_agent",
	Description: "Remove network isolation from an agent",
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"agentId"},
		"properties": map[string]any{
			"agentId": map[string]any{
				"type":        "string",
				"description": "The agent ID to reconnect",
			},
		},
	},
}

func summarizeAgent(a map[string]any) string {
	name := fallback(getStr(a, "computerName"), "Unknown")
	osInfo := fallback(getStr(a, "osName"), fallback(getStr(a, "osType"), "Unknown"))
	status := fallback(getStr(a, "networkStatus"), "unknown")
	infected := "clean"
	if getBool(a, "infected") {
		infected = "INFECTED"
	}
	lastActive := "unknown"
	if d := getStr(a, "lastActiveDate"); d != "" {
		lastActive = formatTimeAgo(d)
	}
	user := fallback(getStr(a, "lastLoggedInUserName"), "unknown")
	id := getStr(a, "id")
	ip := fallback(getStr(a, "externalIp"), fallback(getStr(a, "lastIpToMgmt"), "N/A"))

	return fmt.Sprintf("- %s | %s | %s | %s | %s\n  ID: %s | User: %s | IP: %s",
		name, osInfo, status, infected, lastActive, id, user, ip)
}

func handleListAgents(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		ComputerName    string   `json:"computerName"`
		Limit           int      `json:"limit"`
		OsTypes         []string `json:"osTypes"`
		IsActive        *bool    `json:"isActive"`
		IsInfected      *bool    `json:"isInfected"`
		NetworkStatuses []string `json:"networkStatuses"`
		CountBy         string   `json:"countBy"`
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
	q.Set("sortBy", "updatedAt")
	q.Set("sortOrder", "desc")

	if p.ComputerName != "" {
		q.Set("computerName__contains", p.ComputerName)
	}
	if len(p.OsTypes) > 0 {
		q.Set("osTypes", strings.Join(p.OsTypes, ","))
	}
	if len(p.NetworkStatuses) > 0 {
		q.Set("networkStatuses", strings.Join(p.NetworkStatuses, ","))
	}
	if p.IsActive != nil {
		q.Set("isActive", strconv.FormatBool(*p.IsActive))
	}
	if p.IsInfected != nil {
		q.Set("infected", strconv.FormatBool(*p.IsInfected))
	}

	// When countBy is set, fetch all agents (no limit)
	fetchAll := p.CountBy != ""

	totalItems := 0
	var allAgents []map[string]any
	for {
		result, err := client.ListAgents(ctx, q)
		if err != nil {
			return toolError(fmt.Sprintf("Error: %v", err))
		}
		if result.Pagination != nil && totalItems == 0 {
			totalItems = result.Pagination.TotalItems
		}
		allAgents = append(allAgents, result.Data...)
		if (!fetchAll && len(allAgents) >= p.Limit) || result.Pagination == nil || result.Pagination.NextCursor == "" {
			break
		}
		q.Set("cursor", result.Pagination.NextCursor)
	}

	// countBy mode: group all agents by a field and return counts
	if fetchAll {
		return handleCountBy(p.CountBy, allAgents, totalItems)
	}

	if len(allAgents) > p.Limit {
		allAgents = allAgents[:p.Limit]
	}

	if len(allAgents) == 0 {
		return toolText(fmt.Sprintf("%d agents. None matched filters.", totalItems))
	}

	lines := make([]string, len(allAgents))
	for i, a := range allAgents {
		lines[i] = summarizeAgent(a)
	}

	return toolText(fmt.Sprintf("%d agents. Showing %d:\n\n%s", totalItems, len(allAgents), strings.Join(lines, "\n\n")))
}

// countByFields maps friendly names to S1 agent JSON fields.
var countByFields = map[string]string{
	"user":  "lastLoggedInUserName",
	"os":    "osName",
	"site":  "siteName",
	"group": "groupName",
}

func handleCountBy(field string, agents []map[string]any, totalItems int) ToolResult {
	apiField, ok := countByFields[field]
	if !ok {
		valid := slices.Sorted(maps.Keys(countByFields))
		return toolError(fmt.Sprintf("Invalid countBy field %q. Valid: %s", field, strings.Join(valid, ", ")))
	}

	counts := map[string]int{}
	for _, a := range agents {
		val := fallback(getStr(a, apiField), "(empty)")
		counts[val]++
	}

	// Sort by count descending
	type kv struct {
		Key   string
		Count int
	}
	sorted := make([]kv, 0, len(counts))
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	slices.SortFunc(sorted, func(a, b kv) int {
		return b.Count - a.Count
	})

	lines := make([]string, len(sorted))
	for i, s := range sorted {
		lines[i] = fmt.Sprintf("  %s: %d", s.Key, s.Count)
	}

	return toolText(fmt.Sprintf("%d agents, %d unique %s values:\n\n%s", totalItems, len(counts), field, strings.Join(lines, "\n")))
}

func handleGetAgent(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		AgentID string `json:"agentId"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if p.AgentID == "" {
		return toolError("agentId is required")
	}

	result, err := client.GetAgent(ctx, p.AgentID)
	if err != nil {
		return toolError(fmt.Sprintf("Error: %v", err))
	}

	if len(result.Data) == 0 {
		return toolError(fmt.Sprintf("Agent %s not found", p.AgentID))
	}

	a := result.Data[0]
	infectedStr := "No"
	if getBool(a, "infected") {
		infectedStr = "YES"
	}
	activeStr := "No"
	if getBool(a, "isActive") {
		activeStr = "Yes"
	}

	text := fmt.Sprintf(`Agent Details:
---
Computer: %s
OS: %s %s
Status: %s
Infected: %s
Active: %s
---
ID: %s
UUID: %s
Domain: %s
Site: %s
Group: %s
---
Last Active: %s
User: %s
External IP: %s
Agent Version: %s`,
		fallback(getStr(a, "computerName"), "Unknown"),
		fallback(getStr(a, "osName"), "Unknown"),
		getStr(a, "osRevision"),
		fallback(getStr(a, "networkStatus"), "Unknown"),
		infectedStr,
		activeStr,
		getStr(a, "id"),
		fallback(getStr(a, "uuid"), "N/A"),
		fallback(getStr(a, "domain"), "N/A"),
		fallback(getStr(a, "siteName"), "N/A"),
		fallback(getStr(a, "groupName"), "N/A"),
		fallback(getStr(a, "lastActiveDate"), "Unknown"),
		fallback(getStr(a, "lastLoggedInUserName"), "Unknown"),
		fallback(getStr(a, "externalIp"), "N/A"),
		fallback(getStr(a, "agentVersion"), "N/A"),
	)

	return toolText(text)
}

func handleIsolateAgent(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		AgentID string `json:"agentId"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if p.AgentID == "" {
		return toolError("agentId is required")
	}

	affected, err := client.IsolateAgent(ctx, p.AgentID)
	if err != nil {
		return toolError(fmt.Sprintf("Error: %v", err))
	}

	return toolText(fmt.Sprintf("Done: Agent %s isolated. Affected: %d", p.AgentID, affected))
}

func handleReconnectAgent(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		AgentID string `json:"agentId"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if p.AgentID == "" {
		return toolError("agentId is required")
	}

	affected, err := client.ReconnectAgent(ctx, p.AgentID)
	if err != nil {
		return toolError(fmt.Sprintf("Error: %v", err))
	}

	return toolText(fmt.Sprintf("Done: Agent %s reconnected. Affected: %d", p.AgentID, affected))
}
