package tools

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
	"github.com/mark3labs/mcp-go/mcp"
)

var listAgentsTool = mcp.NewTool("s1_list_agents",
	mcp.WithDescription("List SentinelOne agents with optional filters"),
	mcp.WithString("computerName",
		mcp.Description("Search by computer name (partial match)"),
	),
	mcp.WithNumber("limit",
		mcp.Description("Max results (default 50, max 200)"),
	),
	mcp.WithArray("osTypes",
		mcp.Description("Filter by OS: windows, macos, linux"),
		mcp.Items(map[string]any{"type": "string"}),
	),
	mcp.WithBoolean("isActive",
		mcp.Description("Filter by active status"),
	),
	mcp.WithBoolean("isInfected",
		mcp.Description("Filter by infected status"),
	),
	mcp.WithArray("networkStatuses",
		mcp.Description("Filter: connected, disconnected"),
		mcp.Items(map[string]any{"type": "string"}),
	),
	mcp.WithString("countBy",
		mcp.Description("Fetch all agents and group counts by field: user, os, site, group"),
	),
)

var getAgentTool = mcp.NewTool("s1_get_agent",
	mcp.WithDescription("Get a specific SentinelOne agent by ID"),
	mcp.WithString("agentId",
		mcp.Required(),
		mcp.Description("The agent ID to retrieve"),
	),
)

var isolateAgentTool = mcp.NewTool("s1_isolate_agent",
	mcp.WithDescription("Network isolate an agent (disconnect from network while maintaining S1 communication)"),
	mcp.WithString("agentId",
		mcp.Required(),
		mcp.Description("The agent ID to network isolate"),
	),
)

var reconnectAgentTool = mcp.NewTool("s1_reconnect_agent",
	mcp.WithDescription("Remove network isolation from an agent"),
	mcp.WithString("agentId",
		mcp.Required(),
		mcp.Description("The agent ID to reconnect"),
	),
)

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

func handleListAgents(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	countBy := req.GetString("countBy", "")
	limit := int(req.GetFloat("limit", 50))
	if limit < 1 || limit > 200 {
		limit = 50
	}

	q := url.Values{}
	q.Set("limit", "50")
	q.Set("sortBy", "updatedAt")
	q.Set("sortOrder", "desc")

	if v := req.GetString("computerName", ""); v != "" {
		q.Set("computerName__contains", v)
	}
	if v := req.GetStringSlice("osTypes", nil); len(v) > 0 {
		q.Set("osTypes", strings.Join(v, ","))
	}
	if v := req.GetStringSlice("networkStatuses", nil); len(v) > 0 {
		q.Set("networkStatuses", strings.Join(v, ","))
	}

	// Boolean filters: only set when explicitly provided
	args := req.GetArguments()
	if v, ok := args["isActive"].(bool); ok {
		q.Set("isActive", strconv.FormatBool(v))
	}
	if v, ok := args["isInfected"].(bool); ok {
		q.Set("isInfected", strconv.FormatBool(v))
	}

	// When countBy is set, fetch all agents (no limit)
	fetchAll := countBy != ""

	totalItems := 0
	var allAgents []map[string]any
	for {
		result, err := client.ListAgents(ctx, q)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
		}
		if result.Pagination != nil && totalItems == 0 {
			totalItems = result.Pagination.TotalItems
		}
		allAgents = append(allAgents, result.Data...)
		if (!fetchAll && len(allAgents) >= limit) || result.Pagination == nil || result.Pagination.NextCursor == "" {
			break
		}
		q.Set("cursor", result.Pagination.NextCursor)
	}

	// countBy mode: group all agents by a field and return counts
	if fetchAll {
		return handleCountBy(countBy, allAgents, totalItems)
	}

	if len(allAgents) > limit {
		allAgents = allAgents[:limit]
	}

	if len(allAgents) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("%d agents. None matched filters.", totalItems)), nil
	}

	lines := make([]string, len(allAgents))
	for i, a := range allAgents {
		lines[i] = summarizeAgent(a)
	}

	text := fmt.Sprintf("%d agents. Showing %d:\n\n%s", totalItems, len(allAgents), strings.Join(lines, "\n\n"))
	return mcp.NewToolResultText(text), nil
}

// countByFields maps friendly names to S1 agent JSON fields.
var countByFields = map[string]string{
	"user":  "lastLoggedInUserName",
	"os":    "osName",
	"site":  "siteName",
	"group": "groupName",
}

func handleCountBy(field string, agents []map[string]any, totalItems int) (*mcp.CallToolResult, error) {
	apiField, ok := countByFields[field]
	if !ok {
		valid := slices.Sorted(maps.Keys(countByFields))
		return mcp.NewToolResultError(fmt.Sprintf("Invalid countBy field %q. Valid: %s", field, strings.Join(valid, ", "))), nil
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

	text := fmt.Sprintf("%d agents, %d unique %s values:\n\n%s", totalItems, len(counts), field, strings.Join(lines, "\n"))
	return mcp.NewToolResultText(text), nil
}

func handleGetAgent(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	agentID, err := req.RequireString("agentId")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := client.GetAgent(ctx, agentID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
	}

	if len(result.Data) == 0 {
		return mcp.NewToolResultError(fmt.Sprintf("Agent %s not found", agentID)), nil
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

	return mcp.NewToolResultText(text), nil
}

func handleIsolateAgent(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	agentID, err := req.RequireString("agentId")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	affected, err := client.IsolateAgent(ctx, agentID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
	}

	return mcp.NewToolResultText(
		fmt.Sprintf("Done: Agent %s isolated. Affected: %d", agentID, affected),
	), nil
}

func handleReconnectAgent(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	agentID, err := req.RequireString("agentId")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	affected, err := client.ReconnectAgent(ctx, agentID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
	}

	return mcp.NewToolResultText(
		fmt.Sprintf("Done: Agent %s reconnected. Affected: %d", agentID, affected),
	), nil
}
