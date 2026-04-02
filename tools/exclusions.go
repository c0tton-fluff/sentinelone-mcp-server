package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
)

var listExclusionsTool = ToolDef{
	Name:        "s1_list_exclusions",
	Description: "List SentinelOne exclusions (path, hash, certificate, browser, file type)",
	InputSchema: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"type": map[string]any{
				"type":        "string",
				"description": "Filter by exclusion type",
				"enum":        []string{"path", "white_hash", "certificate", "browser", "file_type"},
			},
			"osTypes": map[string]any{
				"type":        "string",
				"description": "Filter by OS: windows, macos, linux (comma-separated for multiple)",
			},
			"limit": map[string]any{
				"type":        "number",
				"description": "Max results (default 50, max 100)",
			},
			"value": map[string]any{
				"type":        "string",
				"description": "Search by exclusion value (partial match)",
			},
			"siteIds": map[string]any{
				"type":        "array",
				"description": "Filter by site IDs",
				"items":       map[string]any{"type": "string"},
			},
		},
	},
}

var createExclusionTool = ToolDef{
	Name:        "s1_create_exclusion",
	Description: "Create a SentinelOne exclusion rule to suppress false-positive detections.\n\nPath exclusion modes:\n  suppress — suppress all static and dynamic detections\n  suppress_dynamic_only — suppress only behavioral/dynamic detections\n  disable_in_process_monitor — exclude from process monitoring\n  disable_all_monitors — exclude from all monitors\n\nPath types (pathExclusionType):\n  subfolders — match everything under the path\n  file — match the exact file only",
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"type", "value", "osType"},
		"properties": map[string]any{
			"type": map[string]any{
				"type":        "string",
				"description": "Exclusion type",
				"enum":        []string{"path", "white_hash", "certificate", "browser", "file_type"},
			},
			"value": map[string]any{
				"type":        "string",
				"description": "The value to exclude (path, hash, etc.)",
			},
			"osType": map[string]any{
				"type":        "string",
				"description": "Target OS",
				"enum":        []string{"windows", "macos", "linux"},
			},
			"description": map[string]any{
				"type":        "string",
				"description": "Human-readable reason for this exclusion",
			},
			"mode": map[string]any{
				"type":        "string",
				"description": "Exclusion mode (path type only, default: suppress)",
				"enum":        []string{"suppress", "suppress_dynamic_only", "disable_in_process_monitor", "disable_all_monitors"},
			},
			"pathExclusionType": map[string]any{
				"type":        "string",
				"description": "For path exclusions: match subfolders or exact file (default: subfolders)",
				"enum":        []string{"subfolders", "file"},
			},
			"siteIds": map[string]any{
				"type":        "array",
				"description": "Scope to specific site IDs (required — use s1_get_agent to find the siteId)",
				"items":       map[string]any{"type": "string"},
			},
		},
	},
}

var deleteExclusionTool = ToolDef{
	Name:        "s1_delete_exclusion",
	Description: "Delete one or more SentinelOne exclusions by ID",
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"ids"},
		"properties": map[string]any{
			"ids": map[string]any{
				"type":        "array",
				"description": "Exclusion IDs to delete",
				"items":       map[string]any{"type": "string"},
			},
		},
	},
}

func summarizeExclusion(e map[string]any) string {
	id := getStr(e, "id")
	exType := fallback(getStr(e, "type"), "unknown")
	value := fallback(getStr(e, "value"), "N/A")
	osType := fallback(getStr(e, "osType"), "any")
	mode := getStr(e, "mode")
	desc := getStr(e, "description")

	line := fmt.Sprintf("- [%s] %s | %s | OS: %s", exType, value, id, osType)
	if mode != "" {
		line += " | Mode: " + mode
	}
	if desc != "" {
		line += "\n  Description: " + desc
	}
	return line
}

func handleListExclusions(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		Type    string   `json:"type"`
		OSTypes string   `json:"osTypes"`
		Limit   int      `json:"limit"`
		Value   string   `json:"value"`
		SiteIDs []string `json:"siteIds"`
	}
	p.Limit = 50
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if p.Limit < 1 || p.Limit > 100 {
		p.Limit = 50
	}

	q := url.Values{}
	q.Set("limit", fmt.Sprintf("%d", p.Limit))
	q.Set("sortBy", "updatedAt")
	q.Set("sortOrder", "desc")
	if p.Type != "" {
		q.Set("type", p.Type)
	}
	if p.OSTypes != "" {
		q.Set("osTypes", p.OSTypes)
	}
	if p.Value != "" {
		q.Set("value__contains", p.Value)
	}
	if len(p.SiteIDs) > 0 {
		q.Set("siteIds", strings.Join(p.SiteIDs, ","))
	}

	result, err := client.ListExclusions(ctx, q)
	if err != nil {
		return toolError(fmt.Sprintf("Error listing exclusions: %v", err))
	}

	if len(result.Data) == 0 {
		return toolText("No exclusions found matching criteria.")
	}

	lines := make([]string, len(result.Data))
	for i, e := range result.Data {
		lines[i] = summarizeExclusion(e)
	}

	total := ""
	if result.Pagination != nil && result.Pagination.TotalItems > 0 {
		total = fmt.Sprintf(" (total: %d)", result.Pagination.TotalItems)
	}

	return toolText(fmt.Sprintf("Found %d exclusion(s)%s:\n\n%s", len(result.Data), total, strings.Join(lines, "\n\n")))
}

func handleCreateExclusion(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		Type              string   `json:"type"`
		Value             string   `json:"value"`
		OSType            string   `json:"osType"`
		Description       string   `json:"description"`
		Mode              string   `json:"mode"`
		PathExclusionType string   `json:"pathExclusionType"`
		SiteIDs           []string `json:"siteIds"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if p.Type == "" {
		return toolError("type is required")
	}
	if p.Value == "" {
		return toolError("value is required")
	}
	if p.OSType == "" {
		return toolError("osType is required")
	}

	data := map[string]any{
		"type":   p.Type,
		"value":  p.Value,
		"osType": p.OSType,
	}
	if p.Description != "" {
		data["description"] = p.Description
	}
	if p.Type == "path" {
		if p.Mode == "" {
			p.Mode = "suppress"
		}
		data["mode"] = p.Mode
		if p.PathExclusionType != "" {
			data["pathExclusionType"] = p.PathExclusionType
		}
	}

	resp, err := client.CreateExclusion(ctx, data, p.SiteIDs)
	if err != nil {
		return toolError(fmt.Sprintf("Error creating exclusion: %v", err))
	}

	var id string
	if len(resp.Data) > 0 {
		id = getStr(resp.Data[0], "id")
	}
	return toolText(fmt.Sprintf("Exclusion created successfully.\nID: %s\nType: %s\nValue: %s\nOS: %s", id, p.Type, p.Value, p.OSType))
}

func handleDeleteExclusion(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		IDs []string `json:"ids"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if len(p.IDs) == 0 {
		return toolError("ids is required (at least one exclusion ID)")
	}

	affected, err := client.DeleteExclusion(ctx, p.IDs)
	if err != nil {
		return toolError(fmt.Sprintf("Error deleting exclusion(s): %v", err))
	}

	return toolText(fmt.Sprintf("Deleted %d exclusion(s).", affected))
}
