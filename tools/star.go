package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
)

var createSTARRuleTool = ToolDef{
	Name: "s1_create_star_rule",
	Description: `Create a STAR (Custom Detection) Rule in SentinelOne.

Creates an "events" type rule from a Deep Visibility query (S1QL). The rule
fires alerts whenever the query matches new telemetry on endpoints.

Required fields: name, s1ql, severity, scope (one of siteIds, accountIds, or tenant).
Optional: description, treatAsThreat, networkQuarantine, expirationMode, expiration, status.

The rule is created as Active by default. Set status to "Draft" or "Disabled" to
create without immediately activating.

Example — detect DNS lookups for a suspicious domain:
  name: "DNS - evil.com access detected"
  s1ql: "DnsRequest Contains \"evil.com\""
  severity: "High"
  treatAsThreat: "Suspicious"`,
	InputSchema: map[string]any{
		"type":     "object",
		"required": []string{"name", "s1ql", "severity"},
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "Rule name",
			},
			"s1ql": map[string]any{
				"type":        "string",
				"description": "Deep Visibility query (S1QL) that triggers the rule",
			},
			"severity": map[string]any{
				"type":        "string",
				"description": "Alert severity",
				"enum":        []string{"Low", "Medium", "High", "Critical"},
			},
			"description": map[string]any{
				"type":        "string",
				"description": "Human-readable description of what this rule detects",
			},
			"treatAsThreat": map[string]any{
				"type":        "string",
				"description": "Auto-response classification (default: UNDEFINED — alert only)",
				"enum":        []string{"UNDEFINED", "Suspicious", "Malicious"},
			},
			"networkQuarantine": map[string]any{
				"type":        "boolean",
				"description": "Automatically isolate the endpoint when triggered (default: false)",
			},
			"expirationMode": map[string]any{
				"type":        "string",
				"description": "Permanent or Temporary (default: Permanent)",
				"enum":        []string{"Permanent", "Temporary"},
			},
			"expiration": map[string]any{
				"type":        "string",
				"description": "Expiration date in ISO format (required if expirationMode is Temporary)",
			},
			"status": map[string]any{
				"type":        "string",
				"description": "Rule status (default: Active)",
				"enum":        []string{"Active", "Draft", "Disabled"},
			},
			"siteIds": map[string]any{
				"type":        "array",
				"description": "Scope to specific sites",
				"items":       map[string]any{"type": "string"},
			},
			"accountIds": map[string]any{
				"type":        "array",
				"description": "Scope to specific accounts",
				"items":       map[string]any{"type": "string"},
			},
			"tenant": map[string]any{
				"type":        "boolean",
				"description": "Set to true for global (tenant-wide) scope",
			},
		},
	},
}

func handleCreateSTARRule(ctx context.Context, args json.RawMessage) ToolResult {
	var p struct {
		Name               string   `json:"name"`
		S1QL               string   `json:"s1ql"`
		Severity           string   `json:"severity"`
		Description        string   `json:"description"`
		TreatAsThreat      string   `json:"treatAsThreat"`
		NetworkQuarantine  bool     `json:"networkQuarantine"`
		ExpirationMode     string   `json:"expirationMode"`
		Expiration         string   `json:"expiration"`
		Status             string   `json:"status"`
		SiteIDs            []string `json:"siteIds"`
		AccountIDs         []string `json:"accountIds"`
		Tenant             bool     `json:"tenant"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if p.Name == "" {
		return toolError("name is required")
	}
	if p.S1QL == "" {
		return toolError("s1ql is required")
	}
	if p.Severity == "" {
		return toolError("severity is required")
	}

	// Validate the DV query syntax.
	s1ql, warning, err := validateDVQuery(p.S1QL)
	if err != nil {
		return toolError(fmt.Sprintf("Invalid s1ql: %v", err))
	}

	// Require at least one scope.
	if len(p.SiteIDs) == 0 && len(p.AccountIDs) == 0 && !p.Tenant {
		return toolError("scope is required: provide siteIds, accountIds, or set tenant to true")
	}

	// Defaults.
	if p.ExpirationMode == "" {
		p.ExpirationMode = "Permanent"
	}
	if p.Status == "" {
		p.Status = "Active"
	}
	if p.TreatAsThreat == "" {
		p.TreatAsThreat = "UNDEFINED"
	}

	data := map[string]any{
		"name":              p.Name,
		"queryType":         "events",
		"s1ql":              s1ql,
		"severity":          p.Severity,
		"status":            p.Status,
		"expirationMode":    p.ExpirationMode,
		"treatAsThreat":     p.TreatAsThreat,
		"networkQuarantine": p.NetworkQuarantine,
	}
	if p.Description != "" {
		data["description"] = p.Description
	}
	if p.Expiration != "" {
		data["expiration"] = p.Expiration
	}

	filter := map[string]any{}
	if len(p.SiteIDs) > 0 {
		filter["siteIds"] = p.SiteIDs
	}
	if len(p.AccountIDs) > 0 {
		filter["accountIds"] = p.AccountIDs
	}
	if p.Tenant {
		filter["tenant"] = true
	}

	resp, err := client.CreateSTARRule(ctx, data, filter)
	if err != nil {
		return toolError(fmt.Sprintf("Error creating STAR rule: %v", err))
	}

	id := getStr(resp, "id")
	name := getStr(resp, "name")
	status := getStr(resp, "status")
	creator := getStr(resp, "creator")

	msg := fmt.Sprintf("STAR rule created successfully.\nID: %s\nName: %s\nStatus: %s\nSeverity: %s\nQuery: %s",
		id, name, status, p.Severity, s1ql)
	if creator != "" {
		msg += "\nCreator: " + creator
	}
	if warning != "" {
		msg += "\n\nNote: " + warning
	}

	return toolText(msg)
}
