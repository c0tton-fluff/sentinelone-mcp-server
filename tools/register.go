package tools

import (
	"context"
	"encoding/json"
	"fmt"
)

// AllTools returns all MCP tool definitions.
func AllTools() []ToolDef {
	return []ToolDef{
		listThreatsTool,
		getThreatTool,
		mitigateThreatTool,
		setAnalystVerdictTool,
		setIncidentStatusTool,
		listAgentsTool,
		getAgentTool,
		isolateAgentTool,
		reconnectAgentTool,
		listAlertsTool,
		setAlertVerdictTool,
		setAlertStatusTool,
		hashReputationTool,
		dvQueryTool,
		dvGetEventsTool,
		investigateThreatTool,
	}
}

// DispatchTool routes a tool call to the appropriate handler.
func DispatchTool(ctx context.Context, name string, args json.RawMessage) ToolResult {
	switch name {
	case "s1_list_threats":
		return handleListThreats(ctx, args)
	case "s1_get_threat":
		return handleGetThreat(ctx, args)
	case "s1_mitigate_threat":
		return handleMitigateThreat(ctx, args)
	case "s1_set_analyst_verdict":
		return handleSetAnalystVerdict(ctx, args)
	case "s1_set_incident_status":
		return handleSetIncidentStatus(ctx, args)
	case "s1_list_agents":
		return handleListAgents(ctx, args)
	case "s1_get_agent":
		return handleGetAgent(ctx, args)
	case "s1_isolate_agent":
		return handleIsolateAgent(ctx, args)
	case "s1_reconnect_agent":
		return handleReconnectAgent(ctx, args)
	case "s1_list_alerts":
		return handleListAlerts(ctx, args)
	case "s1_set_alert_verdict":
		return handleSetAlertVerdict(ctx, args)
	case "s1_set_alert_status":
		return handleSetAlertStatus(ctx, args)
	case "s1_hash_reputation":
		return handleHashReputation(ctx, args)
	case "s1_dv_query":
		return handleDVQuery(ctx, args)
	case "s1_dv_get_events":
		return handleDVGetEvents(ctx, args)
	case "s1_investigate_threat":
		return handleInvestigateThreat(ctx, args)
	default:
		return toolError(fmt.Sprintf("unknown tool: %s", name))
	}
}
