package tools

import "github.com/mark3labs/mcp-go/server"

func Register(s *server.MCPServer) {
	s.AddTool(listThreatsTool, handleListThreats)
	s.AddTool(getThreatTool, handleGetThreat)
	s.AddTool(mitigateThreatTool, handleMitigateThreat)

	s.AddTool(listAgentsTool, handleListAgents)
	s.AddTool(getAgentTool, handleGetAgent)
	s.AddTool(isolateAgentTool, handleIsolateAgent)
	s.AddTool(reconnectAgentTool, handleReconnectAgent)

	s.AddTool(listAlertsTool, handleListAlerts)

	s.AddTool(hashReputationTool, handleHashReputation)

	s.AddTool(dvQueryTool, handleDVQuery)
	s.AddTool(dvGetEventsTool, handleDVGetEvents)

	s.AddTool(investigateThreatTool, handleInvestigateThreat)
}
