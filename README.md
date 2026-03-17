# sentinelone-mcp-server

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/c0tton-fluff/sentinelone-mcp-server)](https://github.com/c0tton-fluff/sentinelone-mcp-server/releases)

MCP server for [SentinelOne](https://www.sentinelone.com/) integration. Enables AI assistants like Claude Code to manage threats, investigate endpoints, query alerts, and run Deep Visibility hunts.

## Features

- **Threat management** - List, inspect, mitigate, and triage threats (verdict, status, kill, quarantine, remediate)
- **Threat investigation** - Full investigation in one call: threat details, correlated alerts, and timeline
- **Agent operations** - List agents, get details, group counts, network isolate/reconnect endpoints
- **Unified alerts** - Query alerts via GraphQL with severity, verdict, and storyline filters
- **Hash intelligence** - Instant hash verdict plus SHA1/SHA256 fleet-wide hunting via Deep Visibility
- **Deep Visibility** - Run threat hunting queries with automatic polling and pagination
- **Error sanitization** - API keys are redacted from all error messages
- **Zero dependencies** - stdlib-only Go binary, no external packages
- **Single binary** - No runtime dependencies, just copy and run

## Installation

```bash
git clone https://github.com/c0tton-fluff/sentinelone-mcp-server.git
cd sentinelone-mcp-server
go build -o sentinelone-mcp-server .
```

## Quick Start

**1. Get your SentinelOne API token**

Log into your S1 console > Profile icon (top right) > **My Profile** > Actions > **API token operations** > **Regenerate API token**.

**2. Configure MCP client**

Add to `~/.mcp.json`:

```json
{
  "mcpServers": {
    "sentinelone": {
      "command": "/path/to/sentinelone-mcp-server",
      "env": {
        "SENTINELONE_API_KEY": "your_api_token_here",
        "SENTINELONE_API_BASE": "https://your-tenant.sentinelone.net"
      }
    }
  }
}
```

**3. Use with Claude Code**

```
"List all unmitigated threats"
"Investigate threat 1234567890"
"Show infected agents"
"How many agents per OS?"
"Isolate agent 1234567890"
"What's the reputation of this SHA256?"
"Hunt for PowerShell processes in the last 24 hours"
"Show high severity alerts"
```

## Tools Reference

### Threats

| Tool | Description |
|------|-------------|
| `s1_list_threats` | List threats with classification, status, and computer filters |
| `s1_get_threat` | Get threat details including hashes, file path, and storyline |
| `s1_mitigate_threat` | Kill, quarantine, un-quarantine, remediate, or rollback a threat |
| `s1_investigate_threat` | Full investigation: threat details, correlated alerts, and timeline |
| `s1_set_analyst_verdict` | Set analyst verdict: true_positive, false_positive, suspicious, undefined |
| `s1_set_incident_status` | Set incident status (with optional verdict in one call) |

### Agents

| Tool | Description |
|------|-------------|
| `s1_list_agents` | List agents with OS, status, infection filters, and count-by grouping |
| `s1_get_agent` | Get agent details including version, site, and network info |
| `s1_isolate_agent` | Network isolate an endpoint (maintains S1 communication) |
| `s1_reconnect_agent` | Remove network isolation from an agent |

### Alerts

| Tool | Description |
|------|-------------|
| `s1_list_alerts` | Query unified alerts via GraphQL with severity and verdict filters |

### Intelligence

| Tool | Description |
|------|-------------|
| `s1_hash_reputation` | Hash verdict lookup plus fleet-wide hunt via Deep Visibility |

### Deep Visibility

| Tool | Description |
|------|-------------|
| `s1_dv_query` | Run a Deep Visibility query with automatic status polling |
| `s1_dv_get_events` | Retrieve events from a completed DV query |

<details>
<summary>Full parameter reference</summary>

### s1_list_threats
| Parameter | Type | Description |
|-----------|------|-------------|
| `computerName` | string | Search by computer/endpoint name (partial match) |
| `threatName` | string | Search by threat name (partial match) |
| `limit` | number | Max results (default 50, max 200) |
| `mitigationStatuses` | string[] | Filter: not_mitigated, mitigated, marked_as_benign |
| `classifications` | string[] | Filter: Malware, PUA, Suspicious |

### s1_get_threat
| Parameter | Type | Description |
|-----------|------|-------------|
| `threatId` | string | **Required.** The threat ID to retrieve |

### s1_mitigate_threat
| Parameter | Type | Description |
|-----------|------|-------------|
| `threatId` | string | **Required.** The threat ID to mitigate |
| `action` | string | **Required.** kill, quarantine, un-quarantine, remediate, rollback-remediation |

### s1_investigate_threat
| Parameter | Type | Description |
|-----------|------|-------------|
| `threatId` | string | **Required.** The threat ID to investigate |

### s1_set_analyst_verdict
| Parameter | Type | Description |
|-----------|------|-------------|
| `threatId` | string | **Required.** The threat ID |
| `verdict` | string | **Required.** true_positive, false_positive, suspicious, undefined |

### s1_set_incident_status
| Parameter | Type | Description |
|-----------|------|-------------|
| `threatId` | string | **Required.** The threat ID |
| `status` | string | **Required.** unresolved, in_progress, resolved |
| `verdict` | string | Optional: also set analyst verdict in the same call |

### s1_list_agents
| Parameter | Type | Description |
|-----------|------|-------------|
| `computerName` | string | Search by computer name (partial match) |
| `limit` | number | Max results (default 50, max 200) |
| `osTypes` | string[] | Filter by OS: windows, macos, linux |
| `isActive` | boolean | Filter by active status |
| `isInfected` | boolean | Filter by infected status |
| `networkStatuses` | string[] | Filter: connected, disconnected, connecting, disconnecting |
| `countBy` | string | Group counts by field: user, os, site, group |

### s1_get_agent
| Parameter | Type | Description |
|-----------|------|-------------|
| `agentId` | string | **Required.** The agent ID to retrieve |

### s1_isolate_agent / s1_reconnect_agent
| Parameter | Type | Description |
|-----------|------|-------------|
| `agentId` | string | **Required.** The agent ID |

### s1_list_alerts
| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | number | Max results (default 50, max 200) |
| `severity` | string | Filter: LOW, MEDIUM, HIGH, CRITICAL (case-insensitive) |
| `analystVerdict` | string | Filter: TRUE_POSITIVE, FALSE_POSITIVE, SUSPICIOUS, UNDEFINED (case-insensitive) |
| `incidentStatus` | string | Filter: NEW, IN_PROGRESS, RESOLVED (case-insensitive). Aliases: unresolved, open |
| `siteIds` | string[] | Filter by site IDs |
| `storylineId` | string | Filter by storyline ID (correlate with threat) |

### s1_hash_reputation
| Parameter | Type | Description |
|-----------|------|-------------|
| `hash` | string | **Required.** SHA1 (40 chars) or SHA256 (64 chars) hash |

### s1_dv_query
| Parameter | Type | Description |
|-----------|------|-------------|
| `query` | string | **Required.** Deep Visibility query (S1QL syntax) |
| `fromDate` | string | **Required.** Start date in ISO format |
| `toDate` | string | **Required.** End date in ISO format |
| `siteIds` | string[] | Filter by site IDs |
| `accountIds` | string[] | Filter by account IDs |

### s1_dv_get_events
| Parameter | Type | Description |
|-----------|------|-------------|
| `queryId` | string | **Required.** Query ID from s1_dv_query |
| `limit` | number | Max results (default 100, max 100) |

</details>

## Troubleshooting

| Error | Fix |
|-------|-----|
| Configuration error | Ensure SENTINELONE_API_KEY and SENTINELONE_API_BASE are set |
| SENTINELONE_API_BASE must be HTTPS | Use `https://` not `http://` for your tenant URL |
| HTTP 401 | API token expired or invalid - regenerate in S1 console |
| HTTP 403 | Token lacks permissions for this endpoint |
| HTTP 429 | Rate limited - server retries automatically with backoff |
| Request timeout | S1 API took >30s - try narrowing your query filters |
| Tools not appearing | Verify binary path in `~/.mcp.json`, restart Claude Code |

Check MCP logs: `~/.cache/claude-cli-nodejs/*/mcp-logs-sentinelone/`

## License

MIT
