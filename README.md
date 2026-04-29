# SentinelOne MCP Server

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/c0tton-fluff/sentinelone-mcp-server)](https://github.com/c0tton-fluff/sentinelone-mcp-server/releases)

A [Model Context Protocol](https://modelcontextprotocol.io/) server that connects AI assistants to your SentinelOne tenant. Manage threats, investigate endpoints, hunt with Deep Visibility, and triage alerts -- all from natural language.

**Zero dependencies.** Stdlib-only Go binary. No runtime requirements. Just copy and run.

---

## Quick Start

### 1. Build

```bash
git clone https://github.com/c0tton-fluff/sentinelone-mcp-server.git
cd sentinelone-mcp-server
go build -o sentinelone-mcp-server .
```

### 2. Get your API token

S1 Console > Profile (top right) > **My Profile** > Actions > **API token operations** > **Regenerate API token**

### 3. Configure your MCP client

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

### 4. Go

```
"List all unmitigated threats"
"Investigate threat 1234567890"
"Show infected agents"
"Hunt for PowerShell processes in the last 24 hours"
"What's the reputation of this SHA256?"
"Create an exclusion for /opt/myapp on Linux"
"What applications are installed on Benedict's laptop?"
```

---

## Tools (21)

### Threats

| Tool | What it does |
|------|--------------|
| `s1_list_threats` | List threats with classification, status, and endpoint filters |
| `s1_get_threat` | Full threat details -- hashes, file path, storyline |
| `s1_mitigate_threat` | Kill, quarantine, un-quarantine, remediate, or rollback |
| `s1_investigate_threat` | One-call investigation: threat + correlated alerts + timeline |
| `s1_set_analyst_verdict` | Set verdict: true_positive, false_positive, suspicious, undefined |
| `s1_set_incident_status` | Set status (with optional verdict in the same call) |

### Agents

| Tool | What it does |
|------|--------------|
| `s1_list_agents` | List agents with OS, status, infection filters, and count-by grouping |
| `s1_get_agent` | Agent details -- version, site, network info, account ID |
| `s1_isolate_agent` | Network isolate an endpoint (maintains S1 comms) |
| `s1_reconnect_agent` | Remove network isolation |

### Alerts

| Tool | What it does |
|------|--------------|
| `s1_list_alerts` | Query unified alerts via GraphQL with severity, verdict, and status filters |
| `s1_set_alert_verdict` | Bulk set analyst verdict on matching alerts |
| `s1_set_alert_status` | Bulk set incident status (with optional verdict) |

### Deep Visibility

| Tool | What it does |
|------|--------------|
| `s1_dv_query` | Run a threat hunting query with automatic polling |
| `s1_dv_get_events` | Retrieve events from a completed query |

### Intelligence

| Tool | What it does |
|------|--------------|
| `s1_hash_reputation` | Hash verdict + fleet-wide hunt via Deep Visibility |

### Exclusions

| Tool | What it does |
|------|--------------|
| `s1_list_exclusions` | List exclusions (path, hash, certificate, browser, file type) |
| `s1_create_exclusion` | Create an exclusion to suppress false-positive detections |
| `s1_delete_exclusion` | Delete exclusions by ID |

### STAR Rules

| Tool | What it does |
|------|--------------|
| `s1_create_star_rule` | Create a custom detection rule from a Deep Visibility query |

### Applications

| Tool | What it does |
|------|--------------|
| `s1_list_applications` | List installed software on endpoints by name or computer |

---

<details>
<summary><strong>Full parameter reference</strong></summary>

### s1_list_threats
| Parameter | Type | Description |
|-----------|------|-------------|
| `computerName` | string | Search by endpoint name (partial match) |
| `threatName` | string | Search by threat name (partial match) |
| `limit` | number | Max results (default 50, max 200) |
| `mitigationStatuses` | string[] | not_mitigated, mitigated, marked_as_benign |
| `classifications` | string[] | Malware, PUA, Suspicious |

### s1_get_threat
| Parameter | Type | Description |
|-----------|------|-------------|
| `threatId` | string | **Required.** The threat ID |

### s1_mitigate_threat
| Parameter | Type | Description |
|-----------|------|-------------|
| `threatId` | string | **Required.** The threat ID |
| `action` | string | **Required.** kill, quarantine, un-quarantine, remediate, rollback-remediation |

### s1_investigate_threat
| Parameter | Type | Description |
|-----------|------|-------------|
| `threatId` | string | **Required.** The threat ID |

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
| `verdict` | string | Optional: set analyst verdict in the same call |

### s1_list_agents
| Parameter | Type | Description |
|-----------|------|-------------|
| `computerName` | string | Search by computer name (partial match) |
| `limit` | number | Max results (default 50, max 200) |
| `osTypes` | string[] | windows, macos, linux |
| `isActive` | boolean | Filter by active status |
| `isInfected` | boolean | Filter by infected status |
| `networkStatuses` | string[] | connected, disconnected, connecting, disconnecting |
| `countBy` | string | Group counts by: user, os, site, group |

### s1_get_agent
| Parameter | Type | Description |
|-----------|------|-------------|
| `agentId` | string | **Required.** The agent ID |

### s1_isolate_agent / s1_reconnect_agent
| Parameter | Type | Description |
|-----------|------|-------------|
| `agentId` | string | **Required.** The agent ID |

### s1_list_alerts
| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | number | Max results (default 50, max 200) |
| `severity` | string | LOW, MEDIUM, HIGH, CRITICAL |
| `analystVerdict` | string | TRUE_POSITIVE, FALSE_POSITIVE, SUSPICIOUS, UNDEFINED |
| `incidentStatus` | string | NEW, IN_PROGRESS, RESOLVED (aliases: unresolved, open) |
| `siteIds` | string[] | Filter by site IDs |
| `storylineId` | string | Correlate with threat by storyline ID |

### s1_set_alert_verdict
| Parameter | Type | Description |
|-----------|------|-------------|
| `verdict` | string | **Required.** TRUE_POSITIVE, FALSE_POSITIVE, SUSPICIOUS, UNDEFINED |
| `alertIds` | string[] | Target specific alert IDs |
| `query` | string | Free-text search (use for username matching) |
| `ruleName` | string[] | Filter by rule name (partial match) |
| `agentName` | string[] | Filter by endpoint name, not username (partial match) |
| `incidentStatus` | string[] | Filter by current status |
| `siteIds` | string[] | Filter by site IDs |

### s1_set_alert_status
| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | **Required.** UNRESOLVED, IN_PROGRESS, RESOLVED |
| `verdict` | string | Optional: set analyst verdict in the same call |
| `alertIds` | string[] | Target specific alert IDs |
| `query` | string | Free-text search (use for username matching) |
| `ruleName` | string[] | Filter by rule name (partial match) |
| `agentName` | string[] | Filter by endpoint name, not username (partial match) |
| `incidentStatus` | string[] | Filter by current status |
| `siteIds` | string[] | Filter by site IDs |

### s1_hash_reputation
| Parameter | Type | Description |
|-----------|------|-------------|
| `hash` | string | **Required.** SHA1 (40 chars) or SHA256 (64 chars) |

### s1_dv_query
| Parameter | Type | Description |
|-----------|------|-------------|
| `query` | string | **Required.** Deep Visibility query (S1QL) |
| `fromDate` | string | **Required.** ISO format start date |
| `toDate` | string | **Required.** ISO format end date |
| `siteIds` | string[] | Filter by site IDs |
| `accountIds` | string[] | Filter by account IDs |

### s1_dv_get_events
| Parameter | Type | Description |
|-----------|------|-------------|
| `queryId` | string | **Required.** Query ID from s1_dv_query |
| `limit` | number | Max results (default 100, max 100) |

### s1_list_exclusions
| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | path, white_hash, certificate, browser, file_type |
| `value` | string | Search by exclusion value (partial match) |
| `osTypes` | string | windows, macos, linux (comma-separated) |
| `siteIds` | string[] | Filter by site IDs |
| `limit` | number | Max results (default 50, max 100) |

### s1_create_exclusion
| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | **Required.** path, white_hash, certificate, browser, file_type |
| `value` | string | **Required.** The value to exclude |
| `osType` | string | **Required.** windows, macos, linux |
| `siteIds` | string[] | Scope to specific sites (use s1_get_agent to find siteId) |
| `description` | string | Reason for the exclusion |
| `mode` | string | suppress, suppress_dynamic_only, disable_in_process_monitor, disable_all_monitors |
| `pathExclusionType` | string | subfolders (default) or file |

### s1_delete_exclusion
| Parameter | Type | Description |
|-----------|------|-------------|
| `ids` | string[] | **Required.** Exclusion IDs to delete |

### s1_create_star_rule
| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | **Required.** Rule name |
| `s1ql` | string | **Required.** Deep Visibility query that triggers the rule |
| `severity` | string | **Required.** Low, Medium, High, Critical |
| `siteIds` | string[] | Scope to sites |
| `accountIds` | string[] | Scope to accounts |
| `tenant` | boolean | Tenant-wide scope |
| `description` | string | What the rule detects |
| `treatAsThreat` | string | UNDEFINED (alert only), Suspicious, Malicious |
| `networkQuarantine` | boolean | Auto-isolate endpoint on trigger |
| `expirationMode` | string | Permanent (default) or Temporary |
| `expiration` | string | ISO date (required if Temporary) |
| `status` | string | Active (default), Draft, Disabled |

### s1_list_applications
| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Filter by app name (partial match) |
| `agentName` | string | Filter by endpoint name (partial match) |
| `limit` | number | Max results (default 50, max 1000) |

At least one of `name` or `agentName` is required.

</details>

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| Configuration error | Ensure `SENTINELONE_API_KEY` and `SENTINELONE_API_BASE` are set |
| API_BASE must be HTTPS | Use `https://` not `http://` for your tenant URL |
| HTTP 401 | API token expired or invalid -- regenerate in S1 console |
| HTTP 403 | Token lacks permissions for this endpoint |
| HTTP 429 | Rate limited -- server retries automatically with backoff |
| Request timeout | S1 API took >30s -- narrow your query filters |
| Tools not appearing | Verify binary path in `~/.mcp.json`, restart your MCP client |

MCP logs: `~/.cache/claude-cli-nodejs/*/mcp-logs-sentinelone/`

## License

MIT
