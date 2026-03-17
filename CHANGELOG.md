# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Hash verdict lookup via `GET /hashes/{hash}/verdict` — `s1_hash_reputation` now returns instant S1 verdict before DV fleet hunt
- Threat timeline via `GET /threats/{id}/timeline` — `s1_investigate_threat` uses dedicated API instead of DV queries (faster, no rate-limit impact)
- `un-quarantine` mitigation action on `s1_mitigate_threat`
- `s1_set_analyst_verdict` tool — set analyst verdict on a threat (true_positive, false_positive, suspicious, undefined)
- `s1_set_incident_status` tool — set incident status on a threat (unresolved, in_progress, resolved) with optional verdict in one call

### Fixed
- Agent `infected` filter was sent as `isInfected` (silently ignored by S1 API)
- DV query status polling: handle all terminal states (`QUERY_CANCELLED`, `FAILED_CLIENT`, `ERROR`, `TIMED_OUT`, `QUERY_EXPIRED`)
- Remove unsupported `groupIds` parameter from DV init-query
- `networkStatuses` filter description now includes `connecting`/`disconnecting`

### Changed
- Bump Go version from 1.23 to 1.26
- Replace `mcp-go` framework with stdlib-only MCP/JSON-RPC implementation (zero external dependencies)
- Modernize loops and sort calls to use Go 1.22+ range-over-int and `slices`/`maps` packages
- Cap HTTP 429 retry backoff at 60 seconds

## [1.5.0] - 2026-03-15

### Added
- `s1_investigate_threat` tool — full investigation in one call (threat details, correlated alerts, DV timeline)
- `countBy` parameter on `s1_list_agents` — group agent counts by user, os, site, or group
- Auto-pagination on all list tools (`s1_list_threats`, `s1_list_agents`, `s1_list_alerts`)
- Configurable limits up to 200 results on list tools (was capped at 50)
- HTTP 429 retry with exponential backoff and `Retry-After` header support
- DV query validation: reject invalid fields (ObjectType), auto-fix backslash-quote issues, reject mixed AND/OR without parentheses
- Retry on 409 for DV query creation and event retrieval
- S1QL syntax reference in DV tool descriptions

### Fixed
- Alert status filter normalization (accept "unresolved", "open", "inprogress" as aliases)
- DV query status parsing (`responseState` field, not `status`)
- DV polling loop only breaks on terminal states (FINISHED, FAILED, CANCELED)

### Security
- Enforce HTTPS on API base URL — reject http:// to prevent cleartext API key transmission

## [1.0.0] - 2026-02-14

### Added
- Initial release
- SentinelOne REST API client with API key authentication
- GraphQL client for Unified Alerts with edge/node pagination
- 11 MCP tools for SentinelOne integration:
  - `s1_list_threats` - List threats with classification, status, and computer filters
  - `s1_get_threat` - Get threat details including hashes, file path, and storyline
  - `s1_mitigate_threat` - Kill, quarantine, remediate, or rollback threats
  - `s1_list_agents` - List agents with OS, status, and infection filters
  - `s1_get_agent` - Get agent details including version, site, and network info
  - `s1_isolate_agent` - Network isolate an endpoint
  - `s1_reconnect_agent` - Remove network isolation
  - `s1_list_alerts` - Query unified alerts via GraphQL with severity and verdict filters
  - `s1_hash_reputation` - SHA1/SHA256 hash reputation lookup
  - `s1_dv_query` - Run Deep Visibility queries with automatic polling
  - `s1_dv_get_events` - Retrieve Deep Visibility query results with pagination
- API key sanitization in error messages
- Configurable via environment variables (SENTINELONE_API_KEY, SENTINELONE_API_BASE)
