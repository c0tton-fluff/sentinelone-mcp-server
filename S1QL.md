# S1QL / Deep Visibility Query Language - Research Findings

Research conducted 2026-03-13 to understand the S1QL query language,
specifically parenthesized grouping and AND/OR mixing.

## Sources

### 1. SentineLabs/S1QL-Queries (Official SentinelOne Research)
- **URL**: https://github.com/SentineLabs/S1QL-Queries
- 21 YAML query files for threat detection
- Schema tracks: title, description, author, version, operating_system, query, tags, s1ql supported version
- **S1QL version**: All queries target version 3+

### 2. keyboardcrunch/sentinelone-queries (Community)
- **URL**: https://github.com/keyboardcrunch/sentinelone-queries
- Organized by: `apt/`, `linux/`, `windows/`
- YAML format with same schema as SentineLabs

### 3. Blink Ops Integration Docs
- **URL**: https://docs.blinkops.com/docs/integrations/sentinelone/actions/deep-visibility-query
- Confirms query language is called "S1QL" (SentinelOne Query Language)
- References S1QL Cheatsheet PDF at: https://assets.sentinelone.com/dv/sentinel-one-dv-chea-1
  (PDF redirects to marketing page, not directly accessible)

### 4. SentinelOne Blog - Rapid Threat Hunting with Deep Visibility
- **URL**: https://www.sentinelone.com/blog/rapid-threat-hunting-with-deep-visibility-feature-spotlight/
- Query language is "based on a user-friendly SQL subset"
- Console provides syntax assistance with completion suggestions and validation indicator
- Supports hash-based queries, MITRE ATT&CK indicator searches
- Processes ~10 billion events/day with streaming results

## Key Queries from SentineLabs (Canonical Examples)

### Hafnium Process Spawn (complex AND/OR with nested parens)
```
EventType = "Process Creation"
  and (SrcProcName In AnyCase ("umworkerprocess.exe", "umservice.exe")
    or (SrcProcName In Anycase ("w3wp.exe")
      and SrcProcCmdLine Contains Anycase "MSExchange"))
  and TgtProcImagePath Contains Anycase "system32"
  and not TgtProcName in anycase ("wermgr.exe", "werfault.exe")
```
**Notable**: Uses nested parentheses, mixes AND/OR with grouping, uses `not` operator, uses `In AnyCase` for case-insensitive list matching.

### LOLBAS rundll32 (AND with parenthesized OR)
```
TgtProcName Contains Anycase "rundll32.exe"
  and (TgtProcCmdLine Contains Anycase "mshtml,RunHTMLApplication"
    or TgtProcCmdLine Contains Anycase "javascript:")
  and EventType = "Process Creation"
```
**Notable**: Classic `A AND (B OR C) AND D` pattern.

### Suspicious Data Compression (AND-only with RegExp)
```
EventType = "Process Creation"
  and TgtProcCmdLine contains anycase "-hp"
  and TgtProcCmdLine regexp "\sa\s.*\s-hp[^\s]+\s"
  and TgtProcCmdLine regexp "\sa\s.*\s-m[0-5]+\s"
```
**Notable**: Uses `regexp` operator with proper regex syntax. Backslashes are valid inside RegExp values (they're regex metacharacters).

### Webshell Process Creation (AND with In list)
```
EventType = "Process Creation"
  And SrcProcName Contains Anycase "w3wp.exe"
  and TgtProcName in Anycase ("cmd.exe", "powershell.exe", "net.exe",
    "quser.exe", "certutil.exe", "arp.exe", "hostname.exe", "whoami.exe",
    "netstat.exe", "ping.exe", "ipconfig.exe", "wmic.exe", "del.exe")
```
**Notable**: Large `In Anycase` list (13 items). Operators are case-insensitive (`And` vs `and` vs `AND`).

### Indicator Removal / USN Journal Deletion (AND-only)
```
EventType = "Process Creation"
  AND TgtProcName Contains Anycase "fsutil"
  AND TgtProcCmdLine Contains Anycase " usn "
  AND TgtProcCmdLine Contains Anycase " deletejournal"
```
**Notable**: Uses uppercase `AND` (confirming operators are case-insensitive).

### SUNBURST DNS (AND with In Contains)
```
DnsResponse Contains Anycase ".avsvmcloud"
  AND DnsRequest In Contains Anycase ("appsync-api", "avsvmcloud.com")
```
**Notable**: Uses `In Contains Anycase` — a compound operator for case-insensitive contains-match against a list.

## S1QL Syntax Rules (derived from official examples)

### Operators (confirmed from examples)
- `Contains` / `Contains Anycase` — substring match (case-sensitive / insensitive)
- `In` / `In Anycase` — exact match against a list
- `In Contains Anycase` — substring match against a list (case-insensitive)
- `=` / `!=` — exact equality
- `RegExp` — regex match (backslashes preserved as regex metacharacters)
- `not` — negation prefix
- `AND` / `OR` — boolean connectors (case-insensitive: `and`, `And`, `AND` all work)

### Parentheses and Grouping
- **Parenthesized AND/OR grouping IS supported**: `A AND (B OR C)` works
- **Nested parentheses work**: `A AND (B OR (C AND D))` used in Hafnium query
- **Top-level mixed AND/OR without parens**: NOT supported (ambiguous, no operator precedence)
- **`not` operator**: Works as a prefix, e.g., `not TgtProcName in anycase (...)`

### Case Sensitivity
- **Operators are case-insensitive**: `and` = `And` = `AND`
- **Field names appear case-sensitive** (all examples use exact casing like `EventType`, `SrcProcName`)
- **Value matching**: Use `Anycase` / `AnyCase` suffix for case-insensitive matching

### Backslashes in Values
- **Backslashes in regular string values cause parse errors** (400 "could not parse query")
- **Backslashes in RegExp values are valid** (regex syntax requires them)
- S1 DV parser has no backslash escape mechanism for string literals
- Workaround: strip backslashes (broadens match slightly) or use forward slashes

## S1 API Deprecation (discovered during research)

The v2.1 DV endpoints return deprecation metadata:

```json
{
  "alternative": "/sdl/v2/api/queries",
  "deprecation_date": "2026-02-15",
  "message": "This Endpoint is deprecated and will be removed on February 15, 2027. Please use /sdl/v2/api/queries instead.",
  "sunset_date": "2027-02-15"
}
```

### Affected endpoints
| Old (v2.1)              | New (SDL v2)                    |
|-------------------------|---------------------------------|
| POST /dv/init-query     | POST /sdl/v2/api/queries        |
| GET /dv/query-status    | GET /sdl/v2/api/queries/{queryId}|
| GET /dv/events          | TBD (not yet investigated)      |

### Response format changes
- Query status field: `status` -> `responseState`
- New fields: `queryModeInfo.mode` (value: "scalyr"), `queryModeInfo.lastActivatedAt`
- Deprecation metadata included in every response

## Inaccessible Sources (for future reference)

These sources exist but are behind authentication:
- SentinelOne Knowledge Base: `knowledge.sentinelone.com` (requires S1 login)
- SentinelOne API Docs: `usea1-partners.sentinelone.net/docs/en/` (requires console login)
- S1QL Cheatsheet PDF: redirects to marketing page
- SentinelOne Community: `community.sentinelone.com` (not found / auth required)
