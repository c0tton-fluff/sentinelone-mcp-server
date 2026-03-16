package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/c0tton-fluff/sentinelone-mcp-server/client"
	"github.com/mark3labs/mcp-go/mcp"
)

var investigateThreatTool = mcp.NewTool("s1_investigate_threat",
	mcp.WithDescription(`Full threat investigation in one call. Fetches threat details,
correlated alerts by storyline, and a Deep Visibility timeline of endpoint
activity around detection time (-1h to +1h). Replaces 4+ sequential tool calls.`),
	mcp.WithString("threatId",
		mcp.Required(),
		mcp.Description("The threat ID to investigate"),
	),
)

func handleInvestigateThreat(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	threatID, err := req.RequireString("threatId")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := client.GetThreat(ctx, threatID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error: %v", err)), nil
	}
	if len(result.Data) == 0 {
		return mcp.NewToolResultError(fmt.Sprintf("Threat %s not found", threatID)), nil
	}

	t := result.Data[0]
	computer := getStr(t, "agentRealtimeInfo", "agentComputerName")
	storylineID := getStr(t, "threatInfo", "storyline")
	createdAt := getStr(t, "threatInfo", "createdAt")
	osName := fallback(getStr(t, "agentDetectionInfo", "agentOsName"), "Unknown")
	timeStr := createdAt
	if createdAt != "" {
		timeStr = formatTimeAgo(createdAt)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "THREAT: %s | %s | %s | %s\n",
		fallback(getStr(t, "threatInfo", "threatName"), "Unknown"),
		fallback(getStr(t, "threatInfo", "classification"), "Unknown"),
		fallback(getStr(t, "threatInfo", "mitigationStatus"), "Unknown"),
		timeStr)
	fmt.Fprintf(&sb, "Agent: %s | %s | User: %s | Verdict: %s\n",
		fallback(computer, "Unknown"),
		osName,
		fallback(getStr(t, "agentDetectionInfo", "agentLastLoggedInUserName"), "Unknown"),
		fallback(getStr(t, "threatInfo", "analystVerdict"), "undefined"))
	fmt.Fprintf(&sb, "ID: %s | Storyline: %s\n", threatID, fallback(storylineID, "N/A"))
	if fp := getStr(t, "threatInfo", "filePath"); fp != "" {
		fmt.Fprintf(&sb, "Path: %s\n", fp)
	}
	if h := getStr(t, "threatInfo", "sha256"); h != "" {
		fmt.Fprintf(&sb, "SHA256: %s\n", h)
	}

	// Start DV query (runs server-side while we fetch alerts next).
	var queryID string
	var dvStarted bool
	var dvErr error
	if threatTime, ok := parseTime(createdAt); ok && computer != "" {
		from := threatTime.Add(-1 * time.Hour).Format(time.RFC3339)
		to := threatTime.Add(1 * time.Hour).Format(time.RFC3339)
		eventTypes := `"Process Creation","File Creation","IP Connect","DNS Resolved","Behavioral Indicators"`
		noiseFilter := `"poll_calendar","mds_stores","mDNSResponder","cfprefsd"`
		if strings.Contains(strings.ToLower(osName), "windows") {
			eventTypes += `,"Registry Key Creation","Registry Value Modified"`
			noiseFilter = `"svchost.exe","SearchProtocolHost.exe","backgroundtaskhost.exe","RuntimeBroker.exe"`
		}
		q := fmt.Sprintf(`AgentName = "%s" AND EventType In (%s) AND not SrcProcName In Anycase (%s)`,
			computer, eventTypes, noiseFilter)
		for i := range 6 {
			queryID, dvErr = client.CreateDVQuery(ctx, q, from, to, nil, nil, nil)
			if dvErr == nil {
				dvStarted = true
				break
			}
			if !strings.Contains(dvErr.Error(), "409") || i == 5 {
				break
			}
			time.Sleep(3 * time.Second)
		}
	}

	// Fetch correlated alerts (DV query processing server-side in parallel).
	sb.WriteString("\nALERTS")
	if storylineID == "" {
		sb.WriteString("\n---\nNo storyline ID available.")
	} else {
		alerts, alertErr := client.QueryAlerts(ctx, 20, "", "", "", "", storylineID, nil)
		if alertErr != nil {
			fmt.Fprintf(&sb, "\n---\nError: %v", alertErr)
		} else if len(alerts.Alerts) == 0 {
			sb.WriteString("\n---\nNo alerts for this storyline.")
		} else {
			fmt.Fprintf(&sb, " (%d)\n---\n", len(alerts.Alerts))
			for i, a := range alerts.Alerts {
				if i > 0 {
					sb.WriteString("\n\n")
				}
				sb.WriteString(summarizeAlert(a))
			}
		}
	}

	// Poll DV query and fetch timeline.
	sb.WriteString("\n\nTIMELINE")
	if !dvStarted {
		if dvErr != nil {
			fmt.Fprintf(&sb, "\n---\nDV query failed: %v", dvErr)
		} else {
			sb.WriteString("\n---\nInsufficient data (need agent name + timestamp).")
		}
	} else {
		sb.WriteString(pollAndFetchDVTimeline(ctx, queryID))
	}

	return mcp.NewToolResultText(sb.String()), nil
}

// pollAndFetchDVTimeline waits for a DV query to finish, fetches events, and
// returns a formatted string to append to the investigation output.
func pollAndFetchDVTimeline(ctx context.Context, queryID string) string {
	var status *client.DVStatus
	var err error
	for range 30 {
		time.Sleep(1 * time.Second)
		status, err = client.GetDVQueryStatus(ctx, queryID)
		if err != nil {
			return fmt.Sprintf("\n---\nDV poll error: %v", err)
		}
		if status.Status == "FINISHED" || strings.HasPrefix(status.Status, "FAILED") || status.Status == "CANCELED" {
			break
		}
	}

	if status.Status != "FINISHED" {
		return fmt.Sprintf("\n---\nDV query did not complete (status: %s)", fallback(status.Status, "unknown"))
	}

	var events *client.PaginatedResponse
	for range 5 {
		events, err = client.GetDVEvents(ctx, queryID, 100, "")
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "409") {
			return fmt.Sprintf("\n---\nDV events error: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return fmt.Sprintf("\n---\nDV events error: %v", err)
	}
	if len(events.Data) == 0 {
		return "\n---\nNo events in time window."
	}

	// Deduplicate: group by eventType+processName, show count for repeats.
	type eventKey struct{ eventType, process string }
	type eventGroup struct {
		key   eventKey
		line  string
		count int
	}
	var groups []eventGroup
	seen := make(map[eventKey]int) // key -> index in groups
	for _, e := range events.Data {
		k := eventKey{
			eventType: fallback(getStr(e, "eventType"), "Unknown"),
			process:   fallback(getStr(e, "processName"), "N/A"),
		}
		if idx, ok := seen[k]; ok {
			groups[idx].count++
		} else {
			seen[k] = len(groups)
			groups = append(groups, eventGroup{key: k, line: summarizeEvent(e), count: 1})
		}
	}

	lines := make([]string, len(groups))
	for i, g := range groups {
		if g.count > 1 {
			lines[i] = fmt.Sprintf("%s (x%d)", g.line, g.count)
		} else {
			lines[i] = g.line
		}
	}
	return fmt.Sprintf(" (%d events, %d unique, -1h to +1h)\n---\n%s",
		len(events.Data), len(groups), strings.Join(lines, "\n"))
}
