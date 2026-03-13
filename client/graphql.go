package client

import (
	"encoding/json"
	"fmt"
	"strings"
)

type alertFilter struct {
	FieldID     string             `json:"fieldId"`
	StringEqual *stringEqualFilter `json:"stringEqual,omitempty"`
	StringIn    *stringInFilter    `json:"stringIn,omitempty"`
}

type stringEqualFilter struct {
	Value string `json:"value"`
}

type stringInFilter struct {
	Values []string `json:"values"`
}

// AlertPageInfo holds GraphQL pagination state.
type AlertPageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor,omitempty"`
}

// AlertsResult holds the parsed GraphQL alerts response.
type AlertsResult struct {
	Alerts   []map[string]any
	PageInfo AlertPageInfo
}

// normalizeStatus uppercases and maps common aliases to API values.
func normalizeStatus(s string) string {
	v := strings.ToUpper(strings.TrimSpace(s))
	switch v {
	case "UNRESOLVED", "OPEN":
		return "NEW"
	case "INPROGRESS":
		return "IN_PROGRESS"
	default:
		return v
	}
}

func QueryAlerts(
	limit int,
	cursor, severity, analystVerdict, incidentStatus, storylineID string,
	siteIDs []string,
) (*AlertsResult, error) {
	var filters []alertFilter

	if severity != "" {
		filters = append(filters, alertFilter{
			FieldID:     "severity",
			StringEqual: &stringEqualFilter{Value: strings.ToUpper(strings.TrimSpace(severity))},
		})
	}
	if analystVerdict != "" {
		filters = append(filters, alertFilter{
			FieldID:     "analystVerdict",
			StringEqual: &stringEqualFilter{Value: strings.ToUpper(strings.TrimSpace(analystVerdict))},
		})
	}
	if incidentStatus != "" {
		filters = append(filters, alertFilter{
			FieldID:     "status",
			StringEqual: &stringEqualFilter{Value: normalizeStatus(incidentStatus)},
		})
	}
	if storylineID != "" {
		filters = append(filters, alertFilter{
			FieldID:     "storylineId",
			StringEqual: &stringEqualFilter{Value: storylineID},
		})
	}
	if len(siteIDs) > 0 {
		filters = append(filters, alertFilter{
			FieldID:  "siteId",
			StringIn: &stringInFilter{Values: siteIDs},
		})
	}

	const gql = `query GetAlerts($first: Int, $after: String, $filters: [FilterInput!]) {
  alerts(first: $first, after: $after, filters: $filters) {
    edges {
      node {
        id
        severity
        analystVerdict
        name
        classification
        confidenceLevel
        status
        storylineId
        detectedAt
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}`

	if limit <= 0 {
		limit = 20
	}

	variables := map[string]any{"first": limit}
	if cursor != "" {
		variables["after"] = cursor
	}
	if len(filters) > 0 {
		variables["filters"] = filters
	}

	body := map[string]any{
		"query":     gql,
		"variables": variables,
	}

	data, err := doRequest("POST", "/unifiedalerts/graphql", body)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data *struct {
			Alerts struct {
				Edges []struct {
					Node map[string]any `json:"node"`
				} `json:"edges"`
				PageInfo AlertPageInfo `json:"pageInfo"`
			} `json:"alerts"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse GraphQL response: %w", err)
	}

	if len(resp.Errors) > 0 {
		msgs := make([]string, len(resp.Errors))
		for i, e := range resp.Errors {
			msgs[i] = e.Message
		}
		return nil, fmt.Errorf("GraphQL errors: %s", strings.Join(msgs, ", "))
	}

	if resp.Data == nil {
		return nil, fmt.Errorf("no data returned from GraphQL query")
	}

	alerts := make([]map[string]any, len(resp.Data.Alerts.Edges))
	for i, edge := range resp.Data.Alerts.Edges {
		alerts[i] = edge.Node
	}

	return &AlertsResult{
		Alerts:   alerts,
		PageInfo: resp.Data.Alerts.PageInfo,
	}, nil
}
