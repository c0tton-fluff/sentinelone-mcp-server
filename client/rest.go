package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/c0tton-fluff/sentinelone-mcp-server/config"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// PaginatedResponse wraps S1 API list responses.
type PaginatedResponse struct {
	Data       []map[string]any `json:"data"`
	Pagination *Pagination      `json:"pagination,omitempty"`
}

type Pagination struct {
	NextCursor string `json:"nextCursor,omitempty"`
	TotalItems int    `json:"totalItems,omitempty"`
}

// DVStatus represents a Deep Visibility query status.
type DVStatus struct {
	QueryID        string `json:"queryId"`
	Status         string `json:"responseState"`
	ProgressStatus int    `json:"progressStatus"`
	ResponseError  string `json:"responseError"`
}

const maxRetries = 5

func doRequest(ctx context.Context, method, endpoint string, body any) ([]byte, error) {
	cfg := config.Get()
	u := cfg.APIBase + "/web/api/v2.1" + endpoint

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
	}

	backoff := 2 * time.Second

	for attempt := range maxRetries + 1 {
		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("Authorization", "ApiToken "+cfg.APIKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s", sanitize(err.Error()))
		}
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetries {
			wait := backoff
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
					wait = time.Duration(min(secs, 120)) * time.Second
				}
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			backoff = min(backoff*2, 60*time.Second)
			continue
		}

		if resp.StatusCode >= 400 {
			if detail := extractAPIError(data); detail != "" {
				return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, sanitize(detail))
			}
			return nil, fmt.Errorf("HTTP %d: %s - %s", resp.StatusCode, resp.Status, sanitize(string(data)))
		}

		return data, nil
	}

	// Unreachable -- the final attempt always returns above -- but keeps the compiler happy.
	return nil, fmt.Errorf("request failed after %d retries", maxRetries)
}

// extractAPIError pulls the human-readable detail from S1's error JSON.
// S1 errors look like: {"errors":[{"code":4000040,"detail":"Bad Request - could not parse query","title":"Bad Request"}]}
func extractAPIError(body []byte) string {
	var parsed struct {
		Errors []struct {
			Detail string `json:"detail"`
			Title  string `json:"title"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &parsed) != nil || len(parsed.Errors) == 0 {
		return ""
	}
	if parsed.Errors[0].Detail != "" {
		return parsed.Errors[0].Detail
	}
	return parsed.Errors[0].Title
}

func sanitize(s string) string {
	cfg := config.Get()
	return strings.ReplaceAll(s, cfg.APIKey, "[REDACTED]")
}

func doGet(ctx context.Context, endpoint string) (*PaginatedResponse, error) {
	data, err := doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	var resp PaginatedResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &resp, nil
}

func doFilterPost(ctx context.Context, endpoint string, ids []string) (int, error) {
	body := map[string]any{
		"filter": map[string]any{"ids": ids},
	}
	data, err := doRequest(ctx, "POST", endpoint, body)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Data struct {
			Affected int `json:"affected"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}
	return resp.Data.Affected, nil
}

func doDataFilterPost(ctx context.Context, endpoint string, ids []string, data map[string]any) (int, error) {
	body := map[string]any{
		"data":   data,
		"filter": map[string]any{"ids": ids},
	}
	raw, err := doRequest(ctx, "POST", endpoint, body)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Data struct {
			Affected int `json:"affected"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}
	return resp.Data.Affected, nil
}

// -- Threats --

func ListThreats(ctx context.Context, q url.Values) (*PaginatedResponse, error) {
	endpoint := "/threats"
	if qs := q.Encode(); qs != "" {
		endpoint += "?" + qs
	}
	return doGet(ctx, endpoint)
}

func GetThreat(ctx context.Context, id string) (*PaginatedResponse, error) {
	return doGet(ctx, "/threats?"+url.Values{"ids": {id}}.Encode())
}

func MitigateThreat(ctx context.Context, id, action string) (int, error) {
	return doFilterPost(ctx, "/threats/mitigate/"+url.PathEscape(action), []string{id})
}

func SetAnalystVerdict(ctx context.Context, id, verdict string) (int, error) {
	return doDataFilterPost(ctx, "/threats/analyst-verdict", []string{id}, map[string]any{
		"analystVerdict": verdict,
	})
}

func SetIncidentStatus(ctx context.Context, id, status, verdict string) (int, error) {
	data := map[string]any{"incidentStatus": status}
	if verdict != "" {
		data["analystVerdict"] = verdict
	}
	return doDataFilterPost(ctx, "/threats/incident", []string{id}, data)
}

func GetThreatTimeline(ctx context.Context, threatID string, limit int) (*PaginatedResponse, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	q.Set("sortOrder", "asc")
	return doGet(ctx, "/threats/"+url.PathEscape(threatID)+"/timeline?"+q.Encode())
}

// -- Agents --

func ListAgents(ctx context.Context, q url.Values) (*PaginatedResponse, error) {
	endpoint := "/agents"
	if qs := q.Encode(); qs != "" {
		endpoint += "?" + qs
	}
	return doGet(ctx, endpoint)
}

func GetAgent(ctx context.Context, id string) (*PaginatedResponse, error) {
	return doGet(ctx, "/agents?"+url.Values{"ids": {id}}.Encode())
}

func IsolateAgent(ctx context.Context, id string) (int, error) {
	return doFilterPost(ctx, "/agents/actions/disconnect", []string{id})
}

func ReconnectAgent(ctx context.Context, id string) (int, error) {
	return doFilterPost(ctx, "/agents/actions/connect", []string{id})
}

// -- Alerts (REST) --

// AlertFilter represents the filter object for cloud-detection alert bulk operations.
type AlertFilter struct {
	Query                string   `json:"query,omitempty"`
	RuleNameContains     []string `json:"ruleName__contains,omitempty"`
	AgentNameContains    []string `json:"origAgentName__contains,omitempty"`
	IncidentStatus       []string `json:"incidentStatus,omitempty"`
	AnalystVerdict       []string `json:"analystVerdict,omitempty"`
	SiteIDs              []string `json:"siteIds,omitempty"`
	IDs                  []string `json:"ids,omitempty"`
}

func SetAlertVerdict(ctx context.Context, filter AlertFilter, verdict string) (int, error) {
	body := map[string]any{
		"data":   map[string]any{"analystVerdict": verdict},
		"filter": filter,
	}
	raw, err := doRequest(ctx, "POST", "/cloud-detection/alerts/analyst-verdict", body)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Data struct {
			Affected int `json:"affected"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}
	return resp.Data.Affected, nil
}

func SetAlertStatus(ctx context.Context, filter AlertFilter, status string) (int, error) {
	body := map[string]any{
		"data":   map[string]any{"incidentStatus": status},
		"filter": filter,
	}
	raw, err := doRequest(ctx, "POST", "/cloud-detection/alerts/incident", body)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Data struct {
			Affected int `json:"affected"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}
	return resp.Data.Affected, nil
}

// -- Hashes --

func GetHashVerdict(ctx context.Context, hash string) (string, error) {
	data, err := doRequest(ctx, "GET", "/hashes/"+url.PathEscape(hash)+"/verdict", nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Data struct {
			Verdict string `json:"verdict"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	return resp.Data.Verdict, nil
}

// -- Deep Visibility --

func CreateDVQuery(ctx context.Context, query, fromDate, toDate string, siteIDs, accountIDs []string) (string, error) {
	body := map[string]any{
		"query":    query,
		"fromDate": fromDate,
		"toDate":   toDate,
	}
	if len(siteIDs) > 0 {
		body["siteIds"] = siteIDs
	}
	if len(accountIDs) > 0 {
		body["accountIds"] = accountIDs
	}

	data, err := doRequest(ctx, "POST", "/dv/init-query", body)
	if err != nil {
		return "", err
	}

	var resp struct {
		Data struct {
			QueryID string `json:"queryId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	return resp.Data.QueryID, nil
}

func GetDVQueryStatus(ctx context.Context, queryID string) (*DVStatus, error) {
	data, err := doRequest(ctx, "GET", "/dv/query-status?"+url.Values{"queryId": {queryID}}.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data DVStatus `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &resp.Data, nil
}

func GetDVEvents(ctx context.Context, queryID string, limit int, cursor string) (*PaginatedResponse, error) {
	q := url.Values{"queryId": {queryID}}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	return doGet(ctx, "/dv/events?"+q.Encode())
}
