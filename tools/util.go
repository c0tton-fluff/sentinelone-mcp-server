package tools

import (
	"fmt"
	"strconv"
	"time"
)

func formatTimeAgo(dateStr string) string {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, dateStr)
		if err != nil {
			return dateStr
		}
	}
	diff := time.Since(t)
	if diff < 0 {
		return "just now"
	}
	mins := int(diff.Minutes())
	hours := int(diff.Hours())
	days := hours / 24

	switch {
	case mins < 60:
		return fmt.Sprintf("%dm ago", mins)
	case hours < 24:
		return fmt.Sprintf("%dh ago", hours)
	default:
		return fmt.Sprintf("%dd ago", days)
	}
}

func truncatePath(path string, max int) string {
	if len(path) <= max {
		return path
	}
	return "..." + path[len(path)-max+3:]
}

// getStr safely extracts a string from nested map[string]any.
// Usage: getStr(m, "threatInfo", "threatName")
func getStr(m map[string]any, keys ...string) string {
	var current any = m
	for _, key := range keys {
		cm, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = cm[key]
	}
	switch v := current.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}

func getBool(m map[string]any, key string) bool {
	v, _ := m[key].(bool)
	return v
}

// parseTime tries RFC3339 then RFC3339Nano.
func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, s)
	}
	return t, err == nil
}

// fallback returns s if non-empty, otherwise def.
func fallback(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
