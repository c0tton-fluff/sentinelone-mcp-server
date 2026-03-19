package tools

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// util.go: truncatePath
// ---------------------------------------------------------------------------

func TestTruncatePath_Short(t *testing.T) {
	got := truncatePath("/usr/bin", 20)
	if got != "/usr/bin" {
		t.Fatalf("expected /usr/bin, got %q", got)
	}
}

func TestTruncatePath_ExactLength(t *testing.T) {
	path := "/usr/bin"
	got := truncatePath(path, len(path))
	if got != path {
		t.Fatalf("expected %q, got %q", path, got)
	}
}

func TestTruncatePath_Long(t *testing.T) {
	path := "/very/long/path/to/some/file.txt"
	got := truncatePath(path, 15)
	if !strings.HasPrefix(got, "...") {
		t.Fatalf("expected ... prefix, got %q", got)
	}
	if len(got) != 15 {
		t.Fatalf("expected length 15, got %d (%q)", len(got), got)
	}
	// The suffix should be the last 12 chars of the original path.
	wantSuffix := path[len(path)-12:]
	if got != "..."+wantSuffix {
		t.Fatalf("expected ...%s, got %q", wantSuffix, got)
	}
}

func TestTruncatePath_Empty(t *testing.T) {
	got := truncatePath("", 10)
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// util.go: formatTimeAgo
// ---------------------------------------------------------------------------

func TestFormatTimeAgo_Minutes(t *testing.T) {
	ts := time.Now().Add(-5 * time.Minute).Format(time.RFC3339)
	got := formatTimeAgo(ts)
	if !strings.HasSuffix(got, "m ago") {
		t.Fatalf("expected Xm ago, got %q", got)
	}
}

func TestFormatTimeAgo_Hours(t *testing.T) {
	ts := time.Now().Add(-3 * time.Hour).Format(time.RFC3339)
	got := formatTimeAgo(ts)
	if !strings.HasSuffix(got, "h ago") {
		t.Fatalf("expected Xh ago, got %q", got)
	}
}

func TestFormatTimeAgo_Days(t *testing.T) {
	ts := time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
	got := formatTimeAgo(ts)
	if !strings.HasSuffix(got, "d ago") {
		t.Fatalf("expected Xd ago, got %q", got)
	}
}

func TestFormatTimeAgo_Invalid(t *testing.T) {
	got := formatTimeAgo("not-a-date")
	if got != "not-a-date" {
		t.Fatalf("expected raw string back, got %q", got)
	}
}

func TestFormatTimeAgo_RFC3339Nano(t *testing.T) {
	ts := time.Now().Add(-10 * time.Minute).Format(time.RFC3339Nano)
	got := formatTimeAgo(ts)
	if !strings.HasSuffix(got, "m ago") {
		t.Fatalf("expected Xm ago for RFC3339Nano, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// util.go: getStr
// ---------------------------------------------------------------------------

func TestGetStr_SimpleKey(t *testing.T) {
	m := map[string]any{"name": "test"}
	got := getStr(m, "name")
	if got != "test" {
		t.Fatalf("expected test, got %q", got)
	}
}

func TestGetStr_NestedKeys(t *testing.T) {
	m := map[string]any{
		"threatInfo": map[string]any{
			"threatName": "Trojan",
		},
	}
	got := getStr(m, "threatInfo", "threatName")
	if got != "Trojan" {
		t.Fatalf("expected Trojan, got %q", got)
	}
}

func TestGetStr_MissingKey(t *testing.T) {
	m := map[string]any{"name": "test"}
	got := getStr(m, "missing")
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestGetStr_Float64(t *testing.T) {
	m := map[string]any{"port": float64(443)}
	got := getStr(m, "port")
	if got != "443" {
		t.Fatalf("expected 443, got %q", got)
	}
}

func TestGetStr_Bool(t *testing.T) {
	m := map[string]any{"active": true}
	got := getStr(m, "active")
	if got != "true" {
		t.Fatalf("expected true, got %q", got)
	}
}

func TestGetStr_NilMap(t *testing.T) {
	got := getStr(nil, "key")
	if got != "" {
		t.Fatalf("expected empty for nil map, got %q", got)
	}
}

func TestGetStr_IntermediateNonMap(t *testing.T) {
	m := map[string]any{"a": "not-a-map"}
	got := getStr(m, "a", "b")
	if got != "" {
		t.Fatalf("expected empty for non-map intermediate, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// util.go: fallback
// ---------------------------------------------------------------------------

func TestFallback_NonEmpty(t *testing.T) {
	got := fallback("value", "default")
	if got != "value" {
		t.Fatalf("expected value, got %q", got)
	}
}

func TestFallback_Empty(t *testing.T) {
	got := fallback("", "default")
	if got != "default" {
		t.Fatalf("expected default, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// util.go: getBool
// ---------------------------------------------------------------------------

func TestGetBool_True(t *testing.T) {
	m := map[string]any{"infected": true}
	if !getBool(m, "infected") {
		t.Fatal("expected true")
	}
}

func TestGetBool_False(t *testing.T) {
	m := map[string]any{"infected": false}
	if getBool(m, "infected") {
		t.Fatal("expected false")
	}
}

func TestGetBool_Missing(t *testing.T) {
	m := map[string]any{}
	if getBool(m, "infected") {
		t.Fatal("expected false for missing key")
	}
}

func TestGetBool_NonBool(t *testing.T) {
	m := map[string]any{"infected": "yes"}
	if getBool(m, "infected") {
		t.Fatal("expected false for non-bool value")
	}
}

// ---------------------------------------------------------------------------
// dv.go: fixBackslashesInDVValues
// ---------------------------------------------------------------------------

func TestFixBackslashes_NoBackslashes(t *testing.T) {
	q := `SrcProcName = "cmd.exe"`
	got, changed := fixBackslashesInDVValues(q)
	if changed {
		t.Fatal("expected no change")
	}
	if got != q {
		t.Fatalf("expected %q, got %q", q, got)
	}
}

func TestFixBackslashes_StringValuesStripped(t *testing.T) {
	q := `FilePath Contains "C:\Users\test"`
	got, changed := fixBackslashesInDVValues(q)
	if !changed {
		t.Fatal("expected change")
	}
	if strings.Contains(got, `\`) {
		t.Fatalf("backslashes not stripped: %q", got)
	}
	want := `FilePath Contains "C:Userstest"`
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFixBackslashes_RegExpPreserved(t *testing.T) {
	q := `FilePath RegExp "C:\\Users\\.*"`
	got, changed := fixBackslashesInDVValues(q)
	if changed {
		t.Fatal("expected no change for RegExp values")
	}
	if got != q {
		t.Fatalf("expected %q, got %q", q, got)
	}
}

func TestFixBackslashes_CaseInsensitiveRegExp(t *testing.T) {
	tests := []string{
		`FilePath regexp "C:\\test"`,
		`FilePath REGEXP "C:\\test"`,
		`FilePath RegExp "C:\\test"`,
	}
	for _, q := range tests {
		got, changed := fixBackslashesInDVValues(q)
		if changed {
			t.Fatalf("expected no change for %q, but got change: %q", q, got)
		}
		if got != q {
			t.Fatalf("expected %q, got %q", q, got)
		}
	}
}

func TestFixBackslashes_MultipleQuotedValues(t *testing.T) {
	q := `A Contains "C:\a" AND B Contains "D:\b"`
	got, changed := fixBackslashesInDVValues(q)
	if !changed {
		t.Fatal("expected change")
	}
	want := `A Contains "C:a" AND B Contains "D:b"`
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

// ---------------------------------------------------------------------------
// dv.go: validateDVQuery
// ---------------------------------------------------------------------------

func TestValidateDVQuery_Valid(t *testing.T) {
	q := `SrcProcName Contains "cmd"`
	got, warn, err := validateDVQuery(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != q {
		t.Fatalf("expected %q, got %q", q, got)
	}
	if warn != "" {
		t.Fatalf("expected no warning, got %q", warn)
	}
}

func TestValidateDVQuery_ObjectTypeRejected(t *testing.T) {
	q := `ObjectType = "Process"`
	_, _, err := validateDVQuery(q)
	if err == nil {
		t.Fatal("expected error for ObjectType field")
	}
	if !strings.Contains(err.Error(), "ObjectType") {
		t.Fatalf("error should mention ObjectType: %v", err)
	}
}

func TestValidateDVQuery_MixedAndOrRejected(t *testing.T) {
	q := `A = "1" AND B = "2" OR C = "3"`
	_, _, err := validateDVQuery(q)
	if err == nil {
		t.Fatal("expected error for mixed AND/OR")
	}
	if !strings.Contains(err.Error(), "mixes AND and OR") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDVQuery_MixedAndOrInParensOK(t *testing.T) {
	q := `A = "1" AND (B = "2" OR C = "3")`
	_, _, err := validateDVQuery(q)
	if err != nil {
		t.Fatalf("unexpected error for parenthesized mixed: %v", err)
	}
}

func TestValidateDVQuery_BackslashWarning(t *testing.T) {
	q := `FilePath Contains "C:\Users"`
	got, warn, err := validateDVQuery(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if warn == "" {
		t.Fatal("expected warning about backslashes")
	}
	if strings.Contains(got, `\`) {
		t.Fatalf("backslashes should be stripped: %q", got)
	}
}

// ---------------------------------------------------------------------------
// dv.go: summarizeEvent
// ---------------------------------------------------------------------------

func TestSummarizeEvent_Network(t *testing.T) {
	e := map[string]any{
		"eventType":   "IP Connect",
		"agentName":   "srv01",
		"processName": "curl",
		"srcIp":       "10.0.0.1",
		"dstIp":       "8.8.8.8",
		"dstPort":     "443",
	}
	got := summarizeEvent(e)
	if !strings.Contains(got, "10.0.0.1 -> 8.8.8.8:443") {
		t.Fatalf("expected network info, got %q", got)
	}
	if !strings.Contains(got, "IP Connect") {
		t.Fatalf("expected event type, got %q", got)
	}
}

func TestSummarizeEvent_DNS(t *testing.T) {
	e := map[string]any{
		"eventType":   "DNS Resolved",
		"agentName":   "ws01",
		"processName": "chrome",
		"dnsRequest":  "evil.com",
	}
	got := summarizeEvent(e)
	if !strings.Contains(got, "DNS: evil.com") {
		t.Fatalf("expected DNS info, got %q", got)
	}
}

func TestSummarizeEvent_Process(t *testing.T) {
	cmd := "/usr/bin/python3 /opt/scripts/deploy.py --env prod"
	e := map[string]any{
		"eventType":   "Process Creation",
		"agentName":   "ws02",
		"processName": "python3",
		"processCmd":  cmd,
	}
	got := summarizeEvent(e)
	// Full cmdline should come through, no truncation.
	if !strings.Contains(got, cmd) {
		t.Fatalf("expected full cmd, got %q", got)
	}
}

func TestSummarizeEvent_File(t *testing.T) {
	e := map[string]any{
		"eventType":    "File Creation",
		"agentName":    "ws03",
		"processName":  "notepad",
		"fileFullName": "/tmp/test.txt",
	}
	got := summarizeEvent(e)
	if !strings.Contains(got, "/tmp/test.txt") {
		t.Fatalf("expected file path, got %q", got)
	}
}

func TestSummarizeEvent_Minimal(t *testing.T) {
	e := map[string]any{}
	got := summarizeEvent(e)
	if !strings.Contains(got, "Unknown") {
		t.Fatalf("expected Unknown fallbacks, got %q", got)
	}
	if !strings.Contains(got, "N/A") {
		t.Fatalf("expected N/A for process, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// threats.go: summarizeThreat
// ---------------------------------------------------------------------------

func TestSummarizeThreat_Full(t *testing.T) {
	threat := map[string]any{
		"id": "threat-123",
		"threatInfo": map[string]any{
			"threatName":       "Trojan.Gen",
			"classification":   "Malware",
			"mitigationStatus": "mitigated",
			"createdAt":        time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
			"filePath":         "/tmp/malware.exe",
		},
		"agentRealtimeInfo": map[string]any{
			"agentComputerName": "srv01",
		},
		"agentDetectionInfo": map[string]any{
			"agentLastLoggedInUserName": "admin",
		},
	}
	got := summarizeThreat(threat)
	for _, want := range []string{"srv01", "Trojan.Gen", "Malware", "mitigated", "threat-123", "admin", "/tmp/malware.exe"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output, got %q", want, got)
		}
	}
}

func TestSummarizeThreat_Minimal(t *testing.T) {
	got := summarizeThreat(map[string]any{})
	if !strings.Contains(got, "Unknown") {
		t.Fatalf("expected Unknown fallbacks, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// agents.go: summarizeAgent
// ---------------------------------------------------------------------------

func TestSummarizeAgent_Full(t *testing.T) {
	agent := map[string]any{
		"id":                   "agent-456",
		"computerName":         "ws01",
		"osName":               "Windows 11",
		"networkStatus":        "connected",
		"infected":             false,
		"lastActiveDate":       time.Now().Add(-30 * time.Minute).Format(time.RFC3339),
		"lastLoggedInUserName": "jdoe",
		"externalIp":           "203.0.113.5",
	}
	got := summarizeAgent(agent)
	for _, want := range []string{"ws01", "Windows 11", "connected", "clean", "agent-456", "jdoe", "203.0.113.5"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output, got %q", want, got)
		}
	}
}

func TestSummarizeAgent_Minimal(t *testing.T) {
	got := summarizeAgent(map[string]any{})
	for _, want := range []string{"Unknown", "unknown", "clean", "N/A"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output, got %q", want, got)
		}
	}
}

func TestSummarizeAgent_Infected(t *testing.T) {
	agent := map[string]any{
		"computerName": "srv02",
		"infected":     true,
	}
	got := summarizeAgent(agent)
	if !strings.Contains(got, "INFECTED") {
		t.Fatalf("expected INFECTED, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// alerts.go: summarizeAlert
// ---------------------------------------------------------------------------

func TestSummarizeAlert_WithProcess(t *testing.T) {
	alert := map[string]any{
		"id":              "alert-789",
		"name":            "Suspicious Process",
		"severity":        "HIGH",
		"status":          "NEW",
		"analystVerdict":  "UNDEFINED",
		"classification":  "Suspicious",
		"confidenceLevel": "HIGH",
		"storylineId":     "story-abc",
		"detectedAt":      time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"process": map[string]any{
			"cmdLine":    "powershell.exe -enc base64stuff",
			"parentName": "explorer.exe",
			"file": map[string]any{
				"name": "powershell.exe",
				"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			},
		},
		"assets": []any{
			map[string]any{
				"name":             "ws01",
				"lastLoggedInUser": "jdoe",
				"osType":           "WINDOWS",
			},
		},
	}
	got := summarizeAlert(alert)

	// File path must NOT be truncated (bug fix verification).
	fullPath := "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
	if !strings.Contains(got, fullPath) {
		t.Fatalf("file path should not be truncated, got %q", got)
	}
	for _, want := range []string{"Suspicious Process", "HIGH", "NEW", "alert-789", "story-abc", "ws01", "jdoe", "powershell.exe -enc base64stuff", "explorer.exe"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output, got %q", want, got)
		}
	}
}

func TestSummarizeAlert_Minimal(t *testing.T) {
	got := summarizeAlert(map[string]any{})
	if !strings.Contains(got, "Unknown") {
		t.Fatalf("expected Unknown fallbacks, got %q", got)
	}
	// Should not panic with missing process/assets.
}

// ---------------------------------------------------------------------------
// investigate.go: summarizeTimelineEvent
// ---------------------------------------------------------------------------

func TestSummarizeTimelineEvent_WithSecondary(t *testing.T) {
	e := map[string]any{
		"activityType":         "Threat Detected",
		"primaryDescription":   "Malware found on disk",
		"secondaryDescription": "SHA256: abc123",
		"createdAt":            time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
	}
	got := summarizeTimelineEvent(e)
	// Must use " -- " (double dash), not em dash.
	if !strings.Contains(got, " -- SHA256: abc123") {
		t.Fatalf("expected ' -- ' separator, got %q", got)
	}
	if !strings.Contains(got, "Threat Detected") {
		t.Fatalf("expected activity type, got %q", got)
	}
	if !strings.Contains(got, "Malware found on disk") {
		t.Fatalf("expected primary description, got %q", got)
	}
}

func TestSummarizeTimelineEvent_WithoutSecondary(t *testing.T) {
	e := map[string]any{
		"activityType":       "Status Changed",
		"primaryDescription": "Threat mitigated",
		"createdAt":          time.Now().Add(-10 * time.Minute).Format(time.RFC3339),
	}
	got := summarizeTimelineEvent(e)
	if strings.Contains(got, " -- ") {
		t.Fatalf("should not have -- separator without secondary, got %q", got)
	}
	if !strings.Contains(got, "Status Changed") {
		t.Fatalf("expected activity type, got %q", got)
	}
}

func TestSummarizeTimelineEvent_PrimaryMatchesActivity(t *testing.T) {
	// When activityType equals primaryDescription, it should not repeat.
	e := map[string]any{
		"activityType":       "Threat Detected",
		"primaryDescription": "Threat Detected",
		"createdAt":          time.Now().Format(time.RFC3339),
	}
	got := summarizeTimelineEvent(e)
	// Should use the format "- [time] primary" without duplicating.
	count := strings.Count(got, "Threat Detected")
	if count != 1 {
		t.Fatalf("expected 1 occurrence of Threat Detected, got %d in %q", count, got)
	}
}
