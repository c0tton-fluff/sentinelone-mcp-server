package client

import (
	"os"
	"testing"

	"github.com/c0tton-fluff/sentinelone-mcp-server/config"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("SENTINELONE_API_KEY", "test-api-key-123")
	_ = os.Setenv("SENTINELONE_API_BASE", "https://test.sentinelone.net")
	if _, err := config.Load(); err != nil {
		panic("config.Load failed: " + err.Error())
	}
	os.Exit(m.Run())
}

func TestExtractAPIError_DetailField(t *testing.T) {
	body := []byte(`{"errors":[{"code":4000040,"detail":"Bad Request - could not parse query","title":"Bad Request"}]}`)
	got := extractAPIError(body)
	want := "Bad Request - could not parse query"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractAPIError_TitleOnly(t *testing.T) {
	body := []byte(`{"errors":[{"code":4000040,"title":"Bad Request"}]}`)
	got := extractAPIError(body)
	want := "Bad Request"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractAPIError_InvalidJSON(t *testing.T) {
	body := []byte(`not json at all`)
	got := extractAPIError(body)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestExtractAPIError_EmptyErrorsArray(t *testing.T) {
	body := []byte(`{"errors":[]}`)
	got := extractAPIError(body)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestExtractAPIError_NilBody(t *testing.T) {
	got := extractAPIError(nil)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestExtractAPIError_EmptyBody(t *testing.T) {
	got := extractAPIError([]byte{})
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestSanitize_RedactsAPIKey(t *testing.T) {
	input := "request to https://test.sentinelone.net failed with token test-api-key-123"
	got := sanitize(input)
	want := "request to https://test.sentinelone.net failed with token [REDACTED]"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSanitize_NoKeyUnchanged(t *testing.T) {
	input := "something went wrong with the request"
	got := sanitize(input)
	if got != input {
		t.Errorf("got %q, want %q", got, input)
	}
}

func TestNormalizeStatus(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"UNRESOLVED", "NEW"},
		{"OPEN", "NEW"},
		{"unresolved", "NEW"},
		{"INPROGRESS", "IN_PROGRESS"},
		{"RESOLVED", "RESOLVED"},
		{"IN_PROGRESS", "IN_PROGRESS"},
		{" new ", "NEW"},
	}
	for _, tt := range tests {
		got := normalizeStatus(tt.input)
		if got != tt.want {
			t.Errorf(
				"normalizeStatus(%q) = %q, want %q",
				tt.input, got, tt.want,
			)
		}
	}
}
