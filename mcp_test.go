package main

import (
	"context"
	"encoding/json"
	"testing"
)

func makeRequest(method string, id any, params any) JSONRPCRequest {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
	}
	if id != nil {
		raw, _ := json.Marshal(id)
		req.ID = raw
	}
	if params != nil {
		raw, _ := json.Marshal(params)
		req.Params = raw
	}
	return req
}

func resultMap(t *testing.T, resp *JSONRPCResponse) map[string]any {
	t.Helper()
	b, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal result to map: %v", err)
	}
	return m
}

func TestPing(t *testing.T) {
	resp := HandleRequest(context.Background(), makeRequest("ping", 1, nil))
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want %q", resp.JSONRPC, "2.0")
	}

	var gotID int
	if err := json.Unmarshal(resp.ID, &gotID); err != nil {
		t.Fatalf("unmarshal ID: %v", err)
	}
	if gotID != 1 {
		t.Errorf("id = %d, want 1", gotID)
	}

	m := resultMap(t, resp)
	if len(m) != 0 {
		t.Errorf("result = %v, want empty map", m)
	}
	if resp.Error != nil {
		t.Errorf("unexpected error: %+v", resp.Error)
	}
}

func TestInitialize(t *testing.T) {
	resp := HandleRequest(context.Background(), makeRequest("initialize", 42, nil))
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want %q", resp.JSONRPC, "2.0")
	}
	if resp.Error != nil {
		t.Errorf("unexpected error: %+v", resp.Error)
	}

	m := resultMap(t, resp)

	if v, _ := m["protocolVersion"].(string); v != "2024-11-05" {
		t.Errorf("protocolVersion = %q, want %q", v, "2024-11-05")
	}

	si, ok := m["serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("serverInfo missing or not an object")
	}
	if si["name"] != "sentinelone" {
		t.Errorf("serverInfo.name = %v, want %q", si["name"], "sentinelone")
	}
	if si["version"] != "1.0.0" {
		t.Errorf("serverInfo.version = %v, want %q", si["version"], "1.0.0")
	}

	caps, ok := m["capabilities"].(map[string]any)
	if !ok {
		t.Fatal("capabilities missing or not an object")
	}
	if _, hasTools := caps["tools"]; !hasTools {
		t.Error("capabilities.tools missing")
	}
}

func TestNotificationsInitialized(t *testing.T) {
	resp := HandleRequest(
		context.Background(),
		makeRequest("notifications/initialized", nil, nil),
	)
	if resp != nil {
		t.Errorf("expected nil response, got %+v", resp)
	}
}

func TestUnknownNotificationNoID(t *testing.T) {
	resp := HandleRequest(
		context.Background(),
		makeRequest("some/unknown/notification", nil, nil),
	)
	if resp != nil {
		t.Errorf("expected nil for unknown notification without ID, got %+v", resp)
	}
}

func TestUnknownMethodWithID(t *testing.T) {
	resp := HandleRequest(
		context.Background(),
		makeRequest("bogus/method", 99, nil),
	)
	if resp == nil {
		t.Fatal("expected error response, got nil")
	}
	if resp.Error == nil {
		t.Fatal("expected Error field to be set")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("error code = %d, want -32601", resp.Error.Code)
	}
	if resp.Result != nil {
		t.Errorf("result should be nil on error, got %v", resp.Result)
	}
}

func TestToolsCallInvalidParams(t *testing.T) {
	resp := HandleRequest(
		context.Background(),
		makeRequest("tools/call", 7, "not-a-json-object"),
	)
	if resp == nil {
		t.Fatal("expected error response, got nil")
	}
	if resp.Error == nil {
		t.Fatal("expected Error field to be set")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("error code = %d, want -32602", resp.Error.Code)
	}
	if resp.Result != nil {
		t.Errorf("result should be nil on error, got %v", resp.Result)
	}
}
