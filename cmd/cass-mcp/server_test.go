package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	glenKey    = "mr2_glen_test_key"
	hectorKey  = "mr2_hector_test_key"
	revokedKey = "mr2_revoked_test_key"
)

func testServer(t *testing.T, run Runner) (*Server, *int32) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowlist")
	body := "# test allowlist\n" + TokenHash(glenKey) + " glen\n" + TokenHash(revokedKey) + " former staff\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	allowlist, err := NewAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	var calls int32
	validate := func(ctx context.Context, token string) (bool, error) {
		atomic.AddInt32(&calls, 1)
		return token != revokedKey, nil
	}
	if run == nil {
		run = func(ctx context.Context, c Caller, q string) (Answer, error) {
			return Answer{Text: "52 agents are disconnected.", Evidence: json.RawMessage(`[{"evidence":[{"summary":{"disconnected":52}}]}]`)}, nil
		}
	}
	return NewServer(allowlist, validate, run, 4, 2, io.Discard), &calls
}

func rpc(t *testing.T, s *Server, key, session, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestKeysAreCheckedAgainstTheAllowlistBeforeMindRouter(t *testing.T) {
	s, calls := testServer(t, nil)
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	if rec := rpc(t, s, "", "", ping); rec.Code != http.StatusUnauthorized {
		t.Errorf("no key: status %d, want 401", rec.Code)
	}
	if rec := rpc(t, s, hectorKey, "", ping); rec.Code != http.StatusForbidden {
		t.Errorf("valid MindRouter key not on the allowlist: status %d, want 403", rec.Code)
	}
	if *calls != 0 {
		t.Errorf("MindRouter was asked %d times about keys the allowlist already refused", *calls)
	}
	if rec := rpc(t, s, revokedKey, "", ping); rec.Code != http.StatusUnauthorized {
		t.Errorf("allowlisted key MindRouter rejects: status %d, want 401", rec.Code)
	}
	if rec := rpc(t, s, glenKey, "", ping); rec.Code != http.StatusOK {
		t.Errorf("allowlisted, valid key: status %d, want 200", rec.Code)
	}
}

func TestAskRunsAsTheCallerWithTheirAgentNamed(t *testing.T) {
	var got Caller
	s, _ := testServer(t, func(ctx context.Context, c Caller, q string) (Answer, error) {
		got = c
		return Answer{Text: "ok", Evidence: json.RawMessage(`[]`)}, nil
	})
	init := rpc(t, s, glenKey, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"claude-code","version":"2.1"}}}`)
	var initResp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	json.Unmarshal(init.Body.Bytes(), &initResp)
	if initResp.Result.ProtocolVersion != "2025-03-26" {
		t.Errorf("negotiated %q, want the client's 2025-03-26", initResp.Result.ProtocolVersion)
	}
	session := init.Header().Get("Mcp-Session-Id")
	if session == "" {
		t.Fatal("initialize returned no Mcp-Session-Id")
	}
	if rec := rpc(t, s, glenKey, session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); rec.Code != http.StatusAccepted {
		t.Errorf("notification: status %d, want 202", rec.Code)
	}
	list := rpc(t, s, glenKey, session, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if !strings.Contains(list.Body.String(), `"cass_ask"`) {
		t.Fatalf("tools/list = %s, want cass_ask", list.Body.String())
	}
	call := rpc(t, s, glenKey, session, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"cass_ask","arguments":{"question":"how many agents are disconnected?"}}}`)
	if !strings.Contains(call.Body.String(), `"structuredContent"`) {
		t.Errorf("tools/call = %s, want structuredContent with the evidence", call.Body.String())
	}
	if got.Person != "glen" || got.Token != glenKey || got.Client != "claude-code 2.1" {
		t.Errorf("ran as %+v, want glen with his own key via claude-code 2.1", got)
	}
}

func TestOnePersonCannotTakeEverySlot(t *testing.T) {
	s, _ := testServer(t, nil)
	r1, busy := s.acquire("glen")
	if busy != "" {
		t.Fatal(busy)
	}
	r2, busy := s.acquire("glen")
	if busy != "" {
		t.Fatal(busy)
	}
	if _, busy := s.acquire("glen"); busy == "" {
		t.Error("a third concurrent question for one person was accepted; the limit is 2")
	}
	if release, busy := s.acquire("hector"); busy != "" {
		t.Errorf("someone else was refused while slots remained: %s", busy)
	} else {
		release()
	}
	r1()
	r2()
}

func TestTheServicesOwnKeyNeverReachesAQuestion(t *testing.T) {
	env := []string{"PATH=/bin", "MINDROUTER_API_KEY=service-key", "CASS_ZABBIX_ENDPOINT=x"}
	for _, kv := range withoutKey(env) {
		if strings.Contains(kv, "service-key") {
			t.Errorf("%q survived; a question could run on the service's key instead of the caller's", kv)
		}
	}
}

func TestAllowlistRejectsMalformedLines(t *testing.T) {
	if _, err := parseAllowlist(bytes.NewBufferString("glen sha256:abc\n")); err == nil {
		t.Error("a malformed line was accepted")
	}
}

func TestIdleSessionsAreForgottenWhenANewOneStarts(t *testing.T) {
	s, _ := testServer(t, nil)
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"hermes"}}}`
	stale := rpc(t, s, glenKey, "", initialize).Header().Get("Mcp-Session-Id")
	live := rpc(t, s, glenKey, "", initialize).Header().Get("Mcp-Session-Id")
	s.mu.Lock()
	s.sessions[stale] = session{client: "hermes", seen: time.Now().Add(-sessionIdleTTL - time.Minute)}
	s.sessions[live] = session{client: "hermes", seen: time.Now().Add(-sessionIdleTTL + time.Minute)}
	s.mu.Unlock()

	// Using a session keeps it; starting another sweeps out the idle ones.
	rpc(t, s, glenKey, live, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	rpc(t, s, glenKey, "", initialize)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[stale]; ok {
		t.Error("a session idle longer than sessionIdleTTL survived a new initialize")
	}
	if _, ok := s.sessions[live]; !ok {
		t.Error("a session used just now was forgotten")
	}
	if len(s.sessions) != 2 {
		t.Errorf("%d sessions remembered, want 2 (the live one and the new one)", len(s.sessions))
	}
}

// The description is all an MCP client has to decide whether a question is
// Cassandra's. When the inventory intents shipped it still said only "Wazuh
// agent inventory", so a client asked which process owns a port had no reason
// to call cass_ask at all.
func TestTheToolDescriptionNamesHostProcessesAndPorts(t *testing.T) {
	description, _ := askTool()["description"].(string)
	for _, want := range []string{"processes", "listening ports"} {
		if !strings.Contains(description, want) {
			t.Errorf("cass_ask description does not mention %q: %s", want, description)
		}
	}
}
