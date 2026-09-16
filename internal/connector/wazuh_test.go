package connector

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
)

func TestWazuhConnectorAuthenticatesThenListsAgents(t *testing.T) {
	var authCalls, agentCalls int32
	var capturedQuery string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/security/user/authenticate"):
			atomic.AddInt32(&authCalls, 1)
			user, pass, ok := r.BasicAuth()
			if !ok || user != "rts_wazuh_api_ro" || pass != "secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			io.WriteString(w, "jwt-token-value\n")
		case r.URL.Path == "/agents":
			atomic.AddInt32(&agentCalls, 1)
			if got := r.Header.Get("Authorization"); got != "Bearer jwt-token-value" {
				t.Errorf("Authorization = %q", got)
			}
			capturedQuery = r.URL.RawQuery
			io.WriteString(w, `{"data":{"affected_items":[
				{"id":"000","name":"manager","ip":"127.0.0.1","status":"active","version":"Wazuh v4.14.0"},
				{"id":"001","name":"node02","ip":"10.0.0.2","status":"disconnected","version":"Wazuh v4.14.0","lastKeepAlive":"2026-08-27T00:00:00Z"}
			],"total_affected_items":275,"total_failed_items":0},"message":"ok","error":0}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	connector := newTestWazuh(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI,
		Action: "agents.list",
		Limit:  500,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if evidence.ItemCount != 2 {
		t.Fatalf("ItemCount = %d, want 2", evidence.ItemCount)
	}
	if evidence.TotalAvailable != 275 {
		t.Errorf("TotalAvailable = %d, want 275", evidence.TotalAvailable)
	}
	if !evidence.Truncated {
		t.Error("Truncated should be true when the fleet exceeds the returned page")
	}
	// Items are ordered by what matters rather than by the order Wazuh returned
	// them, so look the agent up rather than assuming a position.
	var disconnected *EvidenceItem
	for i := range evidence.Items {
		if evidence.Items[i].State == "disconnected" {
			disconnected = &evidence.Items[i]
		}
	}
	if disconnected == nil {
		t.Fatalf("no disconnected agent in %+v", evidence.Items)
	}
	if disconnected.Fields["ip"] != "10.0.0.2" {
		t.Errorf("ip field = %q", disconnected.Fields["ip"])
	}
	// A down agent sorts ahead of an active one.
	if evidence.Items[0].State != "disconnected" {
		t.Errorf("items[0] = %q, want the disconnected agent first", evidence.Items[0].State)
	}
	if !strings.Contains(capturedQuery, "limit=500") {
		t.Errorf("query = %q, want the plan limit applied", capturedQuery)
	}

	// A second call must reuse the cached token rather than re-authenticating.
	if _, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI,
		Action: "agents.list",
	}); err != nil {
		t.Fatalf("second Execute() error = %v", err)
	}
	if got := atomic.LoadInt32(&authCalls); got != 1 {
		t.Errorf("authCalls = %d, want 1 (token should be cached)", got)
	}
	if got := atomic.LoadInt32(&agentCalls); got != 2 {
		t.Errorf("agentCalls = %d, want 2", got)
	}
}

func TestWazuhConnectorFiltersByHostForAgentStatus(t *testing.T) {
	var capturedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/security/user/authenticate") {
			io.WriteString(w, "jwt-token-value")
			return
		}
		capturedQuery = r.URL.RawQuery
		io.WriteString(w, `{"data":{"affected_items":[{"id":"001","name":"node02","ip":"10.0.0.2","status":"disconnected"}],"total_affected_items":1},"error":0}`)
	}))
	defer server.Close()

	connector := newTestWazuh(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI,
		Action: "agents.status",
		Host:   "node02",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(capturedQuery, "name=node02") {
		t.Errorf("query = %q, want a name filter", capturedQuery)
	}
	if evidence.Truncated {
		t.Error("a complete single-host result should not be marked truncated")
	}
}

func TestWazuhConnectorRequiresHostForAgentStatus(t *testing.T) {
	connector := newTestWazuh(t, "https://wazuh.example.edu:55000")
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI,
		Action: "agents.status",
	})
	if err == nil {
		t.Fatal("expected agents.status without a host to be rejected")
	}
}

func TestWazuhConnectorRejectsUnplannedAction(t *testing.T) {
	connector := newTestWazuh(t, "https://wazuh.example.edu:55000")
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI,
		Action: "agents.delete",
	})
	var connErr *ConnectorError
	if err == nil || !asConnectorError(err, &connErr) || connErr.Code != "unsupported_action" {
		t.Fatalf("error = %v, want unsupported_action", err)
	}
}

func TestWazuhConnectorSurfacesAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/security/user/authenticate") {
			io.WriteString(w, "jwt-token-value")
			return
		}
		io.WriteString(w, `{"data":{"affected_items":[],"total_affected_items":0},"message":"Permission denied","error":4000}`)
	}))
	defer server.Close()

	connector := newTestWazuh(t, server.URL)
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI,
		Action: "agents.list",
	})
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("error = %v, want the API message preserved", err)
	}
}

func TestWazuhConnectorFailsClosedOnBadCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	connector := newTestWazuh(t, server.URL)
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI,
		Action: "agents.list",
	})
	var connErr *ConnectorError
	if err == nil || !asConnectorError(err, &connErr) || connErr.Code != "authentication_failed" {
		t.Fatalf("error = %v, want authentication_failed", err)
	}
}

func TestWazuhConnectorRequiresConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config WazuhConfig
	}{
		{"missing endpoint", WazuhConfig{Username: "u", Password: "p"}},
		{"missing username", WazuhConfig{Endpoint: "https://w.example.edu:55000", Password: "p"}},
		{"missing password", WazuhConfig{Endpoint: "https://w.example.edu:55000", Username: "u"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewWazuhConnector(test.config); err == nil {
				t.Fatal("expected configuration to be rejected")
			}
		})
	}
}

func newTestWazuh(t *testing.T, endpoint string) *WazuhConnector {
	t.Helper()
	connector, err := NewWazuhConnector(WazuhConfig{
		Endpoint: endpoint,
		Username: "rts_wazuh_api_ro",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("NewWazuhConnector() error = %v", err)
	}
	return connector
}

func TestWazuhSummaryExcludesManagerAndMatchesDashboard(t *testing.T) {
	// The manager's own record (id 000) appears in GET /agents but not in the
	// manager's summary endpoint. Counting it would put our numbers one above
	// what the Wazuh dashboard shows.
	agents := []wazuhAgent{
		{ID: "000", Name: "manager", Status: "active"},
		{ID: "001", Name: "node01", Status: "active"},
		{ID: "002", Name: "node02", Status: "disconnected"},
		{ID: "003", Name: "node03", Status: "disconnected"},
	}
	summary := summarizeAgents(agents, nil)

	if summary["total"] != 3 {
		t.Errorf("total = %d, want 3 (manager excluded)", summary["total"])
	}
	if summary["active"] != 1 {
		t.Errorf("active = %d, want 1 (manager excluded)", summary["active"])
	}
	if summary["disconnected"] != 2 {
		t.Errorf("disconnected = %d, want 2", summary["disconnected"])
	}
}

// Which machines are both down and important is arithmetic over a list of
// several hundred, so it is settled here rather than left to a model.
func TestSummarizeAgentsCountsCriticalGroups(t *testing.T) {
	critical := map[string]struct{}{"RTS_Ops": {}, "Viper": {}}
	agents := []wazuhAgent{
		{ID: "000", Name: "manager", Status: "active", Group: []string{"RTS_Ops"}},
		{ID: "001", Name: "zabbixproxy01", Status: "disconnected", Group: []string{"default", "Zabbix", "RTS_Ops"}},
		{ID: "023", Name: "lucee", Status: "disconnected", Group: []string{"default", "RTS_Ops"}},
		{ID: "100", Name: "viper-a", Status: "disconnected", Group: []string{"Viper"}},
		{ID: "101", Name: "viper-b", Status: "active", Group: []string{"Viper"}},
		{ID: "200", Name: "ordinary", Status: "disconnected", Group: []string{"default"}},
		{ID: "201", Name: "wrong-case", Status: "disconnected", Group: []string{"rts_ops"}},
	}
	summary := summarizeAgents(agents, critical)

	if summary["disconnected"] != 5 {
		t.Fatalf("disconnected = %d, want 5", summary["disconnected"])
	}
	// Three of the five: zabbixproxy01, lucee, viper-a. The ordinary agent is
	// not in a critical group, and "rts_ops" is a different group from
	// "RTS_Ops" because Wazuh group names are case sensitive.
	if summary["critical_disconnected"] != 3 {
		t.Fatalf("critical_disconnected = %d, want 3", summary["critical_disconnected"])
	}
	// The manager is excluded from every total, critical or not.
	if summary["critical_total"] != 4 {
		t.Fatalf("critical_total = %d, want 4 (manager excluded)", summary["critical_total"])
	}
	if summary["total"] != 6 {
		t.Fatalf("total = %d, want 6", summary["total"])
	}
}

// The reverse of what this test used to assert. Omitting the critical keys when
// no groups were configured produced a false all-clear in a Zoom channel: the
// model read the absence as zero and reported that no critical agents were
// disconnected. The summary must instead say plainly that the check did not
// run.
func TestSummarizeAgentsSaysWhenTheCriticalCheckDidNotRun(t *testing.T) {
	agents := []wazuhAgent{{ID: "1", Status: "disconnected", Group: []string{"RTS_Ops"}}}
	summary := summarizeAgents(agents, nil)

	configured, present := summary["critical_groups_configured"]
	if !present {
		t.Fatal("summary must always state whether critical groups are configured")
	}
	if configured != 0 {
		t.Fatalf("critical_groups_configured = %d, want 0", configured)
	}
	// No count may appear, because none was computed. A zero here would be a
	// claim, and the claim would be false.
	if _, found := summary["critical_disconnected"]; found {
		t.Fatal("an uncomputed count must be absent, not zero")
	}
}

// When groups are configured, the count is present even at zero, so a reader
// can tell "checked, none affected" from "never checked".
func TestSummarizeAgentsReportsZeroWhenConfiguredAndNoneAffected(t *testing.T) {
	critical := map[string]struct{}{"Viper": {}}
	agents := []wazuhAgent{{ID: "1", Name: "ordinary", Status: "disconnected", Group: []string{"default"}}}
	summary := summarizeAgents(agents, critical)

	if summary["critical_groups_configured"] != 1 {
		t.Fatalf("critical_groups_configured = %d, want 1", summary["critical_groups_configured"])
	}
	count, present := summary["critical_disconnected"]
	if !present {
		t.Fatal("a configured check must report its count even when zero")
	}
	if count != 0 {
		t.Fatalf("critical_disconnected = %d, want 0", count)
	}
}

// An answer has to be able to name the critical hosts, not just count them.
func TestNormalizeAgentsMarksCriticalItems(t *testing.T) {
	critical := map[string]struct{}{"RTS_Ops": {}}
	items := normalizeAgents([]wazuhAgent{
		{ID: "023", Name: "lucee", Status: "disconnected", Group: []string{"default", "RTS_Ops"}},
		{ID: "200", Name: "ordinary", Status: "disconnected", Group: []string{"default"}},
	}, critical)

	if items[0].Fields["critical"] != "true" {
		t.Fatalf("lucee not marked critical: %v", items[0].Fields)
	}
	if items[0].Fields["groups"] != "default,RTS_Ops" {
		t.Fatalf("groups = %q", items[0].Fields["groups"])
	}
	if _, marked := items[1].Fields["critical"]; marked {
		t.Fatal("an agent outside every critical group must not be marked")
	}
}

// The item list is capped, so what survives the cap has to be what matters.
// Critical agents that are down come first, then anything else down.
func TestNormalizeAgentsOrdersByWhatMatters(t *testing.T) {
	critical := map[string]struct{}{"RTS_Ops": {}}
	items := normalizeAgents([]wazuhAgent{
		{ID: "1", Name: "zzz-active-ordinary", Status: "active"},
		{ID: "2", Name: "mmm-down-ordinary", Status: "disconnected"},
		{ID: "3", Name: "aaa-active-critical", Status: "active", Group: []string{"RTS_Ops"}},
		{ID: "4", Name: "yyy-down-critical", Status: "disconnected", Group: []string{"RTS_Ops"}},
		{ID: "5", Name: "bbb-down-critical", Status: "disconnected", Group: []string{"RTS_Ops"}},
	}, critical)

	got := make([]string, len(items))
	for i, item := range items {
		got[i] = item.Host
	}
	want := []string{
		"bbb-down-critical", "yyy-down-critical", // critical and down, by name
		"mmm-down-ordinary",   // down
		"aaa-active-critical", // critical, up
		"zzz-active-ordinary", // neither
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order[%d] = %s, want %s\n  got: %v", i, got[i], want[i], got)
		}
	}
}

// A check that did not run must say so in words, not by leaving a key out.
// Every mechanism that expressed this by omission was resolved the reassuring
// way by the model reading it.
func TestWazuhWarnsWhenCriticalGroupsAreUnconfigured(t *testing.T) {
	server := newAgentsServer(t)
	defer server.Close()

	connector := newTestWazuh(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI, Action: "agents.list", Limit: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Warnings) == 0 {
		t.Fatal("an unevaluated critical check must warn")
	}
	if !strings.Contains(evidence.Warnings[0], "NOT evaluated") {
		t.Fatalf("warning does not say the check was skipped: %q", evidence.Warnings[0])
	}
}

// Configured, the check runs and there is nothing to warn about.
func TestWazuhDoesNotWarnWhenConfigured(t *testing.T) {
	server := newAgentsServer(t)
	defer server.Close()

	connector := newTestWazuh(t, server.URL)
	connector.criticalGroups = map[string]struct{}{"RTS_Ops": {}}
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceWazuhAPI, Action: "agents.list", Limit: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", evidence.Warnings)
	}
}

// newAgentsServer is a minimal manager: authenticate, then one small fleet in
// which node02 belongs to RTS_Ops.
func newAgentsServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/security/user/authenticate"):
			io.WriteString(w, "jwt-token-value\n")
		case r.URL.Path == "/agents":
			io.WriteString(w, `{"data":{"affected_items":[
				{"id":"000","name":"manager","status":"active","group":["RTS_Ops"]},
				{"id":"001","name":"node02","status":"disconnected","group":["default","RTS_Ops"]}
			],"total_affected_items":2,"total_failed_items":0},"message":"ok","error":0}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}
