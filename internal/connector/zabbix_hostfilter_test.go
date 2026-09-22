package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
)

// captures every JSON-RPC call so a test can assert what the API was actually
// asked, rather than what the code appears to ask.
type zabbixCapture struct {
	method string
	params map[string]any
}

func zabbixStub(t *testing.T, calls *[]zabbixCapture, hostIDs []string, events int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.Unmarshal(body, &request)
		*calls = append(*calls, zabbixCapture{method: request.Method, params: request.Params})

		switch request.Method {
		case "user.login", "apiinfo.version":
			io.WriteString(w, `{"result":"session-token"}`)
		case "host.get":
			parts := make([]string, 0, len(hostIDs))
			for _, id := range hostIDs {
				parts = append(parts, `{"hostid":"`+id+`"}`)
			}
			io.WriteString(w, `{"result":[`+strings.Join(parts, ",")+`]}`)
		case "event.get":
			rows := make([]string, 0, events)
			for i := 0; i < events; i++ {
				rows = append(rows, `{"eventid":"9`+string(rune('0'+i%10))+
					`","clock":"1788000000","name":"Power supply problem","severity":"4","value":"1",`+
					`"hosts":[{"host":"cpu040"}]}`)
			}
			io.WriteString(w, `{"result":[`+strings.Join(rows, ",")+`]}`)
		default:
			io.WriteString(w, `{"result":[]}`)
		}
	}))
}

func newHostFilterConnector(t *testing.T, endpoint string) *ZabbixConnector {
	t.Helper()
	connector, err := NewZabbixConnector(ZabbixConfig{
		Endpoint: endpoint, Token: "zabbix-test-token-0123456789",
	})
	if err != nil {
		t.Fatalf("NewZabbixConnector() error = %v", err)
	}
	return connector
}

// The bug: event.get was sent `host`, which it does not accept and silently
// ignores. A question about one host returned 25 of 88,216 cluster-wide
// events, and the census ran with the same params so even the total was
// unfiltered. Only `hostids` narrows event.get.
func TestEventHistoryFiltersByHostIDsNotHostName(t *testing.T) {
	var calls []zabbixCapture
	server := zabbixStub(t, &calls, []string{"10684"}, 3)
	defer server.Close()

	_, err := newHostFilterConnector(t, server.URL).Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI, Action: "event.get",
		Host: "cpu040", Since: "2026-09-01T00:00:00Z", Until: "2026-09-02T00:00:00Z", Limit: 25,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	var sawEventGet bool
	for _, call := range calls {
		if call.method != "event.get" {
			continue
		}
		sawEventGet = true
		if _, present := call.params["host"]; present {
			t.Error(`event.get was sent "host", which it ignores; the filter would not apply`)
		}
		ids, present := call.params["hostids"]
		if !present {
			t.Fatal(`event.get was not sent "hostids"; nothing narrows the query to the host`)
		}
		encoded, _ := json.Marshal(ids)
		if !strings.Contains(string(encoded), "10684") {
			t.Errorf("hostids = %s, want the resolved id 10684", encoded)
		}
	}
	if !sawEventGet {
		t.Fatal("event.get was never called")
	}
}

// Both the fetch and the census must be scoped, or the total describes the
// cluster while the rows describe the host -- which is how "25 of 88,216"
// read as a sampling problem rather than an unapplied filter.
func TestEventHistoryCensusIsAlsoScopedToTheHost(t *testing.T) {
	var calls []zabbixCapture
	server := zabbixStub(t, &calls, []string{"10684"}, 3)
	defer server.Close()

	_, err := newHostFilterConnector(t, server.URL).Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI, Action: "event.get",
		Host: "cpu040", Since: "2026-09-01T00:00:00Z", Limit: 25,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var eventCalls int
	for _, call := range calls {
		if call.method != "event.get" {
			continue
		}
		eventCalls++
		if _, present := call.params["hostids"]; !present {
			t.Errorf("event.get call %d carries no hostids; one of fetch or census is unscoped", eventCalls)
		}
	}
	if eventCalls < 2 {
		t.Skipf("only %d event.get calls; census may not have run for this fixture", eventCalls)
	}
}

// A host Zabbix has never heard of must be refused. Returning the cluster's
// events is the worst available answer: voluminous, confident, and about
// other machines.
func TestEventHistoryRefusesAnUnknownHost(t *testing.T) {
	var calls []zabbixCapture
	server := zabbixStub(t, &calls, nil, 5) // host.get resolves nothing
	defer server.Close()

	_, err := newHostFilterConnector(t, server.URL).Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI, Action: "event.get",
		Host: "does-not-exist", Since: "2026-09-01T00:00:00Z", Limit: 25,
	})
	if err == nil {
		t.Fatal("an unknown host was accepted; the cluster's events would be returned for it")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error = %v, want it to name the host", err)
	}
	for _, call := range calls {
		if call.method == "event.get" {
			t.Error("event.get ran for an unresolvable host; the refusal must come first")
		}
	}
}

func TestEventHistorySurfacesHostLookupError(t *testing.T) {
	var eventCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if request.Method == "event.get" {
			eventCalls++
		}
		io.WriteString(w, `{"error":{"code":-32602,"message":"No permissions","data":"host.get denied"}}`)
	}))
	defer server.Close()

	_, err := newHostFilterConnector(t, server.URL).Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI, Action: "event.get",
		Host: "cpu040", Since: "2026-09-01T00:00:00Z", Limit: 25,
	})
	var connectorErr *ConnectorError
	if !errors.As(err, &connectorErr) || connectorErr.Code != "zabbix_error" {
		t.Fatalf("Execute() error = %v, want zabbix_error rather than unknown_host", err)
	}
	if eventCalls != 0 {
		t.Errorf("event.get ran %d times after host.get failed", eventCalls)
	}
}

// The selector has to appear in the evidence. Match, Severity and State are
// recorded so an unapplied filter is visible; Host was the one missing, and
// it was the one being dropped.
func TestEventHistoryRecordsTheHostSelector(t *testing.T) {
	var calls []zabbixCapture
	server := zabbixStub(t, &calls, []string{"10684"}, 2)
	defer server.Close()

	evidence, err := newHostFilterConnector(t, server.URL).Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI, Action: "event.get",
		Host: "cpu040", Since: "2026-09-01T00:00:00Z", Limit: 25,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if evidence.Host != "cpu040" {
		t.Errorf("Evidence.Host = %q, want cpu040 -- a reader cannot tell the filter applied", evidence.Host)
	}
	if evidence.Ordering != "newest first by event time" {
		t.Errorf("Evidence.Ordering = %q, want newest first by event time", evidence.Ordering)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), "host_filter") {
		t.Error("the host selector is absent from serialized evidence, so the model never sees it")
	}
}
