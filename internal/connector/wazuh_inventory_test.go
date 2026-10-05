package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
)

// fakeInventory is a Wazuh manager holding one agent's syscollector tables.
// It answers the agent lookup, the filtered table reads and the freshness
// read, and records every query it is sent.
type fakeInventory struct {
	agent     string // JSON for the agent lookup's affected_items; "" for none
	processes string // JSON affected_items for a processes read
	procTotal int
	ports     map[string]string // q filter, without any match -> affected_items
	portTotal map[string]int
	newest    string // scan.time of the newest row; "" for an empty table
	tableBody string // if set, the raw body of every table read

	mu      sync.Mutex
	queries []string
}

func (f *fakeInventory) serve(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.queries = append(f.queries, r.URL.Path+"?"+r.URL.RawQuery)
		f.mu.Unlock()
		query := r.URL.Query()
		switch {
		case strings.HasPrefix(r.URL.Path, "/security/user/authenticate"):
			io.WriteString(w, "jwt\n")
		case r.URL.Path == "/agents":
			items := "[]"
			if f.agent != "" {
				items = "[" + f.agent + "]"
			}
			fmt.Fprintf(w, `{"data":{"affected_items":%s,"total_affected_items":%d},"error":0}`, items, strings.Count(items, `"id"`))
		case strings.HasPrefix(r.URL.Path, "/syscollector/"):
			if f.tableBody != "" {
				io.WriteString(w, f.tableBody)
				return
			}
			if query.Get("sort") == "-scan.time" {
				if f.newest == "" {
					io.WriteString(w, `{"data":{"affected_items":[],"total_affected_items":0},"error":0}`)
					return
				}
				fmt.Fprintf(w, `{"data":{"affected_items":[{"scan":{"time":%q}}],"total_affected_items":1},"error":0}`, f.newest)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/processes") {
				fmt.Fprintf(w, `{"data":{"affected_items":%s,"total_affected_items":%d},"error":0}`, f.processes, f.procTotal)
				return
			}
			// Keyed on the filter before any ';process~' match, exactly:
			// protocol=udp6 also begins with protocol=udp.
			filter := strings.SplitN(query.Get("q"), ";", 2)[0]
			if items, ok := f.ports[filter]; ok {
				fmt.Fprintf(w, `{"data":{"affected_items":%s,"total_affected_items":%d},"error":0}`, items, f.portTotal[filter])
				return
			}
			io.WriteString(w, `{"data":{"affected_items":[],"total_affected_items":0},"error":0}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func (f *fakeInventory) sent(path string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, q := range f.queries {
		if strings.Contains(q, path) {
			out = append(out, q)
		}
	}
	return out
}

func inventoryConnector(t *testing.T, endpoint string) *WazuhConnector {
	t.Helper()
	c, err := NewWazuhConnector(WazuhConfig{Endpoint: endpoint, Username: "u", Password: "p",
		CriticalGroups: []string{"RTS_Ops"}})
	if err != nil {
		t.Fatalf("NewWazuhConnector() error = %v", err)
	}
	return c
}

func inventoryStep(action, match string) broker.RouteStep {
	return broker.RouteStep{Source: broker.SourceWazuhAPI, Action: action, Host: "node01.example.edu", Match: match}
}

const activeAgent = `{"id":"022","name":"node01.example.edu","status":"active","lastKeepAlive":"2026-10-05T11:00:00+00:00"}`

func minutesAgo(m int) string {
	return time.Now().UTC().Add(-time.Duration(m) * time.Minute).Format(time.RFC3339)
}

// Command lines can carry passwords. They are never asked for, and a manager
// that sent them anyway would still not get them into evidence.
func TestInventoryNeverReturnsCommandLines(t *testing.T) {
	fake := &fakeInventory{
		agent: activeAgent,
		processes: `[{"name":"mysqld","pid":"4242","ppid":1,"euser":"mysql","state":"S","start_time":1784395235,
			"cmd":"/usr/sbin/mysqld --password=hunter2","argvs":"--password=hunter2","scan":{"time":"2026-07-18T22:17:57+00:00"}}]`,
		procTotal: 1,
		newest:    minutesAgo(30),
	}
	server := fake.serve(t)
	defer server.Close()

	evidence, err := inventoryConnector(t, server.URL).Execute(context.Background(),
		inventoryStep("syscollector.processes", "mysql"))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	encoded, _ := json.Marshal(evidence)
	if strings.Contains(string(encoded), "hunter2") || strings.Contains(string(encoded), "--password") {
		t.Fatalf("a command line reached evidence: %s", encoded)
	}
	reads := fake.sent("/processes")
	if len(reads) == 0 || !strings.Contains(reads[0], "select=") || strings.Contains(reads[0], "cmd") {
		t.Errorf("processes read %q must name its fields and never cmd", reads)
	}
	if !strings.Contains(reads[0], "q=name~mysql") || !strings.Contains(reads[0], "sort=%2Bname") {
		t.Errorf("processes read %q does not carry the match and the name ordering", reads[0])
	}
	if evidence.Items[0].Description != "mysqld" || evidence.Items[0].Fields["user"] != "mysql" ||
		evidence.Items[0].Fields["pid"] != "4242" || evidence.Items[0].Fields["started"] == "" {
		t.Errorf("item = %+v, want the process with its user, pid and start time", evidence.Items[0])
	}
	if len(evidence.Warnings) != 0 {
		t.Errorf("a fresh inventory of an active agent carries warnings: %v", evidence.Warnings)
	}
	if len(evidence.Notes) != 1 || !strings.Contains(evidence.Notes[0], "newest change") {
		t.Errorf("notes = %v, want the inventory's age stated", evidence.Notes)
	}
	if age := evidence.Summary["newest_change_age_minutes"]; age < 29 || age > 31 {
		t.Errorf("newest_change_age_minutes = %d, want about 30", age)
	}
}

// An unknown name must fail: an empty inventory would read as a host running
// nothing.
func TestInventoryOfAnUnknownAgentIsAnError(t *testing.T) {
	fake := &fakeInventory{}
	server := fake.serve(t)
	defer server.Close()

	_, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep("syscollector.processes", ""))
	if connErr, ok := err.(*ConnectorError); !ok || connErr.Code != "unknown_agent" {
		t.Fatalf("error = %v, want unknown_agent", err)
	}
	if len(fake.sent("/syscollector/")) != 0 {
		t.Error("syscollector was read for an agent that does not exist")
	}
}

// Measured: an agent silent since July still serves thousands of process
// rows, and nothing in them says they are old.
func TestInventoryOfADisconnectedAgentWarnsFirst(t *testing.T) {
	fake := &fakeInventory{
		agent:     `{"id":"001","name":"node01.example.edu","status":"disconnected","lastKeepAlive":"2026-07-17T19:52:58+00:00"}`,
		processes: `[{"name":"zabbix_proxy","pid":"900","scan":{"time":"2026-07-17T18:58:20+00:00"}}]`,
		procTotal: 4403,
		newest:    "2026-07-17T18:58:20+00:00",
	}
	server := fake.serve(t)
	defer server.Close()

	evidence, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep("syscollector.processes", ""))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(evidence.Warnings) == 0 || !strings.Contains(evidence.Warnings[0], "disconnected") ||
		!strings.Contains(evidence.Warnings[0], "2026-07-17T19:52:58") {
		t.Errorf("warnings = %v, want the disconnection and its last contact first", evidence.Warnings)
	}
}

func TestInventoryWarnsWhenItsNewestChangeIsOld(t *testing.T) {
	for name, tc := range map[string]struct {
		newest    string
		wantStale bool
	}{
		"within the hour": {minutesAgo(50), false},
		"five hours old":  {minutesAgo(300), true},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeInventory{agent: activeAgent, processes: `[]`, newest: tc.newest}
			server := fake.serve(t)
			defer server.Close()
			evidence, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep("syscollector.processes", ""))
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			stale := len(evidence.Warnings) > 0 && strings.Contains(evidence.Warnings[0], "may not describe the host")
			if stale != tc.wantStale {
				t.Errorf("stale warning = %v, want %v; warnings %v", stale, tc.wantStale, evidence.Warnings)
			}
		})
	}
}

// No rows at all is not "nothing is running": syscollector may be off.
func TestAnEmptyInventoryIsNotReportedAsAnIdleHost(t *testing.T) {
	fake := &fakeInventory{agent: activeAgent, processes: `[]`}
	server := fake.serve(t)
	defer server.Close()
	evidence, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep("syscollector.processes", ""))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(evidence.Warnings) == 0 || !strings.Contains(evidence.Warnings[0], "not evidence that nothing is running") {
		t.Errorf("warnings = %v, want an empty table called out", evidence.Warnings)
	}
}

// UDP has no listening state, so listeners are TCP in the listening state
// plus every bound UDP socket, each filtered by Wazuh.
func TestListenersMergeListeningTCPWithBoundUDP(t *testing.T) {
	fake := &fakeInventory{
		agent: activeAgent,
		ports: map[string]string{
			"state=listening": `[{"local":{"ip":"::","port":22},"protocol":"tcp6","process":"sshd","pid":2399,"state":"listening","scan":{"time":"2026-07-18T22:17:56+00:00"}},
				{"local":{"ip":"0.0.0.0","port":9085},"protocol":"tcp","process":"","pid":0,"state":"listening","scan":{"time":"2026-07-18T22:17:56+00:00"}}]`,
			"protocol=udp":  `[{"local":{"ip":"127.0.0.1","port":323},"protocol":"udp","process":"chronyd","pid":2284,"scan":{"time":"2026-07-18T22:17:57+00:00"}}]`,
			"protocol=udp6": `[]`,
		},
		portTotal: map[string]int{"state=listening": 2, "protocol=udp": 1, "protocol=udp6": 0},
		newest:    minutesAgo(20),
	}
	server := fake.serve(t)
	defer server.Close()

	evidence, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep("syscollector.listeners", ""))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	want := map[string]int{"tcp_listening": 2, "udp_bound": 1, "total_matching": 3, "returned": 3, "returned_without_process": 1}
	for key, value := range want {
		if evidence.Summary[key] != value {
			t.Errorf("summary[%s] = %d, want %d (summary %v)", key, evidence.Summary[key], value, evidence.Summary)
		}
	}
	if evidence.Items[0].Fields["port"] != "22" || evidence.Items[0].Fields["process"] != "sshd" ||
		evidence.Items[2].Fields["port"] != "9085" {
		t.Errorf("items are not ordered by port with their owners: %+v", evidence.Items)
	}
	for _, q := range fake.sent("/ports") {
		if strings.Contains(q, "cmd") {
			t.Errorf("ports read %q asks for cmd", q)
		}
	}
}

func TestListenersCarryTheProcessMatchIntoEveryQuery(t *testing.T) {
	fake := &fakeInventory{agent: activeAgent, newest: minutesAgo(5)}
	server := fake.serve(t)
	defer server.Close()
	if _, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep("syscollector.listeners", "sshd")); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	filtered := 0
	for _, q := range fake.sent("/ports") {
		if strings.Contains(q, "sort=-scan.time") {
			continue
		}
		if !strings.Contains(q, "%3Bprocess~sshd") {
			t.Errorf("ports read %q does not carry the process match", q)
		}
		filtered++
	}
	if filtered != 3 {
		t.Errorf("%d filtered ports reads, want 3 (tcp listening, udp, udp6)", filtered)
	}
}

func TestInventoryCapKeepsTheExactTotal(t *testing.T) {
	rows := make([]string, inventoryItemCap)
	for i := range rows {
		rows[i] = fmt.Sprintf(`{"name":"p%03d","pid":"%d","scan":{"time":"2026-10-05T11:00:00+00:00"}}`, i, i+1)
	}
	fake := &fakeInventory{agent: activeAgent, processes: "[" + strings.Join(rows, ",") + "]", procTotal: 1113, newest: minutesAgo(10)}
	server := fake.serve(t)
	defer server.Close()
	evidence, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep("syscollector.processes", ""))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !evidence.Truncated || evidence.TotalAvailable != 1113 || evidence.Summary["total_matching"] != 1113 ||
		evidence.ItemCount != inventoryItemCap {
		t.Errorf("truncated=%v total=%d summary=%v items=%d, want a capped page with the exact total",
			evidence.Truncated, evidence.TotalAvailable, evidence.Summary, evidence.ItemCount)
	}
}

// A moved endpoint and an error reported inside a 200 must both fail, never
// come back as an empty, clean-looking host.
func TestInventoryFailuresAreErrorsNotEmptyAnswers(t *testing.T) {
	for name, body := range map[string]string{
		"wazuh error in a 200": `{"data":{"affected_items":[],"total_affected_items":0},"message":"No syscollector information was returned","error":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeInventory{agent: activeAgent, tableBody: body}
			server := fake.serve(t)
			defer server.Close()
			if _, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep("syscollector.processes", "")); err == nil {
				t.Fatal("an error reported by Wazuh came back as evidence")
			}
		})
	}

	t.Run("endpoint gone", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasPrefix(r.URL.Path, "/security/user/authenticate"):
				io.WriteString(w, "jwt\n")
			case r.URL.Path == "/agents":
				io.WriteString(w, `{"data":{"affected_items":[`+activeAgent+`],"total_affected_items":1},"error":0}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()
		_, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep("syscollector.listeners", ""))
		if connErr, ok := err.(*ConnectorError); !ok || connErr.Code != "http_status" {
			t.Fatalf("error = %v, want http_status for a 404", err)
		}
	})
}

// For listeners a numeric match filters the port, not the process name, in
// every one of the three queries.
func TestListenersReadANumericMatchAsAPort(t *testing.T) {
	fake := &fakeInventory{agent: activeAgent, newest: minutesAgo(5)}
	server := fake.serve(t)
	defer server.Close()
	if _, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep("syscollector.listeners", "8443")); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	filtered := 0
	for _, q := range fake.sent("/ports") {
		if strings.Contains(q, "sort=-scan.time") {
			continue
		}
		if !strings.Contains(q, "%3Blocal.port%3D8443") || strings.Contains(q, "process~") {
			t.Errorf("ports read %q does not filter on the port", q)
		}
		filtered++
	}
	if filtered != 3 {
		t.Errorf("%d filtered ports reads, want 3", filtered)
	}
}

// An empty filtered result must say it is empty because of the filter; read
// bare, it says the host runs or listens on nothing of the kind.
func TestAnEmptyFilteredResultSaysWhatWasFiltered(t *testing.T) {
	for name, tc := range map[string]struct {
		action, match, want string
	}{
		"process name":   {"syscollector.processes", "nosuchd", `process names containing "nosuchd"`},
		"listener owner": {"syscollector.listeners", "nosuchd", `owning process name contains "nosuchd"`},
		"listener port":  {"syscollector.listeners", "8443", `listeners on port "8443"`},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeInventory{agent: activeAgent, processes: `[]`, newest: minutesAgo(5)}
			server := fake.serve(t)
			defer server.Close()
			evidence, err := inventoryConnector(t, server.URL).Execute(context.Background(), inventoryStep(tc.action, tc.match))
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			found := false
			for _, note := range evidence.Notes {
				if strings.Contains(note, tc.want) && strings.Contains(note, "not that nothing is running or listening") {
					found = true
				}
			}
			if !found {
				t.Errorf("notes = %v, want the empty filter explained (%s)", evidence.Notes, tc.want)
			}
		})
	}
}
