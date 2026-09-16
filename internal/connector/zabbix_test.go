package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
)

func TestZabbixConnectorNormalizesTriggers(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json-rpc" {
			t.Errorf("Content-Type = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"priority"]`) && !strings.Contains(string(body), "selectHosts") {
			// The severity census asks for priority only and strips presentation
			// parameters, so it must not overwrite what the data call sent.
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[{"priority":"4"},{"priority":"2"}]}`)
			return
		}
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
			{"triggerid":"101","description":"Disk space low","priority":"4","value":"1","lastchange":"1756300000","hosts":[{"host":"node01"}]},
			{"triggerid":"102","description":"Agent unreachable","priority":"2","value":"1","lastchange":"1756300100","hosts":[{"host":"node02"}]}
		]}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
		Limit:  25,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if captured["method"] != "trigger.get" {
		t.Errorf("method = %v, want trigger.get", captured["method"])
	}
	// Without expandDescription, Zabbix returns unresolved macros such as
	// {HOST.NAME}, which a model will repeat verbatim to a reader.
	params, _ := captured["params"].(map[string]any)
	if params["expandDescription"] != true {
		t.Error("expandDescription must be requested so trigger macros resolve")
	}
	if evidence.ItemCount != 2 {
		t.Fatalf("ItemCount = %d, want 2", evidence.ItemCount)
	}
	if evidence.Items[0].Severity != "high" {
		t.Errorf("severity = %q, want high", evidence.Items[0].Severity)
	}
	if evidence.Items[0].State != "problem" {
		t.Errorf("state = %q, want problem", evidence.Items[0].State)
	}
	if evidence.Items[0].Host != "node01" {
		t.Errorf("host = %q, want node01", evidence.Items[0].Host)
	}
	if evidence.Source != string(broker.SourceZabbixAPI) {
		t.Errorf("source = %q", evidence.Source)
	}
	if strings.Contains(evidence.Endpoint, "test-token") {
		t.Error("endpoint provenance must not carry credential material")
	}
}

func TestZabbixConnectorRejectsUnplannedAction(t *testing.T) {
	connector := newTestZabbix(t, "https://zabbix.example.edu/api_jsonrpc.php")
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "host.delete",
	})
	if err == nil {
		t.Fatal("expected an unsupported action to be rejected")
	}
	var connErr *ConnectorError
	if !asConnectorError(err, &connErr) || connErr.Code != "unsupported_action" {
		t.Fatalf("error = %v, want unsupported_action", err)
	}
}

func TestZabbixConnectorSurfacesAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params.","data":"Not authorised."}}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
	})
	if err == nil {
		t.Fatal("expected a JSON-RPC error to fail the step")
	}
	if !strings.Contains(err.Error(), "Not authorised") {
		t.Errorf("error = %v, want the API message preserved", err)
	}
}

func TestZabbixConnectorBoundsResponseSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[`)
		for i := 0; i < 5000; i++ {
			io.WriteString(w, `{"triggerid":"1","description":"padding padding padding padding","priority":"1","value":"1","hosts":[{"host":"h"}]},`)
		}
		io.WriteString(w, `{"triggerid":"2","description":"end","priority":"1","value":"1","hosts":[{"host":"h"}]}]}`)
	}))
	defer server.Close()

	connector, err := NewZabbixConnector(ZabbixConfig{
		Endpoint:         server.URL,
		Token:            "test-token",
		MaxResponseBytes: 4096,
	})
	if err != nil {
		t.Fatalf("NewZabbixConnector() error = %v", err)
	}
	if _, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
	}); err == nil {
		t.Fatal("expected an oversized response to be rejected")
	}
}

func TestZabbixConnectorRequiresConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config ZabbixConfig
	}{
		{"missing endpoint", ZabbixConfig{Token: "t"}},
		{"missing token", ZabbixConfig{Endpoint: "https://zabbix.example.edu/api_jsonrpc.php"}},
		{"unsupported scheme", ZabbixConfig{Endpoint: "ftp://zabbix.example.edu", Token: "t"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewZabbixConnector(test.config); err == nil {
				t.Fatal("expected configuration to be rejected")
			}
		})
	}
}

func newTestZabbix(t *testing.T, endpoint string) *ZabbixConnector {
	t.Helper()
	connector, err := NewZabbixConnector(ZabbixConfig{Endpoint: endpoint, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewZabbixConnector() error = %v", err)
	}
	return connector
}

func asConnectorError(err error, target **ConnectorError) bool {
	for err != nil {
		if typed, ok := err.(*ConnectorError); ok {
			*target = typed
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

func TestZabbixSummaryCountsBySeverityAndRendersTimestamps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), `"priority"]`) && !strings.Contains(string(raw), "selectHosts") {
			// 97 matching rows: one disaster, 96 high. The page shows three.
			census := `{"jsonrpc":"2.0","id":1,"result":[{"priority":"5"}`
			for i := 0; i < 96; i++ {
				census += `,{"priority":"4"}`
			}
			io.WriteString(w, census+`]}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
			{"triggerid":"1","description":"a","priority":"5","value":"1","lastchange":"1786576250","hosts":[{"host":"h1"}]},
			{"triggerid":"2","description":"b","priority":"4","value":"1","hosts":[{"host":"h2"}]},
			{"triggerid":"3","description":"c","priority":"4","value":"1","hosts":[{"host":"h3"}]}
		]}`)
	}))
	defer server.Close()

	evidence, err := newTestZabbix(t, server.URL).Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if evidence.Summary["returned"] != 3 {
		t.Errorf("returned = %d, want 3", evidence.Summary["returned"])
	}
	if evidence.Summary["total_matching"] != 97 {
		t.Errorf("total_matching = %d, want 97", evidence.Summary["total_matching"])
	}
	if !evidence.Truncated {
		t.Error("a bounded page of a larger match set must be marked truncated")
	}
	// Severity counts describe all 97 matching rows, not the 3 returned. A
	// breakdown of the page answers a question nobody asked.
	if evidence.Summary["high"] != 96 {
		t.Errorf("high = %d, want 96 across the full match", evidence.Summary["high"])
	}
	if evidence.Summary["disaster"] != 1 {
		t.Errorf("disaster = %d, want 1", evidence.Summary["disaster"])
	}
	if got := evidence.Items[0].Fields["last_change"]; !strings.HasPrefix(got, "2026-") {
		t.Errorf("last_change = %q, want an RFC 3339 timestamp", got)
	}
}

func TestZabbixDistinguishesUnknownHostFromHealthyHost(t *testing.T) {
	// Zero problems for a host Zabbix has never heard of must not be reported
	// the same way as zero problems for a monitored host.
	for _, test := range []struct {
		name      string
		hostFound bool
		want      int
	}{
		{"host is monitored and clean", true, 1},
		{"host is not monitored at all", false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				body := string(raw)
				switch {
				case strings.Contains(body, "host.get"):
					if test.hostFound {
						io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[{"hostid":"1"}]}`)
					} else {
						io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
					}
				case strings.Contains(body, `"priority"]`):
					io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
				default:
					io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
				}
			}))
			defer server.Close()

			evidence, err := newTestZabbix(t, server.URL).Execute(context.Background(), broker.RouteStep{
				Source: broker.SourceZabbixAPI,
				Action: "trigger.get",
				Host:   "log001-004",
			})
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if got, ok := evidence.Summary["host_known"]; !ok || got != test.want {
				t.Errorf("host_known = %v (present=%v), want %d", got, ok, test.want)
			}
		})
	}
}

// classifyZabbixCall names which of the three round trips a request body is.
//
// The connector makes up to three calls per step -- the page, the severity
// census, and the per-host census -- and they are distinguished by what they
// ask for rather than by call order, so a test does not silently pass when the
// order changes.
func classifyZabbixCall(t *testing.T, body []byte) (string, map[string]any) {
	t.Helper()
	var request struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	params := request.Params
	_, hasHosts := params["selectHosts"]
	output, _ := params["output"].([]any)
	first := ""
	if len(output) > 0 {
		first, _ = output[0].(string)
	}
	switch {
	case !hasHosts && (first == "severity" || first == "priority"):
		return "severity-census", params
	case hasHosts && (first == "eventid" || first == "triggerid") && len(output) == 1:
		return "host-census", params
	default:
		return "page", params
	}
}

func TestZabbixAppliesSelectorsToTheAPICall(t *testing.T) {
	// Each selector has a different spelling per method, which is the detail a
	// caller must not have to carry. A selector that never reaches the API
	// returns a wide result that reads as a narrow one.
	var pageParams map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		kind, params := classifyZabbixCall(t, body)
		if kind == "page" {
			pageParams = params
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source:   broker.SourceZabbixAPI,
		Action:   "event.get",
		Limit:    25,
		Since:    "2026-08-29T05:00:00Z",
		Match:    "Zabbix agent is not available",
		Severity: "average",
		State:    "problem",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	search, ok := pageParams["search"].(map[string]any)
	if !ok || search["name"] != "Zabbix agent is not available" {
		t.Errorf("event.get search = %v, want a substring filter on name", pageParams["search"])
	}
	severities, ok := pageParams["severities"].([]any)
	if !ok || len(severities) != 3 {
		t.Errorf("severities = %v, want average and worse (3, 4, 5)", pageParams["severities"])
	}
	value, ok := pageParams["value"].([]any)
	if !ok || len(value) != 1 || value[0].(float64) != 1 {
		t.Errorf("value = %v, want [1] for problems opening", pageParams["value"])
	}

	// The evidence echoes what was applied, for the same reason it echoes
	// since: a filter absent here was not applied, whatever was requested.
	if evidence.Match != "Zabbix agent is not available" || evidence.Severity != "average" || evidence.State != "problem" {
		t.Errorf("evidence does not echo the selectors: %q %q %q", evidence.Match, evidence.Severity, evidence.State)
	}
}

func TestZabbixTriggerSelectorsUseTheTriggerSpelling(t *testing.T) {
	var pageParams map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		kind, params := classifyZabbixCall(t, body)
		if kind == "page" {
			pageParams = params
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	if _, err := connector.Execute(context.Background(), broker.RouteStep{
		Source:   broker.SourceZabbixAPI,
		Action:   "trigger.get",
		Limit:    25,
		Match:    "*disk*",
		Severity: "high",
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	search, ok := pageParams["search"].(map[string]any)
	if !ok {
		t.Fatalf("trigger.get sent no search: %v", pageParams)
	}
	// Zabbix wraps the value in wildcards itself. Passing the caller's stars
	// through would search for literal asterisks and confidently return nothing.
	if search["description"] != "disk" {
		t.Errorf("trigger.get search = %v, want description filtered on the bare substring", search)
	}
	if pageParams["min_severity"].(float64) != 4 {
		t.Errorf("min_severity = %v, want 4 for high", pageParams["min_severity"])
	}
}

func TestZabbixCountsMatchingRowsByHostWhenTruncated(t *testing.T) {
	// The answer to 1,200 matching events is not a longer page. It is which
	// hosts they landed on, counted over every matching row rather than over
	// the 25 that fit.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		kind, _ := classifyZabbixCall(t, body)
		switch kind {
		case "severity-census":
			rows := make([]string, 0, 6)
			for i := 0; i < 6; i++ {
				rows = append(rows, `{"severity":"3"}`)
			}
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[`+strings.Join(rows, ",")+`]}`)
		case "host-census":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
				{"hosts":[{"host":"dss01"}]},{"hosts":[{"host":"dss01"}]},{"hosts":[{"host":"dss01"}]},
				{"hosts":[{"host":"dss02"}]},{"hosts":[{"host":"dss02"}]},
				{"hosts":[{"host":"mgt01"}]}
			]}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
				{"eventid":"1","clock":"1756300000","name":"Zabbix agent is not available","severity":"3","value":"1","hosts":[{"host":"dss01"}]}
			]}`)
		}
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "event.get",
		Limit:  1,
		Since:  "2026-08-29T05:00:00Z",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !evidence.Truncated {
		t.Fatal("6 matching rows and 1 returned is truncated")
	}
	hosts := evidence.Breakdown["events_by_host"]
	if len(hosts) != 3 {
		t.Fatalf("events_by_host = %v, want three hosts", hosts)
	}
	if hosts["dss01"] != 3 || hosts["dss02"] != 2 || hosts["mgt01"] != 1 {
		t.Errorf("events_by_host = %v, want counts over all matching rows, not the page", hosts)
	}
	if evidence.Summary["hosts_affected"] != 3 {
		t.Errorf("hosts_affected = %d, want 3", evidence.Summary["hosts_affected"])
	}
}

func TestZabbixSkipsTheHostCensusWhenThePageIsComplete(t *testing.T) {
	// The extra round trip buys nothing when every matching row is already in
	// the evidence: the hosts can be read off the items.
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		kind, _ := classifyZabbixCall(t, body)
		calls[kind]++
		if kind == "severity-census" {
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[{"severity":"3"}]}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
			{"eventid":"1","clock":"1756300000","name":"Agent down","severity":"3","value":"1","hosts":[{"host":"dss01"}]}
		]}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "event.get",
		Limit:  25,
		Since:  "2026-08-29T05:00:00Z",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if evidence.Truncated {
		t.Fatal("one matching row and one returned is not truncated")
	}
	if calls["host-census"] != 0 {
		t.Errorf("host census ran %d times for a complete page", calls["host-census"])
	}
	if evidence.Breakdown != nil {
		t.Errorf("Breakdown = %v, want none when the page holds every matching row", evidence.Breakdown)
	}
}

func TestZabbixWarnsWhenTheHostBreakdownIsPartial(t *testing.T) {
	// A breakdown naming 25 of 60 hosts, presented as the whole picture, is a
	// more convincing wrong answer than no breakdown at all.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		kind, _ := classifyZabbixCall(t, body)
		switch kind {
		case "severity-census":
			rows := make([]string, 0, 60)
			for i := 0; i < 60; i++ {
				rows = append(rows, `{"severity":"2"}`)
			}
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[`+strings.Join(rows, ",")+`]}`)
		case "host-census":
			rows := make([]string, 0, 60)
			for i := 0; i < 60; i++ {
				rows = append(rows, fmt.Sprintf(`{"hosts":[{"host":"node%02d"}]}`, i))
			}
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[`+strings.Join(rows, ",")+`]}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
				{"eventid":"1","clock":"1756300000","name":"Agent down","severity":"2","value":"1","hosts":[{"host":"node00"}]}
			]}`)
		}
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "event.get",
		Limit:  1,
		Since:  "2026-08-29T05:00:00Z",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := len(evidence.Breakdown["events_by_host"]); got != maxBreakdownHosts {
		t.Errorf("events_by_host holds %d hosts, want it capped at %d", got, maxBreakdownHosts)
	}
	if evidence.Summary["hosts_affected"] != 60 {
		t.Errorf("hosts_affected = %d, want the full count even though the names are capped", evidence.Summary["hosts_affected"])
	}
	if len(evidence.Warnings) == 0 {
		t.Fatal("a capped breakdown carried no warning, so it reads as the whole picture")
	}
	if !strings.Contains(evidence.Warnings[0], "60") {
		t.Errorf("warning does not say how many hosts were left unnamed: %q", evidence.Warnings[0])
	}
	// hosts_affected comes from the same capped fetch, and it is the number a
	// reader quotes. A warning that names only the per-host counts leaves it
	// looking exact.
	for _, w := range evidence.Warnings {
		if strings.Contains(w, "lower bound") && !strings.Contains(w, "hosts_affected") {
			t.Errorf("the cap warning does not say hosts_affected is a floor too: %q", w)
		}
	}
}

func TestZabbixCensusIsExactWhenTheRowFetchOverflows(t *testing.T) {
	// A row census reports len(result), which stops being a count the moment it
	// equals its own limit. Live Zabbix had 21,296 events since 05:00 against a
	// 20,000-row census: the total would have been reported as exactly 20,000,
	// which reads as a measurement and is a ceiling.
	countCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if request.Params["countOutput"] == true {
			countCalls++
			filter, _ := request.Params["filter"].(map[string]any)
			level := int(filter["severity"].(float64))
			// 21,296 split so that no single level reaches the row cap.
			perLevel := map[int]int{0: 1, 1: 2, 2: 20000, 3: 1000, 4: 290, 5: 3}
			// Zabbix returns countOutput as a string, not a number.
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":"%d"}`, perLevel[level])
			return
		}
		if _, hasHosts := request.Params["selectHosts"]; !hasHosts {
			// The row census, overflowing at its cap.
			rows := make([]string, 0, maxCensusRows)
			for i := 0; i < maxCensusRows; i++ {
				rows = append(rows, `{"severity":"2"}`)
			}
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[`+strings.Join(rows, ",")+`]}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
			{"eventid":"1","clock":"1756300000","name":"Load average is too high","severity":"2","value":"1","hosts":[{"host":"node01"}]}
		]}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "event.get",
		Limit:  1,
		Since:  "2026-08-30T09:00:00Z",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if evidence.TotalAvailable != 21296 {
		t.Errorf("total = %d, want the exact 21296 rather than the 20000-row ceiling", evidence.TotalAvailable)
	}
	if evidence.Summary["total_matching"] != 21296 {
		t.Errorf("total_matching = %d, want 21296", evidence.Summary["total_matching"])
	}
	if evidence.Summary["warning"] != 20000 || evidence.Summary["average"] != 1000 {
		t.Errorf("severity breakdown describes the page, not the population: %v", evidence.Summary)
	}
	if countCalls != 6 {
		t.Errorf("countOutput calls = %d, want one per severity so their sum is the exact total", countCalls)
	}
}

func TestZabbixCensusStaysCheapWhenItFits(t *testing.T) {
	// The exact census costs a round trip per severity, so it must not run on
	// the ordinary case where the row fetch already holds every matching row.
	countCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if request.Params["countOutput"] == true {
			countCalls++
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"0"}`)
			return
		}
		if _, hasHosts := request.Params["selectHosts"]; !hasHosts {
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[{"severity":"4"},{"severity":"2"}]}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
			{"eventid":"1","clock":"1756300000","name":"Agent down","severity":"4","value":"1","hosts":[{"host":"node01"}]},
			{"eventid":"2","clock":"1756300100","name":"Load high","severity":"2","value":"1","hosts":[{"host":"node02"}]}
		]}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "event.get",
		Limit:  25,
		Since:  "2026-08-30T09:00:00Z",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if countCalls != 0 {
		t.Errorf("countOutput ran %d times for a census that fit", countCalls)
	}
	if evidence.TotalAvailable != 2 {
		t.Errorf("total = %d, want 2", evidence.TotalAvailable)
	}
}

func TestZabbixCountsHostsEvenWhenNothingIsTruncated(t *testing.T) {
	// Several triggers can fire on one host, so rows and machines are different
	// numbers. Handed 3 complete rows over 2 hosts, a model reported the row
	// count above a shorter list of names and left the reader to reconcile them.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		kind, _ := classifyZabbixCall(t, body)
		if kind == "severity-census" {
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[{"priority":"4"},{"priority":"4"},{"priority":"3"}]}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
			{"triggerid":"1","description":"Zabbix agent is not available","priority":"4","value":"1","lastchange":"1756300000","hosts":[{"host":"cpu052"}]},
			{"triggerid":"2","description":"Linux: Zabbix agent is not available","priority":"4","value":"1","lastchange":"1756300001","hosts":[{"host":"cpu052"}]},
			{"triggerid":"3","description":"Zabbix agent is not available","priority":"3","value":"1","lastchange":"1756300002","hosts":[{"host":"gpu002"}]}
		]}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
		Limit:  25,
		Match:  "Zabbix agent is not available",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if evidence.Truncated {
		t.Fatal("three rows of three is not truncated")
	}
	if evidence.Summary["hosts_affected"] != 2 {
		t.Errorf("hosts_affected = %d, want 2 distinct hosts behind 3 triggers", evidence.Summary["hosts_affected"])
	}
	if evidence.Summary["total_matching"] != 3 {
		t.Errorf("total_matching = %d, want 3", evidence.Summary["total_matching"])
	}
}

func TestZabbixSaysWhatATimeBoundExcluded(t *testing.T) {
	// A bound on trigger.get filters lastchange, so it selects problems that
	// CHANGED state in the window. One that began earlier and is still firing
	// falls out, and the zero reads as health: asked whether any host had lost
	// its Zabbix agent since 05:00, the answer was "no host has" while 19 were
	// down.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if request.Params["countOutput"] == true {
			if _, bounded := request.Params["lastChangeSince"]; bounded {
				t.Error("the comparison call still carries the time bound it exists to remove")
			}
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"19"}`)
			return
		}
		// Both the page and the severity census come back empty under the bound.
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
		Limit:  25,
		Since:  "2026-08-30T04:00:00Z",
		Match:  "Zabbix agent is not available",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if evidence.Summary["total_matching"] != 0 {
		t.Fatalf("the bounded query should match nothing here, got %d", evidence.Summary["total_matching"])
	}
	if evidence.Summary["total_ignoring_time_bound"] != 19 {
		t.Errorf("total_ignoring_time_bound = %d, want the 19 that are firing regardless of the bound",
			evidence.Summary["total_ignoring_time_bound"])
	}
	if len(evidence.Warnings) == 0 {
		t.Fatal("an empty bounded result carried no warning, so zero reads as an all-clear")
	}
	joined := strings.Join(evidence.Warnings, " ")
	if !strings.Contains(joined, "19") || !strings.Contains(joined, "still firing") {
		t.Errorf("warning does not say what the bound hid: %q", joined)
	}
}

func TestZabbixSkipsTheComparisonWithoutATimeBound(t *testing.T) {
	// The comparison costs a round trip and means nothing when no bound was
	// applied: the count it would return is the count already in hand.
	countCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if request.Params["countOutput"] == true {
			countCalls++
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"0"}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
		Limit:  25,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if countCalls != 0 {
		t.Errorf("countOutput ran %d times with no time bound to compare against", countCalls)
	}
	if _, present := evidence.Summary["total_ignoring_time_bound"]; present {
		t.Error("total_ignoring_time_bound appeared without a time bound, where it means nothing")
	}
}
