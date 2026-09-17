package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
)

func TestRTConnectorSearchesOpenTicketsAndBreaksDownByQueue(t *testing.T) {
	var capturedQueries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "token rt-test-token" {
			t.Errorf("Authorization = %q", got)
		}
		query := r.URL.Query().Get("query")
		capturedQueries = append(capturedQueries, query)

		if r.URL.Query().Get("per_page") == "1" {
			// A queue-census probe: report a small exact total for whichever
			// single queue this request named.
			switch {
			case strings.Contains(query, "Queue = 'Ops'"):
				w.Write([]byte(`{"total":2,"items":[]}`))
			case strings.Contains(query, "Queue = 'Helpdesk'"):
				w.Write([]byte(`{"total":0,"items":[]}`))
			default:
				w.Write([]byte(`{"total":0,"items":[]}`))
			}
			return
		}

		w.Write([]byte(`{"total":2,"items":[
			{"id":"101","Subject":"GPFS panic on node01","Status":"open","Queue":{"id":"Ops"},"Owner":{"id":"alice"},"Created":"2026-08-30T10:00:00Z","LastUpdated":"2026-08-30T11:00:00Z"},
			{"id":"102","Subject":"disk full","Status":"new","Queue":"Ops","Owner":"Nobody","Created":"2026-08-29T09:00:00Z","LastUpdated":"2026-08-29T09:30:00Z"}
		]}`))
	}))
	defer server.Close()

	connector := newTestRT(t, server.URL, []string{"Ops", "Helpdesk"})
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "tickets.search",
		Limit:  50,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if evidence.ItemCount != 2 {
		t.Fatalf("ItemCount = %d, want 2", evidence.ItemCount)
	}
	if evidence.TotalAvailable != 2 {
		t.Errorf("TotalAvailable = %d, want 2", evidence.TotalAvailable)
	}
	if evidence.Truncated {
		t.Error("a complete result should not be marked truncated")
	}
	if evidence.Items[0].Description != "GPFS panic on node01" {
		t.Errorf("Description = %q", evidence.Items[0].Description)
	}
	if evidence.Items[0].Fields["queue"] != "Ops" {
		t.Errorf("queue field = %q, want Ops (from a hyperlink object)", evidence.Items[0].Fields["queue"])
	}
	if evidence.Items[1].Fields["queue"] != "Ops" {
		t.Errorf("queue field = %q, want Ops (from a plain string)", evidence.Items[1].Fields["queue"])
	}
	if evidence.Items[0].State != "open" {
		t.Errorf("State = %q, want open", evidence.Items[0].State)
	}

	// Ticket content must never appear anywhere in evidence.
	encoded, _ := json.Marshal(evidence)
	if strings.Contains(string(encoded), "Content") {
		t.Error("evidence must not carry ticket content")
	}

	if evidence.Breakdown["tickets_by_queue"]["Ops"] != 2 {
		t.Errorf("tickets_by_queue[Ops] = %d, want 2", evidence.Breakdown["tickets_by_queue"]["Ops"])
	}
	if _, present := evidence.Breakdown["tickets_by_queue"]["Helpdesk"]; present {
		t.Error("a queue with zero matching tickets should be omitted, not present at zero")
	}

	// The search query is scoped to open statuses and every allowlisted queue.
	if !strings.Contains(capturedQueries[0], "Status = 'new'") || !strings.Contains(capturedQueries[0], "Queue = 'Ops'") || !strings.Contains(capturedQueries[0], "Queue = 'Helpdesk'") {
		t.Errorf("query = %q, want open statuses and both allowlisted queues", capturedQueries[0])
	}
}

func TestRTConnectorFiltersByHostForTicketsByHost(t *testing.T) {
	var capturedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("per_page") == "1" {
			w.Write([]byte(`{"total":0,"items":[]}`))
			return
		}
		capturedQuery = r.URL.Query().Get("query")
		w.Write([]byte(`{"total":1,"items":[
			{"id":"200","Subject":"node01 GPFS panic since Aug 12","Status":"open","Queue":"Ops","Created":"2026-08-12T00:00:00Z"}
		]}`))
	}))
	defer server.Close()

	connector := newTestRT(t, server.URL, []string{"Ops"})
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "tickets.search",
		Host:   "node01",
		Limit:  50,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(capturedQuery, "Subject LIKE 'node01'") {
		t.Errorf("query = %q, want a Subject filter on the host", capturedQuery)
	}
	if evidence.ItemCount != 1 {
		t.Fatalf("ItemCount = %d, want 1", evidence.ItemCount)
	}
}

func TestRTConnectorRejectsUnplannedAction(t *testing.T) {
	connector := newTestRT(t, "https://rt.example.edu", []string{"Ops"})
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "ticket.comment",
	})
	var connErr *ConnectorError
	if err == nil || !asConnectorError(err, &connErr) || connErr.Code != "unsupported_action" {
		t.Fatalf("error = %v, want unsupported_action", err)
	}
}

func TestRTConnectorRejectsWrongSource(t *testing.T) {
	connector := newTestRT(t, "https://rt.example.edu", []string{"Ops"})
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "tickets.search",
	})
	var connErr *ConnectorError
	if err == nil || !asConnectorError(err, &connErr) || connErr.Code != "wrong_source" {
		t.Fatalf("error = %v, want wrong_source", err)
	}
}

func TestRTConnectorSurfacesAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message":"Invalid query"}`))
	}))
	defer server.Close()

	connector := newTestRT(t, server.URL, []string{"Ops"})
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "tickets.search",
	})
	if err == nil || !strings.Contains(err.Error(), "Invalid query") {
		t.Fatalf("error = %v, want the API message preserved", err)
	}
}

func TestRTConnectorFailsClosedOnBadCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	connector := newTestRT(t, server.URL, []string{"Ops"})
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "tickets.search",
	})
	var connErr *ConnectorError
	if err == nil || !asConnectorError(err, &connErr) || connErr.Code != "authentication_failed" {
		t.Fatalf("error = %v, want authentication_failed", err)
	}
}

func TestRTConnectorRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("per_page") == "1" {
			w.Write([]byte(`{"total":0,"items":[]}`))
			return
		}
		w.Write([]byte(`{"total":1,"items":[{"id":"1","Subject":"x","Status":"open"}]}`))
	}))
	defer server.Close()

	connector, err := NewRTConnector(RTConfig{
		Endpoint:         server.URL,
		Token:            "rt-test-token",
		Queues:           []string{"Ops"},
		MaxResponseBytes: 8,
	})
	if err != nil {
		t.Fatalf("NewRTConnector() error = %v", err)
	}
	_, err = connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "tickets.search",
	})
	var connErr *ConnectorError
	if err == nil || !asConnectorError(err, &connErr) || connErr.Code != "response_too_large" {
		t.Fatalf("error = %v, want response_too_large", err)
	}
}

func TestRTConnectorRequiresConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config RTConfig
	}{
		{"missing endpoint", RTConfig{Token: "t", Queues: []string{"Ops"}}},
		{"missing token", RTConfig{Endpoint: "https://rt.example.edu", Queues: []string{"Ops"}}},
		{"empty queue allowlist", RTConfig{Endpoint: "https://rt.example.edu", Token: "t"}},
		{"queue allowlist of only blanks", RTConfig{Endpoint: "https://rt.example.edu", Token: "t", Queues: []string{"  ", ""}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRTConnector(test.config); err == nil {
				t.Fatal("expected configuration to be rejected")
			}
		})
	}
}

func TestRTConnectorSkipsQueueCensusWhenAllowlistIsLarge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"items":[]}`))
	}))
	defer server.Close()

	queues := make([]string, maxRTQueueCensus+1)
	for i := range queues {
		queues[i] = "Q" + string(rune('A'+i))
	}
	connector := newTestRT(t, server.URL, queues)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "tickets.search",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if evidence.Breakdown != nil {
		t.Error("breakdown must not be computed above the queue-census cap")
	}
	if len(evidence.Warnings) == 0 || !strings.Contains(evidence.Warnings[0], "was not computed") {
		t.Fatalf("warnings = %v, want a warning that the breakdown was skipped", evidence.Warnings)
	}
}

func TestTicketSearchQueryEscapesQuotes(t *testing.T) {
	query := ticketSearchQuery("o'brien", "", "", "", []string{"Ops"})
	if !strings.Contains(query, `Subject LIKE 'o\'brien'`) {
		t.Errorf("query = %q, want an escaped quote", query)
	}
}

func TestTicketSearchQueryFiltersByOwner(t *testing.T) {
	query := ticketSearchQuery("", "jcreech@gwu.edu", "", "", []string{"Ops"})
	if !strings.Contains(query, "Owner = 'jcreech@gwu.edu'") {
		t.Errorf("query = %q, want an Owner filter", query)
	}
}

func TestTicketSearchQueryAddsCreatedBounds(t *testing.T) {
	query := ticketSearchQuery("", "", "2026-01-01 00:00:00", "2026-07-04 00:00:00", []string{"Ops"})
	if !strings.Contains(query, "Created > '2026-01-01 00:00:00'") {
		t.Errorf("query = %q, want a Created lower bound", query)
	}
	if !strings.Contains(query, "Created < '2026-07-04 00:00:00'") {
		t.Errorf("query = %q, want a Created upper bound", query)
	}
}

func TestRTConnectorFiltersByCreatedDate(t *testing.T) {
	var capturedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("per_page") == "1" {
			w.Write([]byte(`{"total":35,"items":[]}`))
			return
		}
		capturedQuery = r.URL.Query().Get("query")
		w.Write([]byte(`{"total":35,"items":[
			{"id":"1","Subject":"old ticket","Status":"open","Queue":"Ops","Created":"2026-01-15T00:00:00Z"}
		]}`))
	}))
	defer server.Close()

	connector := newTestRT(t, server.URL, []string{"Ops"})
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "tickets.search",
		Until:  "2026-07-04T00:00:00Z",
		Limit:  50,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	// 2026-07-04T00:00:00Z is 20:00 on the 3rd in New York, and that is what RT
	// must be sent: it parses a bare literal in the server's zone while
	// returning Created in UTC. A ticket created at 2026-09-03T07:49:10Z
	// matches Created > '2026-09-03 00:00:00' and not '2026-09-03 04:00:00',
	// which is only true if the literal is read as 03:49 local.
	if !strings.Contains(capturedQuery, "Created < '2026-07-03 20:00:00'") {
		t.Errorf("query = %q, want the until instant rendered in RT's zone", capturedQuery)
	}
	// RT's own total for the bounded query, not a count derived from a page.
	if evidence.TotalAvailable != 35 {
		t.Errorf("TotalAvailable = %d, want RT's exact total for the bounded query", evidence.TotalAvailable)
	}
	if evidence.Until != "2026-07-04T00:00:00Z" {
		t.Errorf("evidence.Until = %q, want the applied bound echoed back", evidence.Until)
	}
}

func TestRTConnectorBreaksDownByOwner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if r.URL.Query().Get("per_page") == "1" {
			switch {
			case strings.Contains(query, "Owner = 'jcreech@gwu.edu'"):
				w.Write([]byte(`{"total":16,"items":[]}`))
			case strings.Contains(query, "Owner = 'Nobody'"):
				w.Write([]byte(`{"total":3,"items":[]}`))
			default:
				w.Write([]byte(`{"total":0,"items":[]}`))
			}
			return
		}
		w.Write([]byte(`{"total":304,"items":[
			{"id":"1","Subject":"a","Status":"open","Queue":"Ops","Owner":"jcreech@gwu.edu"},
			{"id":"2","Subject":"b","Status":"open","Queue":"Ops","Owner":"Nobody"},
			{"id":"3","Subject":"c","Status":"open","Queue":"Ops","Owner":"jcreech@gwu.edu"}
		]}`))
	}))
	defer server.Close()

	connector := newTestRT(t, server.URL, []string{"Ops"})
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "tickets.search",
		Limit:  3,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	// Exact per-owner counts from RT, not a tally of the 3 returned rows.
	if evidence.Breakdown["tickets_by_owner"]["jcreech@gwu.edu"] != 16 {
		t.Errorf("tickets_by_owner[jcreech@gwu.edu] = %d, want 16", evidence.Breakdown["tickets_by_owner"]["jcreech@gwu.edu"])
	}
	if evidence.Breakdown["tickets_by_owner"]["Nobody"] != 3 {
		t.Errorf("tickets_by_owner[Nobody] = %d, want 3", evidence.Breakdown["tickets_by_owner"]["Nobody"])
	}

	if !evidence.Truncated {
		t.Fatal("304 matching against 3 returned should be truncated")
	}
	found := false
	for _, warning := range evidence.Warnings {
		if strings.Contains(warning, "accounts for 19 of 304") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %v, want a warning naming how much of the total is unaccounted for", evidence.Warnings)
	}
}

// The completeness proof: when discovered owners' exact counts already sum
// to the query's total, no owner outside that set can exist -- Owner is
// single-valued per ticket -- so the breakdown is exact even though the page
// itself was truncated, and no warning should claim otherwise.
func TestRTConnectorOwnerBreakdownIsCompleteWhenCountsSumToTotal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if r.URL.Query().Get("per_page") == "1" {
			switch {
			case strings.Contains(query, "Owner = 'alice'"):
				w.Write([]byte(`{"total":3,"items":[]}`))
			case strings.Contains(query, "Owner = 'bob'"):
				w.Write([]byte(`{"total":2,"items":[]}`))
			default:
				w.Write([]byte(`{"total":0,"items":[]}`))
			}
			return
		}
		// total:5 with only 2 returned, so the page is truncated -- but alice
		// (3) and bob (2) between them already account for all 5.
		w.Write([]byte(`{"total":5,"items":[
			{"id":"1","Subject":"a","Status":"open","Queue":"Ops","Owner":"alice"},
			{"id":"2","Subject":"b","Status":"open","Queue":"Ops","Owner":"bob"}
		]}`))
	}))
	defer server.Close()

	connector := newTestRT(t, server.URL, []string{"Ops"})
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "tickets.search",
		Limit:  2,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !evidence.Truncated {
		t.Fatal("5 matching against 2 returned should be truncated")
	}
	for _, warning := range evidence.Warnings {
		if strings.Contains(warning, "tickets_by_owner") {
			t.Errorf("unexpected owner-breakdown warning on a provably complete breakdown: %q", warning)
		}
	}
}

func TestOwnersOnPageCapsAndFlags(t *testing.T) {
	items := make([]EvidenceItem, 0, maxRTOwnerCensus+5)
	for i := 0; i < maxRTOwnerCensus+5; i++ {
		items = append(items, EvidenceItem{Fields: map[string]string{"owner": fmt.Sprintf("owner%d@gwu.edu", i)}})
	}
	owners, capped := ownersOnPage(items)
	if len(owners) != maxRTOwnerCensus {
		t.Fatalf("len(owners) = %d, want %d", len(owners), maxRTOwnerCensus)
	}
	if !capped {
		t.Error("expected capped to be true when more distinct owners exist than the cap")
	}

	fewer, fewerCapped := ownersOnPage(items[:3])
	if len(fewer) != 3 || fewerCapped {
		t.Errorf("ownersOnPage(3 items) = %v, capped=%v", fewer, fewerCapped)
	}
}

func TestRTConnectorRejectsMalformedTimeBound(t *testing.T) {
	connector := newTestRT(t, "https://rt.example.edu", []string{"Ops"})
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker,
		Action: "tickets.search",
		Until:  "not-a-time",
	})
	var connErr *ConnectorError
	if err == nil || !asConnectorError(err, &connErr) || connErr.Code != "invalid_time_bound" {
		t.Fatalf("error = %v, want invalid_time_bound", err)
	}
}

func newTestRT(t *testing.T, endpoint string, queues []string) *RTConnector {
	t.Helper()
	connector, err := NewRTConnector(RTConfig{
		Endpoint: endpoint,
		Token:    "rt-test-token",
		Queues:   queues,
		// Pinned, or these assertions pass on an Eastern laptop and fail on a
		// UTC runner. The zone is the whole point of what is being asserted.
		Location: testRTZone(t),
	})
	if err != nil {
		t.Fatalf("NewRTConnector() error = %v", err)
	}
	return connector
}

// TestRTQueueReferenceResolvesToAName pins the defect the live suite found on
// 2026-09-03: per-item evidence named "queue 3" and "queue 6" where every
// other part of this connector, and every operator, means a queue name.
//
// RT returns Queue as a bare reference whose only readable member is a numeric
// id. The fix is to ask RT to expand it, so both halves are asserted here: the
// request carries the expansion, and an expanded reference decodes to its name.
func TestRTQueueReferenceResolvesToAName(t *testing.T) {
	// The queue and owner censuses fire after the search, so capture the first
	// request rather than the last: the expansion belongs on the search, which
	// is the only call whose items are read.
	var gotQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotQuery == nil {
			gotQuery = r.URL.Query()
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"total":1,"items":[{
			"id":"2264","Subject":"disk full on dss01","Status":"open",
			"Queue":{"id":"10","type":"queue","Name":"alerts"},
			"Owner":{"id":"someone@example.edu","type":"user"},
			"Created":"2026-08-30T10:00:00Z","LastUpdated":"2026-08-30T11:00:00Z"}]}`)
	}))
	defer server.Close()

	rt, err := NewRTConnector(RTConfig{Endpoint: server.URL, Token: "t", Queues: []string{"alerts"}})
	if err != nil {
		t.Fatalf("build connector: %v", err)
	}
	evidence, err := rt.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceRequestTracker, Action: "tickets.search", Limit: 10,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	if got := gotQuery.Get(rtQueueNameField); got != "Name" {
		t.Errorf("search did not ask RT to expand the queue reference: %s=%q, want %q",
			rtQueueNameField, got, "Name")
	}
	if len(evidence.Items) == 0 {
		t.Fatal("no items returned")
	}
	if queue := evidence.Items[0].Fields["queue"]; queue != "alerts" {
		t.Errorf("queue = %q, want %q; a numeric id here means the reference was not resolved", queue, "alerts")
	}
}

// TestRTUnexpandedReferenceKeepsItsID asserts the fallback still works. A user
// reference carries no Name and its id is already a login name, so Owner reads
// correctly without expansion and must not be broken by preferring Name.
func TestRTUnexpandedReferenceKeepsItsID(t *testing.T) {
	var ref rtRef
	if err := ref.UnmarshalJSON([]byte(`{"id":"someone@example.edu","type":"user"}`)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(ref) != "someone@example.edu" {
		t.Errorf("owner = %q, want the login name from id", string(ref))
	}
}

// testRTZone pins the zone these tests assume RT parses literals in.
func testRTZone(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("no tzdata: %v", err)
	}
	return loc
}

// TestRTDateBoundRendersInRTsZone pins the bug that made "how many tickets
// were submitted today" answer 21 against a true 22.
//
// The broker resolves a day in the operator's zone and hands over a UTC
// instant. RT parses a bare date literal in the server's zone, so rendering
// that instant as UTC moves the bound by the offset -- four hours late in
// summer, which dropped a ticket filed at 03:49.
//
// Two bugs used to cancel: the broker handed over a local calendar date
// stamped midnight UTC, which rendered here as local midnight and was right by
// accident. Fixing the broker in 8e52f8c exposed this one.
func TestRTDateBoundRendersInRTsZone(t *testing.T) {
	zone := testRTZone(t)
	for _, test := range []struct{ instant, want string }{
		// Local midnight on 3 September, as the broker now resolves "today".
		{"2026-09-03T04:00:00Z", "2026-09-03 00:00:00"},
		// Winter, when the offset is five hours rather than four.
		{"2026-01-15T05:00:00Z", "2026-01-15 00:00:00"},
		{"", ""},
	} {
		got, err := rtDateBound(test.instant, zone)
		if err != nil {
			t.Errorf("rtDateBound(%q) error = %v", test.instant, err)
			continue
		}
		if got != test.want {
			t.Errorf("rtDateBound(%q) = %q, want %q", test.instant, got, test.want)
		}
	}
}

// TestTicketOrderFollowsTheBound pins which end of a truncated page the reader
// gets. 73% of ticket searches truncate, so for most questions this decides
// which tickets are seen at all.
func TestTicketOrderFollowsTheBound(t *testing.T) {
	for _, tc := range []struct {
		name, since, until, want string
	}{
		{"older-than asks for the oldest", "", "2026-07-01T00:00:00Z", "ASC"},
		{"since asks for the newest", "2026-09-01T00:00:00Z", "", "DESC"},
		{"unbounded is a question about now", "", "", "DESC"},
		// A window names both ends, and the newer one is the live edge; a
		// reader asking about a window is not asking to start at its far end.
		{"a window keeps the recent end", "2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z", "DESC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ticketOrder(tc.since, tc.until); got != tc.want {
				t.Errorf("ticketOrder(%q, %q) = %q, want %q", tc.since, tc.until, got, tc.want)
			}
		})
	}
}

// TestSearchSendsRTsOwnOrderingSyntax guards the mistake itself. RT does not
// reject orderby=-Created; it ignores it and returns its default order, so the
// bug was invisible in every response.
func TestSearchSendsRTsOwnOrderingSyntax(t *testing.T) {
	var got url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"total":0,"items":[]}`)
	}))
	defer server.Close()

	connector, err := NewRTConnector(RTConfig{Endpoint: server.URL, Token: "t", Queues: []string{"q"}})
	if err != nil {
		t.Fatalf("NewRTConnector() error = %v", err)
	}
	if _, _, err := connector.search(context.Background(), "Status = 'open'", 10, "ASC"); err != nil {
		t.Fatalf("search: %v", err)
	}

	if got.Get("orderby") != "Created" {
		t.Errorf("orderby = %q, want the bare field name; RT silently ignores a signed one", got.Get("orderby"))
	}
	if got.Get("order") != "ASC" {
		t.Errorf("order = %q, want ASC as a separate parameter", got.Get("order"))
	}
}
