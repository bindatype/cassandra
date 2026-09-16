//go:build rtlive

// Live Request Tracker invariants. Excluded from the default build by the
// rtlive tag, deliberately: `go test ./...` must stay credential-free and must
// not reach the network, or it starts failing when a service is down and
// people learn to ignore a red suite.
//
//	make test-rt-live
//
// These assert the machinery, with no model involved. They cannot tell you
// whether an answer improved -- that question is about the model, which is the
// one nondeterministic part -- but they catch what the model-facing evaluation
// structurally cannot see: a bound that never reaches RT, a queue allowlist
// not applied, a census that silently undercounts, ticket content leaking into
// evidence.
package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
)

const (
	rtLiveEndpointEnv = "SROIAAA_RT_ENDPOINT"
	rtLiveTokenEnv    = "RT_API_TOKEN"
	rtLiveQueuesEnv   = "SROIAAA_RT_QUEUES"

	// rtLiveAgeDays is the bound these tests reason about. Ticket age is
	// stable in a way "open right now" is not: a ticket 61 days old stays 61
	// days old for the duration of a run.
	rtLiveAgeDays = 60
)

// rtLiveConnector builds a connector from the environment, or fails with the
// name of whatever is missing. A skip here would be wrong: this file only runs
// when someone asked for it by tag, and silently passing on no credentials is
// how a suite comes to prove nothing.
func rtLiveConnector(t *testing.T) (*RTConnector, []string) {
	t.Helper()
	endpoint, token := os.Getenv(rtLiveEndpointEnv), os.Getenv(rtLiveTokenEnv)
	queues := splitLive(os.Getenv(rtLiveQueuesEnv))
	for name, value := range map[string]string{
		rtLiveEndpointEnv: endpoint,
		rtLiveTokenEnv:    token,
		rtLiveQueuesEnv:   os.Getenv(rtLiveQueuesEnv),
	} {
		if strings.TrimSpace(value) == "" {
			t.Fatalf("%s is not set (and must be exported); these tests reach live RT by design", name)
		}
	}
	rt, err := NewRTConnector(RTConfig{Endpoint: endpoint, Token: token, Queues: queues})
	if err != nil {
		t.Fatalf("build RT connector: %v", err)
	}
	return rt, queues
}

func splitLive(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func rtLiveStep(until string) broker.RouteStep {
	return broker.RouteStep{Source: broker.SourceRequestTracker, Action: "tickets.search", Limit: 100, Until: until}
}

// rtLiveBound is the same relative window the broker would resolve, resolved
// here so the test and the connector are talking about one instant.
func rtLiveBound() (string, time.Time) {
	moment := time.Now().UTC().Add(-rtLiveAgeDays * 24 * time.Hour)
	return moment.Format(time.RFC3339), moment
}

// TestRTLiveBoundNarrows asserts a bound reaches RT rather than being accepted
// and dropped. An until that changes nothing is the silent-selector failure
// this project keeps finding: the caller believes it asked a narrower question
// than it asked, and reads a wide answer as a narrow one.
func TestRTLiveBoundNarrows(t *testing.T) {
	rt, queues := rtLiveConnector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	unbounded, err := rt.Execute(ctx, rtLiveStep(""))
	if err != nil {
		t.Fatalf("unbounded search: %v", err)
	}
	bound, _ := rtLiveBound()
	bounded, err := rt.Execute(ctx, rtLiveStep(bound))
	if err != nil {
		t.Fatalf("bounded search: %v", err)
	}

	open, older := unbounded.Summary["total_matching"], bounded.Summary["total_matching"]
	t.Logf("open now: %d; older than %d days: %d", open, rtLiveAgeDays, older)

	if open == 0 {
		t.Skip("RT reports no open tickets in the allowlisted queues; a bound cannot be shown to narrow " +
			"anything. Not a pass: check the queue names in " + rtLiveQueuesEnv)
	}

	if older > open {
		t.Errorf("bounded total %d exceeds unbounded total %d: the bound widened the result", older, open)
	}
	if bounded.Until == "" {
		t.Error("evidence does not record the bound it applied; an unrecorded filter cannot be audited")
	}

	// Equal counts used to be a warning here. That was the wrong resolution: it
	// is simultaneously the signature of an honest result (every open ticket
	// really is old) and of a bound that never reached RT, and a test that
	// cannot separate those resolves the ambiguity the reassuring way.
	//
	// Ask RT how many open tickets are YOUNGER than the bound. That number is
	// what the bound is supposed to exclude, so it decides the case: if any
	// exist, the bounded total must be strictly smaller, and RT's own two
	// halves must sum to its own whole.
	// Scoped to the same queues as the other two counts. Passing nil here
	// swept every queue in RT and made the sum check fail on the first live
	// run: 304 older + 311 newer against 458 open, because "newer" was
	// counting queues the allowlist excludes.
	younger, err := rtLiveDirectCount(ctx, queues, bound, "")
	if err != nil {
		t.Fatalf("direct RT count of tickets newer than the bound: %v", err)
	}
	t.Logf("RT directly: %d open tickets newer than the bound", younger)

	if younger == 0 {
		t.Skipf("RT has no open tickets newer than %d days, so an applied bound and an ignored one "+
			"produce identical results and this cannot tell them apart. Not a pass", rtLiveAgeDays)
	}
	if older == open {
		t.Errorf("the bound excluded nothing: %d open, %d older, yet RT reports %d open tickets newer "+
			"than the bound. The bound is not reaching RT", open, older, younger)
	}
	if open != older+younger {
		t.Errorf("RT's own halves do not sum: %d older + %d newer = %d, but %d open. The two queries "+
			"are not asking about the same population", older, younger, older+younger, open)
	}
}

// TestRTLiveBoundIsTheRightSide catches a direction inversion in the
// connector. "Older than 60 days" must return tickets created BEFORE that
// moment. Inverted, it answers the opposite question and the prose reads
// perfectly plausible either way.
func TestRTLiveBoundIsTheRightSide(t *testing.T) {
	rt, _ := rtLiveConnector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	bound, moment := rtLiveBound()
	evidence, err := rt.Execute(ctx, rtLiveStep(bound))
	if err != nil {
		t.Fatalf("bounded search: %v", err)
	}
	if len(evidence.Items) == 0 {
		t.Skipf("no tickets older than %d days; nothing to check the direction against", rtLiveAgeDays)
	}

	// RT renders dates in more than one format depending on configuration, and
	// nothing in the connector parses Created -- it is passed through as a
	// string, so the fixtures assert a format nobody has checked against a
	// live instance. Accept both, and count what was actually verified.
	//
	// The first version of this test logged an unparseable date and continued.
	// Had the format differed, every item would have been skipped and the test
	// would have PASSED having checked nothing -- reporting the bound
	// direction as sound on the evidence of zero tickets. A check that cannot
	// run must say so loudly; one that quietly verifies nothing is worse than
	// no check, because it also stops anyone looking.
	layouts := []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"}
	checked, unparseable := 0, []string{}
	for _, item := range evidence.Items {
		raw := item.Fields["created"]
		var created time.Time
		var err error
		for _, layout := range layouts {
			if created, err = time.Parse(layout, raw); err == nil {
				break
			}
		}
		if err != nil {
			unparseable = append(unparseable, fmt.Sprintf("%s=%q", item.ID, raw))
			continue
		}
		checked++
		if created.After(moment) {
			t.Errorf("ticket %s was created %s, after the %s bound: the filter is inverted",
				item.ID, created.Format(time.RFC3339), moment.Format(time.RFC3339))
		}
	}

	if checked == 0 {
		t.Fatalf("verified the bound direction against 0 of %d tickets: no created date matched any "+
			"known layout (%s). Add RT's actual format to layouts -- until then this test proves nothing",
			len(evidence.Items), strings.Join(unparseable[:min(3, len(unparseable))], ", "))
	}
	if len(unparseable) > 0 {
		t.Errorf("verified %d of %d tickets; %d created dates were unreadable (%s)",
			checked, len(evidence.Items), len(unparseable),
			strings.Join(unparseable[:min(3, len(unparseable))], ", "))
	}
	t.Logf("bound direction verified against %d tickets", checked)
}

// TestRTLiveCensusAccountsForEveryTicket asserts the owner breakdown is a
// census over every matching ticket rather than a tally of the returned page.
// A breakdown that silently covers less than the total is the failure the
// answer on 2026-09-02 actually made -- 100 rows of 428 reported as a property
// of RT -- and here it must be either complete or warned about.
func TestRTLiveCensusAccountsForEveryTicket(t *testing.T) {
	rt, _ := rtLiveConnector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	bound, _ := rtLiveBound()
	evidence, err := rt.Execute(ctx, rtLiveStep(bound))
	if err != nil {
		t.Fatalf("bounded search: %v", err)
	}
	total := evidence.Summary["total_matching"]
	if total == 0 {
		t.Skipf("no tickets older than %d days", rtLiveAgeDays)
	}

	for _, name := range []string{"tickets_by_owner", "tickets_by_queue"} {
		breakdown, ok := evidence.Breakdown[name]
		if !ok {
			if !hasWarningAbout(evidence.Warnings, name) {
				t.Errorf("%s is absent with no warning saying why; a count that was never computed is not zero", name)
			}
			continue
		}
		sum := 0
		for _, count := range breakdown {
			sum += count
		}
		if sum == total {
			continue
		}
		if !hasWarningAbout(evidence.Warnings, name) {
			t.Errorf("%s sums to %d of %d matching tickets and says nothing about the gap", name, sum, total)
		}
		if sum > total {
			t.Errorf("%s sums to %d, more than the %d matching tickets: tickets are being counted twice", name, sum, total)
		}
	}
}

func hasWarningAbout(warnings []string, name string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, name) {
			return true
		}
	}
	return false
}

// TestRTLiveHonoursTheQueueAllowlist asserts no ticket arrives from a queue
// nobody allowlisted. The allowlist is the whole reason the connector refuses
// to construct without one.
func TestRTLiveHonoursTheQueueAllowlist(t *testing.T) {
	rt, queues := rtLiveConnector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	evidence, err := rt.Execute(ctx, rtLiveStep(""))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	allowed := make(map[string]bool, len(queues))
	for _, queue := range queues {
		allowed[queue] = true
	}
	if len(evidence.Items) == 0 {
		t.Skip("no open tickets returned; the allowlist was not exercised. Not a pass: nothing was checked")
	}
	seen := 0
	for _, item := range evidence.Items {
		queue := item.Fields["queue"]
		if queue == "" {
			continue
		}
		seen++
		if !allowed[queue] {
			t.Errorf("ticket %s came from queue %q, which is not in %s", item.ID, queue, rtLiveQueuesEnv)
		}
	}
	if seen == 0 {
		t.Errorf("%d tickets returned and none carried a queue; the allowlist could not be checked", len(evidence.Items))
	}
	if breakdown, ok := evidence.Breakdown["tickets_by_queue"]; ok {
		for queue := range breakdown {
			if !allowed[queue] {
				t.Errorf("tickets_by_queue names queue %q, which is not in %s", queue, rtLiveQueuesEnv)
			}
		}
	}
}

// TestRTLiveCarriesNoTicketContent asserts the sensitivity boundary against
// live data rather than against a fixture written to respect it. RT tickets
// are human correspondence and routinely contain user PII and credentials
// pasted into a support request; evidence is metadata only.
func TestRTLiveCarriesNoTicketContent(t *testing.T) {
	rt, _ := rtLiveConnector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	evidence, err := rt.Execute(ctx, rtLiveStep(""))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(evidence.Items) == 0 {
		t.Skip("no open tickets returned; the sensitivity boundary was not exercised. Not a pass")
	}
	// Exactly what normalizeTicket populates. A new field arriving here should
	// fail until someone decides it is metadata rather than content.
	allowed := map[string]bool{"queue": true, "owner": true, "created": true, "last_updated": true}
	for _, item := range evidence.Items {
		for field := range item.Fields {
			if !allowed[field] {
				t.Errorf("ticket %s carries field %q, which is not metadata this connector is allowed to return", item.ID, field)
			}
		}
	}

	// Serialize the whole thing: a field named innocuously elsewhere in the
	// structure would not be caught by the loop above.
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	for _, forbidden := range []string{`"Content"`, `"content"`, `"Transactions"`, `"correspondence"`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("evidence contains %s; ticket bodies must never leave the connector", forbidden)
		}
	}
}

// TestRTLiveMatchesRTsOwnCount compares the connector's total against RT
// answering the same question directly. Ground truth drawn back through the
// connector would confirm the code against itself.
func TestRTLiveMatchesRTsOwnCount(t *testing.T) {
	rt, queues := rtLiveConnector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	bound, _ := rtLiveBound()

	// Sample either side of the connector's own call. Tickets are resolved and
	// filed while a test runs, and a mismatch inside that drift is movement,
	// not a defect.
	before, err := rtLiveDirectCount(ctx, queues, "", bound)
	if err != nil {
		t.Fatalf("direct RT count (before): %v", err)
	}
	evidence, err := rt.Execute(ctx, rtLiveStep(bound))
	if err != nil {
		t.Fatalf("bounded search: %v", err)
	}
	after, err := rtLiveDirectCount(ctx, queues, "", bound)
	if err != nil {
		t.Fatalf("direct RT count (after): %v", err)
	}

	got := evidence.Summary["total_matching"]
	low, high := before, after
	if low > high {
		low, high = high, low
	}
	t.Logf("RT directly: %d before, %d after; connector reported %d", before, after, got)
	if got < low || got > high {
		t.Errorf("connector reported %d, outside RT's own %d..%d for the same query", got, low, high)
	}
}

// rtLiveDirectCount asks RT the same question over HTTP without going through
// the connector, reading the envelope's own total rather than counting rows.
func rtLiveDirectCount(ctx context.Context, queues []string, since, until string) (int, error) {
	endpoint := strings.TrimRight(os.Getenv(rtLiveEndpointEnv), "/")
	parts := []string{"(Status = 'new' OR Status = 'open' OR Status = 'stalled')"}
	queueParts := make([]string, 0, len(queues))
	for _, queue := range queues {
		queueParts = append(queueParts, fmt.Sprintf("Queue = '%s'", strings.ReplaceAll(queue, "'", "\\'")))
	}
	if len(queueParts) > 0 {
		parts = append(parts, "("+strings.Join(queueParts, " OR ")+")")
	}
	for _, bound := range []struct{ value, operator string }{{since, ">"}, {until, "<"}} {
		if bound.value == "" {
			continue
		}
		moment, err := time.Parse(time.RFC3339, bound.value)
		if err != nil {
			return 0, err
		}
		// Same literal format the connector's rtDateBound produces, so both
		// sides are asking RT the same question.
		parts = append(parts, fmt.Sprintf("Created %s '%s'", bound.operator, moment.Format("2006-01-02 15:04:05")))
	}

	values := url.Values{}
	values.Set("query", strings.Join(parts, " AND "))
	values.Set("per_page", "1")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/REST/2.0/tickets?"+values.Encode(), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "token "+os.Getenv(rtLiveTokenEnv))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("rt returned HTTP %d", response.StatusCode)
	}
	var envelope struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return 0, err
	}
	return envelope.Total, nil
}
