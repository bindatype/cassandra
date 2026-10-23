package orchestrator

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
	"github.com/bindatype/cassandra/internal/connector"
)

// A model that keeps calling tools until none are offered, then answers. On
// 2026-10-23 two questions had their answer in hand and still failed at the
// turn limit, because nothing asked for the answer.
func TestTurnLimitAnswersFromCollectedEvidence(t *testing.T) {
	var requests, withoutTools int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		if _, offered := body["tools"]; !offered {
			withoutTools++
			if _, forced := body["tool_choice"]; forced {
				t.Error("the final turn must not set tool_choice without tools")
			}
			io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"node02 is disconnected."}}]}`)
			return
		}
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
			{"id":"c","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"fleet.inventory\"}"}}]}}]}`)
	}))
	defer server.Close()

	session := newTestSession(t, server.URL, &fakeConnector{source: broker.SourceWazuhAPI})
	answer, err := session.Ask(context.Background(), "list agents forever")
	if err != nil {
		t.Fatalf("Ask() error = %v; evidence was collected, so an answer was owed", err)
	}
	if requests != maxToolCalls+1 || withoutTools != 1 {
		t.Errorf("requests = %d (%d without tools), want %d with exactly one final answer-only turn",
			requests, withoutTools, maxToolCalls+1)
	}
	if !strings.HasPrefix(answer, "node02 is disconnected.") || !strings.Contains(answer, "This answer is partial") {
		t.Errorf("answer = %q, want the model's answer plus the partial disclosure", answer)
	}
	if !session.Partial() || !session.event.Partial || session.event.Status != "answered" {
		t.Errorf("partial = %v, audit partial = %v, status = %q; want a partial answered record",
			session.Partial(), session.event.Partial, session.event.Status)
	}
	var stages []string
	for _, entry := range session.Trace() {
		stages = append(stages, entry.Stage)
	}
	joined := strings.Join(stages, ",")
	if !strings.Contains(joined, "turn_limit_reached,answered_at_turn_limit") {
		t.Errorf("trace = %s, want turn_limit_reached then answered_at_turn_limit", joined)
	}
}

// The model's own statement of what it could not do stands without a second one.
func TestTurnLimitKeepsTheModelsOwnDisclosure(t *testing.T) {
	answer := disclosePartialAnswer("Two of three hosts checked; I could not reach the third.")
	if strings.Contains(answer, "This answer is partial") {
		t.Errorf("answer = %q, the model already said what is missing", answer)
	}
}

// failingConnector fails every call, standing in for a model that never
// collects anything.
type failingConnector struct{ fakeConnector }

func (f *failingConnector) Execute(context.Context, broker.RouteStep) (connector.Evidence, error) {
	return connector.Evidence{}, errors.New("query_failed: always fails")
}

// With nothing collected there is nothing to answer from: no extra turn, and
// the message says the calls were used up, not that it "gave up".
func TestTurnLimitWithoutEvidenceStillFails(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
			{"id":"c","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"fleet.inventory\"}"}}]}}]}`)
	}))
	defer server.Close()

	session := newTestSession(t, server.URL, &failingConnector{fakeConnector{source: broker.SourceWazuhAPI}})
	_, err := session.Ask(context.Background(), "list agents forever")
	if err == nil || !strings.Contains(err.Error(), "used all 5 evidence calls without composing an answer") {
		t.Fatalf("error = %v, want the turn-limit failure", err)
	}
	if requests != maxToolCalls {
		t.Errorf("requests = %d, want %d: no final turn without evidence", requests, maxToolCalls)
	}
	if session.Partial() || session.event.Status != "failed" {
		t.Errorf("partial = %v, status = %q", session.Partial(), session.event.Status)
	}
}

// A final turn that still produces no answer fails as before.
func TestTurnLimitFinalTurnWithoutAnswerFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
			{"id":"c","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"fleet.inventory\"}"}}]}}]}`)
	}))
	defer server.Close()

	session := newTestSession(t, server.URL, &fakeConnector{source: broker.SourceWazuhAPI})
	if _, err := session.Ask(context.Background(), "list agents forever"); err == nil {
		t.Fatal("expected a failure when even the final turn gives no answer")
	}
	if session.Partial() || session.event.Status != "failed" {
		t.Errorf("partial = %v, status = %q", session.Partial(), session.event.Status)
	}
}
