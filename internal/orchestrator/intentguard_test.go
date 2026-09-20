package orchestrator

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
)

// NewSession lists only intents this session can reach, but a list is not a
// door. Observed: a deployment with no CASS_AGENT_CONFIG offers no
// live.evidence, the model proposed it anyway, the router planned it, and the
// user saw "no connector registered for source cass-agent" -- an internal
// fault to read, rather than the configuration problem it was.
func TestAnIntentThatWasNeverOfferedIsRefused(t *testing.T) {
	session := &Session{intents: []string{"fleet.inventory", "tickets.open"}}

	err := session.intentIsOffered(broker.IntentLiveEvidence)
	if err == nil {
		t.Fatal("an intent this session never offered was accepted")
	}
	if !strings.Contains(err.Error(), string(broker.IntentLiveEvidence)) {
		t.Errorf("refusal does not name the intent: %v", err)
	}
	// Naming what IS available turns a dead end into a next step.
	for _, want := range []string{"fleet.inventory", "tickets.open"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not list %q as available: %v", want, err)
		}
	}
	if !strings.Contains(err.Error(), "not configured here") {
		t.Error("the refusal should say the source is unconfigured, not that the intent does not exist")
	}
}

func TestAnOfferedIntentPasses(t *testing.T) {
	session := &Session{intents: []string{"fleet.inventory", "live.evidence"}}
	if err := session.intentIsOffered(broker.IntentLiveEvidence); err != nil {
		t.Errorf("an offered intent was refused: %v", err)
	}
}

// A deployment with nothing configured should say so plainly, rather than
// listing an empty set of alternatives and inviting the model to hunt.
func TestADeploymentWithNoSourcesSaysSo(t *testing.T) {
	session := &Session{}
	err := session.intentIsOffered(broker.IntentFleetInventory)
	if err == nil {
		t.Fatal("an intent was accepted by a session with no sources")
	}
	if !strings.Contains(err.Error(), "no evidence sources configured") {
		t.Errorf("error = %v, want it to name the deployment as the problem", err)
	}
	if !strings.Contains(err.Error(), "configuration problem") {
		t.Error("the refusal must point at configuration, not at the request")
	}
	// It must not suggest trying something else when nothing else exists.
	if strings.Contains(err.Error(), "Available:") {
		t.Error("an empty deployment offered a list of alternatives")
	}
}

// Every intent the session advertises must pass its own guard, or the tool
// description and the door disagree -- which is the failure this guard exists
// to prevent, pointed the other way.
func TestEveryAdvertisedIntentPassesItsOwnGuard(t *testing.T) {
	var all []string
	for _, intent := range broker.AllIntents() {
		all = append(all, string(intent))
	}
	session := &Session{intents: all}
	for _, intent := range broker.AllIntents() {
		if err := session.intentIsOffered(intent); err != nil {
			t.Errorf("advertised intent %q fails its own guard: %v", intent, err)
		}
	}
}

// Drives the whole loop, not just the helper: a session whose only connector
// is Wazuh is offered fleet.inventory and agent.status, the model proposes
// live.evidence anyway, and the refusal must arrive before the executor is
// touched. Without the guard the plan reaches the executor and the caller sees
// "no connector registered for source cass-agent".
func TestUnofferedIntentIsRefusedBeforeTheExecutor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"live.evidence\",\"host\":\"docker-harness\",\"resource\":\"system-log\"}"}}
		]}}]}`)
	}))
	defer server.Close()

	// Wazuh only. live.evidence has no connector behind it here.
	fake := &fakeConnector{source: broker.SourceWazuhAPI}
	session := newTestSession(t, server.URL, fake)

	for _, offered := range session.Intents() {
		if offered == string(broker.IntentLiveEvidence) {
			t.Fatal("fixture is wrong: live.evidence must not be offered for this test to mean anything")
		}
	}

	_, err := session.Ask(context.Background(), "read the log on docker-harness")
	if err == nil {
		t.Fatal("an unoffered intent was accepted")
	}
	if len(fake.calls) != 0 {
		t.Errorf("the connector was called %d times; the refusal must land before execution", len(fake.calls))
	}

	var recorded bool
	for _, entry := range session.Trace() {
		if entry.Stage == "intent_not_offered" {
			recorded = true
		}
	}
	if !recorded {
		t.Error("the refusal is absent from the trace, so the audit would not explain the outcome")
	}
	if strings.Contains(err.Error(), "no connector registered") {
		t.Errorf("the caller still sees an executor fault rather than a configuration problem: %v", err)
	}
}

// The documentation fallback must be unreachable when evidence was gathered.
// Prose describing what the tool can do must never stand where a measurement
// was actually taken.
func TestDocumentationNeverDisplacesEvidence(t *testing.T) {
	// The model calls the tool once, gets evidence, then answers.
	var turn int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turn++
		if turn == 1 {
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"fleet.inventory\"}"}}
			]}}]}`)
			return
		}
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"Two agents are disconnected. Scope: fleet.inventory."}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourceWazuhAPI}
	session := newTestSession(t, server.URL, fake)

	answer, err := session.Ask(context.Background(), "how many agents are disconnected?")
	if err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if strings.Contains(answer, "Cassandra documentation") {
		t.Error("an answer backed by evidence was replaced with documentation")
	}
	for _, entry := range session.Trace() {
		if entry.Stage == "answered_from_documentation" {
			t.Error("the documentation path ran even though evidence was collected")
		}
	}
}
