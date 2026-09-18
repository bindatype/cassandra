package orchestrator

import (
	"encoding/json"
	"testing"
)

// The trace holds the steps that describe something which did NOT happen --
// evidence withheld, a result discarded, a repeat refused. Those leave no other
// mark anywhere, so an audit without them can be read as a complete record of a
// run while omitting the only explanation of its outcome.
func TestAuditCarriesTheTrace(t *testing.T) {
	event := AuditEvent{
		RequestID: "req_test",
		Question:  "what happened",
		Status:    "answered",
		Trace: []TraceEntry{
			{Stage: "intent_proposed", Detail: "live.evidence host-uptime", Allowed: true},
			{Stage: "repeated_failing_query", Detail: "model re-sent a query that already failed", Allowed: false},
			{Stage: "evidence_withheld_for_context", Detail: "adding 40000 bytes would reach about 130000 tokens", Allowed: false},
		},
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded AuditEvent
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.Trace) != 3 {
		t.Fatalf("trace has %d entries after a round trip, want 3", len(decoded.Trace))
	}
	for i, want := range event.Trace {
		got := decoded.Trace[i]
		if got.Stage != want.Stage || got.Detail != want.Detail || got.Allowed != want.Allowed {
			t.Errorf("entry %d = %+v, want %+v", i, got, want)
		}
	}
}

// An event with no trace must not emit an empty key, so existing readers that
// walk the field see absence rather than an empty list they might read as
// "nothing was decided".
func TestAuditOmitsAnEmptyTrace(t *testing.T) {
	encoded, err := json.Marshal(AuditEvent{RequestID: "req_test", Status: "answered"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := generic["trace"]; present {
		t.Error("an empty trace was emitted; absent and empty must not look the same")
	}
}
