package orchestrator

import (
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
	"github.com/bindatype/cassandra/internal/connector"
)

func cassPlan(host, operation string) broker.RoutePlan {
	return broker.RoutePlan{
		Version: 1,
		Intent:  broker.IntentLiveEvidence,
		Steps: []broker.RouteStep{{
			Source: broker.SourceCass, Action: "operations.execute",
			Host: host, Operation: operation,
		}},
	}
}

// The case this exists for: a policy offers host.uptime on two hosts and only
// one runs an agent that implements it. Without the check the model sends the
// request, gets "operation is not supported", and retries it verbatim.
func TestPlanIsRefusedWhenTheAgentLacksTheOperation(t *testing.T) {
	known := map[string]agentCapabilities{
		"winston.arc.gwu.edu": {
			reachable:  true,
			operations: map[string]bool{"host.info": true, "filesystem.list": true},
		},
	}

	err := checkPlanAgainstAgents(cassPlan("winston.arc.gwu.edu", "host.uptime"), known)
	if err == nil {
		t.Fatal("a plan for an operation the agent does not implement was allowed through")
	}
	// The refusal has to be actionable, or the next attempt is a guess.
	for _, want := range []string{"winston.arc.gwu.edu", "host.uptime", "host.info", "filesystem.list"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
	if !strings.Contains(err.Error(), "Do not send this request again") {
		t.Error("the refusal must say the request is deterministic, or it invites the retry it exists to prevent")
	}
}

func TestPlanIsAllowedWhenTheAgentImplementsIt(t *testing.T) {
	known := map[string]agentCapabilities{
		"sgtstubby.arc.gwu.edu": {
			reachable:  true,
			operations: map[string]bool{"host.uptime": true},
		},
	}
	if err := checkPlanAgainstAgents(cassPlan("sgtstubby.arc.gwu.edu", "host.uptime"), known); err != nil {
		t.Errorf("a supported operation was refused: %v", err)
	}
}

// Unreachable is not the same fact as "does not implement it". Refusing on a
// transport failure would report a blip as a missing capability -- precisely
// the confusion this mechanism exists to remove.
func TestAnUnreachableAgentDoesNotBecomeAMissingCapability(t *testing.T) {
	known := map[string]agentCapabilities{
		"winston.arc.gwu.edu": {reachable: false, reason: "transport_failed: connection refused"},
	}
	if err := checkPlanAgainstAgents(cassPlan("winston.arc.gwu.edu", "host.uptime"), known); err != nil {
		t.Errorf("an unreachable host was reported as lacking a capability: %v", err)
	}
}

// A host nobody probed must not be refused either, so skipping reconciliation
// leaves behaviour exactly as it was.
func TestAnUnprobedHostIsNotRefused(t *testing.T) {
	known := map[string]agentCapabilities{
		"sgtstubby.arc.gwu.edu": {reachable: true, operations: map[string]bool{"host.info": true}},
	}
	if err := checkPlanAgainstAgents(cassPlan("winston.arc.gwu.edu", "host.uptime"), known); err != nil {
		t.Errorf("an unprobed host was refused: %v", err)
	}
	if err := checkPlanAgainstAgents(cassPlan("winston.arc.gwu.edu", "host.uptime"), nil); err != nil {
		t.Errorf("with no probe results at all, the check must have no opinion: %v", err)
	}
}

// Steps that are not endpoint-agent steps carry no operation for an agent to
// implement and must pass untouched.
func TestNonAgentStepsAreUnaffected(t *testing.T) {
	known := map[string]agentCapabilities{
		"winston.arc.gwu.edu": {reachable: true, operations: map[string]bool{}},
	}
	plan := broker.RoutePlan{
		Version: 1,
		Intent:  broker.IntentFleetInventory,
		Steps:   []broker.RouteStep{{Source: broker.SourceWazuhAPI, Action: "agents.list"}},
	}
	if err := checkPlanAgainstAgents(plan, known); err != nil {
		t.Errorf("a wazuh step was judged against endpoint-agent capabilities: %v", err)
	}
}

// An agent that answers but names no operation is unreadable, not empty. If it
// were recorded as reachable-with-nothing, every request to that host would be
// refused as unimplemented.
func TestAnAgentNamingNoOperationsIsNotTreatedAsOfferingNothing(t *testing.T) {
	_, err := operationsFromEvidence(evidenceWithOperations(nil))
	if err == nil {
		t.Fatal("an agent that named no operations was accepted as offering nothing")
	}
	if !strings.Contains(err.Error(), "named no operations") {
		t.Errorf("error = %v, want it to say the agent named nothing", err)
	}
}

func TestOperationsAreReadFromCapabilityEvidence(t *testing.T) {
	operations, err := operationsFromEvidence(evidenceWithOperations([]string{"host.info", "host.uptime"}))
	if err != nil {
		t.Fatalf("operationsFromEvidence() error = %v", err)
	}
	if !operations["host.info"] || !operations["host.uptime"] {
		t.Errorf("operations = %v, want both named operations", operations)
	}
	if operations["host.diskfree"] {
		t.Error("an operation the agent did not name was reported as available")
	}
}

// evidenceWithOperations builds a capabilities.describe result the way the cass
// connector delivers one: the agent's own JSON, unreshaped.
func evidenceWithOperations(names []string) connector.Evidence {
	operations := make([]map[string]any, 0, len(names))
	for _, name := range names {
		operations = append(operations, map[string]any{"name": name, "description": "x"})
	}
	return connector.Evidence{
		Source: string(broker.SourceCass),
		Action: "operations.execute",
		Data:   map[string]any{"operations": operations},
	}
}
