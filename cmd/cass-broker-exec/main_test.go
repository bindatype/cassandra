package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
)

func examplePolicy(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "configs", "broker-policy.example.json")
}

// planFor produces a plan the policy really would have produced, so the
// forgery tests below start from something legitimate and change one thing.
func planFor(t *testing.T, request broker.RouteRequest) broker.RoutePlan {
	t.Helper()
	file, err := os.Open(examplePolicy(t))
	if err != nil {
		t.Fatalf("open policy: %v", err)
	}
	defer file.Close()
	policy, err := broker.LoadPolicy(file)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	router, err := broker.NewRouter(policy)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	plan, err := router.Plan(request)
	if err != nil {
		t.Fatalf("plan %s: %v", request.Intent, err)
	}
	return plan
}

func TestDecodePlanRejectsMalformedInput(t *testing.T) {
	valid, err := json.Marshal(planFor(t, broker.RouteRequest{Intent: broker.IntentFleetInventory}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	tests := []struct {
		name  string
		input string
		says  string
	}{
		{"empty input", "", "decode route plan"},
		{"not json", "this is not a plan", "decode route plan"},
		{"no steps", `{"version":1,"steps":[]}`, "no steps"},
		// An unknown field is a plan written against a different contract, or
		// an attempt to smuggle one past a decoder that ignores what it does
		// not recognise.
		{"unknown field", `{"version":1,"steps":[{"source":"wazuh-api","action":"agents.list"}],"shell":"rm -rf /"}`, "decode route plan"},
		// Two documents on stdin is how a second, unverified plan would ride
		// along behind a legitimate one.
		{"trailing second document", string(valid) + string(valid), "multiple JSON values"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodePlan(strings.NewReader(test.input))
			if err == nil {
				t.Fatalf("accepted %q", test.input)
			}
			if !strings.Contains(err.Error(), test.says) {
				t.Fatalf("error = %q, want it to mention %q", err, test.says)
			}
		})
	}
}

func TestDecodePlanAcceptsARealPlan(t *testing.T) {
	want := planFor(t, broker.RouteRequest{Intent: broker.IntentFleetInventory})
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := decodePlan(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode a plan this router just produced: %v", err)
	}
	if len(got.Steps) != 1 || got.Steps[0].Action != want.Steps[0].Action {
		t.Fatalf("round trip changed the plan: %+v", got)
	}
}

// The point of the second verification: a plan that arrives here is untrusted,
// whatever produced it. Each case is a plan no router would emit.
func TestVerifyPlanRejectsForgeries(t *testing.T) {
	policy := examplePolicy(t)

	if err := verifyPlan(policy, planFor(t, broker.RouteRequest{Intent: broker.IntentFleetInventory})); err != nil {
		t.Fatalf("a legitimate plan was rejected: %v", err)
	}

	tests := []struct {
		name string
		plan func() broker.RoutePlan
	}{
		{
			name: "path swapped after planning",
			plan: func() broker.RoutePlan {
				plan := planFor(t, broker.RouteRequest{
					Intent: broker.IntentLiveEvidence, Host: "docker-harness", Resource: "system-log"})
				plan.Steps[0].Target = &broker.OperationTarget{Path: "/etc/shadow"}
				return plan
			},
		},
		{
			name: "row limit raised after planning",
			plan: func() broker.RoutePlan {
				plan := planFor(t, broker.RouteRequest{Intent: broker.IntentFleetInventory})
				plan.Steps[0].Limit = 1000000
				return plan
			},
		},
		{
			name: "action swapped for one the policy never grants",
			plan: func() broker.RoutePlan {
				plan := planFor(t, broker.RouteRequest{Intent: broker.IntentFleetInventory})
				plan.Steps[0].Action = "agents.delete"
				return plan
			},
		},
		{
			name: "second step appended to a verified first",
			plan: func() broker.RoutePlan {
				plan := planFor(t, broker.RouteRequest{Intent: broker.IntentFleetInventory})
				plan.Steps = append(plan.Steps, plan.Steps[0])
				return plan
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyPlan(policy, test.plan()); err == nil {
				t.Fatal("forged plan was accepted")
			}
		})
	}
}

func TestRunRejectsBadInvocations(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		stdin  string
		status int
		says   string
	}{
		{"no policy", nil, "", 2, "-policy is required"},
		{"unknown flag", []string{"-nonsense"}, "", 2, ""},
		{"unreadable policy", []string{"-policy", filepath.Join(t.TempDir(), "absent.json")},
			`{"version":1,"steps":[{"source":"wazuh-api","action":"agents.list"}]}`, 1, "open policy"},
		{"garbage on stdin", []string{"-policy", examplePolicy(t)}, "not a plan", 1, "decode route plan"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			status := run(test.args, strings.NewReader(test.stdin), &stdout, &stderr)
			if status != test.status {
				t.Fatalf("status = %d, want %d (stderr: %s)", status, test.status, stderr.String())
			}
			if test.says != "" && !strings.Contains(stderr.String(), test.says) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr.String(), test.says)
			}
		})
	}
}

// TestBothPathsReadTheSameWazuhConfiguration pins a divergence found on
// 2026-09-02. cass-chat read SROIAAA_WAZUH_CRITICAL_GROUPS and this path
// did not, so the same plan against the same environment produced evidence
// that could not say whether a critical agent was affected -- and the
// connector's own warning ("critical group membership was NOT evaluated")
// made it look like a deliberate deployment choice rather than a path
// difference. The README presents these two as the same route.
func TestBothPathsReadTheSameWazuhConfiguration(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read own source: %v", err)
	}
	if !strings.Contains(string(source), "CriticalGroups:") {
		t.Error("this path no longer passes CriticalGroups; a plan run here will differ from the same plan run by cass-chat")
	}

	chat, err := os.ReadFile("../cass-chat/main.go")
	if err != nil {
		t.Fatalf("read cass-chat source: %v", err)
	}
	for _, name := range []string{
		"SROIAAA_WAZUH_CRITICAL_GROUPS", "SROIAAA_RT_QUEUES", "RT_API_TOKEN", "SROIAAA_RT_ENDPOINT", "SROIAAA_AGENT_CONFIG",
	} {
		if strings.Contains(string(chat), name) != strings.Contains(string(source), name) {
			t.Errorf("%s is read by one execution path and not the other", name)
		}
	}
}

// TestRTQueueAllowlistNamesItsVariable asserts that a missing queue allowlist
// is refused with the name of the variable that fixes it. The connector
// refuses correctly on its own, but it is a library: its message cannot
// mention an environment variable it does not know exists.
func TestRTQueueAllowlistNamesItsVariable(t *testing.T) {
	t.Setenv(rtTokenEnv, "token")
	t.Setenv(rtQueuesEnv, "")

	plan := broker.RoutePlan{Steps: []broker.RouteStep{{Source: broker.SourceRequestTracker, Action: "tickets.search"}}}
	_, err := buildConnectors(plan, connectorOptions{rtEndpoint: "https://rt.example.edu"})
	if err == nil {
		t.Fatal("an empty queue allowlist must be refused")
	}
	if !strings.Contains(err.Error(), rtQueuesEnv) {
		t.Errorf("the refusal must name the variable that fixes it; got %q", err)
	}
}

func TestEndpointAgentConfigNamesItsVariable(t *testing.T) {
	t.Setenv(cassAgentConfigEnv, "")
	plan := planFor(t, broker.RouteRequest{
		Intent:   broker.IntentLiveEvidence,
		Host:     "docker-harness",
		Resource: "system-log",
	})

	_, err := buildConnectors(plan, connectorOptions{})
	if err == nil {
		t.Fatal("a live-evidence plan without endpoint configuration was accepted")
	}
	if !strings.Contains(err.Error(), cassAgentConfigEnv) {
		t.Errorf("the refusal must name the variable that fixes it; got %q", err)
	}
}
