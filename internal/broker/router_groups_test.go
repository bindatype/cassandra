package broker

import (
	"strings"
	"testing"
)

func TestFleetGroupsPlansAgainstTheGroupEndpoint(t *testing.T) {
	router := newTestRouter(t)
	plan, err := router.Plan(RouteRequest{Intent: IntentFleetGroups})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Steps) != 1 {
		t.Fatalf("got %d steps, want 1", len(plan.Steps))
	}
	step := plan.Steps[0]
	if step.Source != SourceWazuhAPI {
		t.Errorf("source = %q, want wazuh-api", step.Source)
	}
	if step.Action != "groups.list" {
		t.Errorf("action = %q, want groups.list -- agents.list would return records to tally", step.Action)
	}
}

// Every intent must be reachable through plan reconstruction, or the plan is
// refused at execution time and the capability is unreachable in practice.
func TestFleetGroupsSurvivesPlanReconstruction(t *testing.T) {
	router := newTestRouter(t)
	plan, err := router.Plan(RouteRequest{Intent: IntentFleetGroups})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	candidates := router.candidateRequests(plan)
	if len(candidates) == 0 {
		t.Fatal("no candidate request reconstructs a fleet.groups plan")
	}
	for _, candidate := range candidates {
		rebuilt, err := router.Plan(candidate)
		if err != nil {
			t.Fatalf("replan of %+v: %v", candidate, err)
		}
		if rebuilt.Steps[0].Action != plan.Steps[0].Action {
			t.Errorf("replan action = %q, want %q", rebuilt.Steps[0].Action, plan.Steps[0].Action)
		}
	}
}

func TestFleetGroupsRefusesTargetsAndBounds(t *testing.T) {
	cases := []struct {
		name    string
		request RouteRequest
		wants   string
	}{
		{"host", RouteRequest{Intent: IntentFleetGroups, Host: "sgtstubby"}, "host or resource"},
		{"resource", RouteRequest{Intent: IntentFleetGroups, Resource: "syslog"}, "host or resource"},
		{"since", RouteRequest{Intent: IntentFleetGroups, Since: "2026-09-01T00:00:00Z"}, "since or until"},
		{"until", RouteRequest{Intent: IntentFleetGroups, Until: "2026-09-01T00:00:00Z"}, "since or until"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestRouter(t).Plan(tc.request)
			if err == nil {
				t.Fatalf("Plan(%+v) was accepted", tc.request)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("error = %v, want it to name %q", err, tc.wants)
			}
		})
	}
}

// Every intent the broker offers must route to a source, or a model is shown a
// capability whose connector cannot be found at execution time.
func TestFleetGroupsIsRoutableAndListed(t *testing.T) {
	source, ok := SourceForIntent(IntentFleetGroups)
	if !ok || source != SourceWazuhAPI {
		t.Fatalf("SourceForIntent(fleet.groups) = %q, %v", source, ok)
	}
	var listed bool
	for _, intent := range AllIntents() {
		if intent == IntentFleetGroups {
			listed = true
		}
	}
	if !listed {
		t.Error("fleet.groups is absent from AllIntents(); it would never be offered to a model")
	}
}

func newGroupsRouter(t *testing.T) *Router {
	t.Helper()
	router, err := NewRouter(Policy{Version: 1})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	return router
}
