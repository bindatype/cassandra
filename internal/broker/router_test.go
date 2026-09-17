package broker

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRouterPlansCentralDataSources(t *testing.T) {
	router := newTestRouter(t)
	tests := []struct {
		name    string
		request RouteRequest
		source  Source
		action  string
	}{
		{
			name:    "fleet inventory uses Wazuh API",
			request: RouteRequest{Intent: IntentFleetInventory},
			source:  SourceWazuhAPI,
			action:  "agents.list",
		},
		{
			name:    "agent status uses Wazuh API",
			request: RouteRequest{Intent: IntentAgentStatus, Host: "node01.example.edu"},
			source:  SourceWazuhAPI,
			action:  "agents.status",
		},
		{
			name:    "monitoring problems use Zabbix API",
			request: RouteRequest{Intent: IntentMonitoringProblems, Host: "node01.example.edu"},
			source:  SourceZabbixAPI,
			action:  "trigger.get",
		},
		{
			name:    "open tickets use the RT API",
			request: RouteRequest{Intent: IntentTicketsOpen},
			source:  SourceRequestTracker,
			action:  "tickets.search",
		},
		{
			name:    "tickets for a host use the RT API",
			request: RouteRequest{Intent: IntentTicketsByHost, Host: "node01.example.edu"},
			source:  SourceRequestTracker,
			action:  "tickets.search",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := router.Plan(test.request)
			if err != nil {
				t.Fatalf("plan route: %v", err)
			}
			if plan.Version != 1 || len(plan.Steps) != 1 {
				t.Fatalf("unexpected plan envelope: %+v", plan)
			}
			if plan.Steps[0].Source != test.source || plan.Steps[0].Action != test.action {
				t.Fatalf("unexpected route step: %+v", plan.Steps[0])
			}
		})
	}
}

func TestRouterResolvesAuthorizedLiveResource(t *testing.T) {
	router := newTestRouter(t)

	plan, err := router.Plan(RouteRequest{
		Intent:   IntentLiveEvidence,
		Host:     "node01.example.edu",
		Resource: "system-messages",
	})
	if err != nil {
		t.Fatalf("plan route: %v", err)
	}

	step := plan.Steps[0]
	if step.Source != SourceCass || step.Operation != "filesystem.tail" {
		t.Fatalf("unexpected live route: %+v", step)
	}
	if step.Target == nil || step.Target.Path != "/var/log/messages" {
		t.Fatalf("expected policy path, got %+v", step.Target)
	}
	if step.Params == nil || step.Params.MaxBytes != 8192 {
		t.Fatalf("expected policy limits, got %+v", step.Params)
	}
}

func TestRouterDeniesUnauthorizedLiveRoutes(t *testing.T) {
	router := newTestRouter(t)
	tests := []struct {
		name    string
		request RouteRequest
		code    string
	}{
		{
			name:    "unknown host",
			request: RouteRequest{Intent: IntentLiveEvidence, Host: "node02.example.edu", Resource: "system-messages"},
			code:    "host_not_authorized",
		},
		{
			name:    "resource not allowed on host",
			request: RouteRequest{Intent: IntentLiveEvidence, Host: "node01.example.edu", Resource: "workspace-file"},
			code:    "resource_not_authorized",
		},
		{
			name:    "missing resource",
			request: RouteRequest{Intent: IntentLiveEvidence, Host: "node01.example.edu"},
			code:    "missing_resource",
		},
		{
			name:    "unsupported intent",
			request: RouteRequest{Intent: "shell.execute"},
			code:    "unknown_intent",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := router.Plan(test.request)
			var routeError *RouteError
			if !errors.As(err, &routeError) {
				t.Fatalf("expected RouteError, got %v", err)
			}
			if routeError.Code != test.code {
				t.Fatalf("expected %q, got %q", test.code, routeError.Code)
			}
		})
	}
}

func TestRouterTicketIntentsRejectWrongFields(t *testing.T) {
	router := newTestRouter(t)
	tests := []struct {
		name    string
		request RouteRequest
	}{
		{"open tickets reject host", RouteRequest{Intent: IntentTicketsOpen, Host: "node01.example.edu"}},
		{"tickets for host require host", RouteRequest{Intent: IntentTicketsByHost}},
		{"tickets for host reject resource", RouteRequest{Intent: IntentTicketsByHost, Host: "node01.example.edu", Resource: "x"}},
		{"open tickets reject match", RouteRequest{Intent: IntentTicketsOpen, Match: "panic"}},
		{"open tickets reject limit", RouteRequest{Intent: IntentTicketsOpen, Limit: 5}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := router.Plan(test.request); err == nil {
				t.Fatalf("expected %+v to be rejected", test.request)
			}
		})
	}
}

// Unlike fleet.inventory or agent.status, a ticket's Created date is not
// current state, so since/until narrow "how old" rather than hide anything
// that is still open. Both intents must accept them and carry the bound
// through to the plan.
func TestRouterTicketIntentsAcceptTimeBounds(t *testing.T) {
	router := newTestRouter(t)

	openPlan, err := router.Plan(RouteRequest{Intent: IntentTicketsOpen, Until: "2026-07-04"})
	if err != nil {
		t.Fatalf("plan tickets.open with until: %v", err)
	}
	if openPlan.Steps[0].Until == "" {
		t.Fatal("tickets.open plan lost the until bound")
	}

	hostPlan, err := router.Plan(RouteRequest{
		Intent: IntentTicketsByHost, Host: "node01.example.edu",
		Since: "2026-01-01", Until: "2026-06-01",
	})
	if err != nil {
		t.Fatalf("plan tickets.for_host with since/until: %v", err)
	}
	if hostPlan.Steps[0].Since == "" || hostPlan.Steps[0].Until == "" {
		t.Fatalf("tickets.for_host plan lost a time bound: %+v", hostPlan.Steps[0])
	}

	// A malformed bound is still refused by the shared since/until parser, not
	// silently ignored.
	if _, err := router.Plan(RouteRequest{Intent: IntentTicketsOpen, Since: "not-a-time"}); err == nil {
		t.Fatal("expected a malformed since to be rejected")
	}
}

func TestRouterVerifyAcceptsTicketPlans(t *testing.T) {
	router := newTestRouter(t)

	openPlan, err := router.Plan(RouteRequest{Intent: IntentTicketsOpen, Until: "2026-07-04"})
	if err != nil {
		t.Fatalf("plan tickets.open: %v", err)
	}
	if err := router.Verify(openPlan); err != nil {
		t.Fatalf("Verify(tickets.open) = %v", err)
	}

	hostPlan, err := router.Plan(RouteRequest{Intent: IntentTicketsByHost, Host: "node01.example.edu"})
	if err != nil {
		t.Fatalf("plan tickets.for_host: %v", err)
	}
	if err := router.Verify(hostPlan); err != nil {
		t.Fatalf("Verify(tickets.for_host) = %v", err)
	}

	// A plan naming an unsupported action must still fail reconstruction: host
	// is a free parameter here, like it is for agent.status and
	// monitoring.problems, but the action table is not.
	tampered := hostPlan
	steps := append([]RouteStep(nil), tampered.Steps...)
	steps[0].Action = "tickets.comment"
	tampered.Steps = steps
	if err := router.Verify(tampered); err == nil {
		t.Fatal("Verify() accepted a tickets.for_host plan with a substituted action")
	}

	// An until bound that fails the shared parser -- here, one further in the
	// future than "now" allows -- still fails reconstruction, the same way an
	// invalid since/until does for monitoring.problems and monitoring.history.
	tamperedBound := openPlan
	boundSteps := append([]RouteStep(nil), tamperedBound.Steps...)
	boundSteps[0].Until = "2099-01-01T00:00:00Z"
	tamperedBound.Steps = boundSteps
	if err := router.Verify(tamperedBound); err == nil {
		t.Fatal("Verify() accepted a tickets.open plan with an out-of-range until bound")
	}
}

func TestLoadPolicyAndRequestRejectUnknownFields(t *testing.T) {
	_, err := LoadPolicy(strings.NewReader(`{"version":1,"live_hosts":{},"resources":{},"extra":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown policy field error, got %v", err)
	}

	_, err = DecodeRouteRequest(strings.NewReader(`{"intent":"live.evidence","path":"/etc/shadow"}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected model-selected path rejection, got %v", err)
	}
}

func TestNewRouterRejectsUnsafeResources(t *testing.T) {
	tests := []struct {
		name     string
		resource Resource
	}{
		{
			name:     "arbitrary operation",
			resource: Resource{Operation: "process.list", Path: "/proc"},
		},
		{
			name:     "relative path",
			resource: Resource{Operation: "filesystem.stat", Path: "etc/passwd"},
		},
		{
			name: "excessive read",
			resource: Resource{
				Operation: "filesystem.read",
				Path:      "/etc/hosts",
				Params:    &OperationParams{MaxBytes: 65537},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRouter(Policy{
				Version:   1,
				LiveHosts: map[string]HostPolicy{},
				Resources: map[string]Resource{"unsafe": test.resource},
			})
			if err == nil {
				t.Fatal("expected unsafe resource to be rejected")
			}
		})
	}
}

func newTestRouter(t *testing.T) *Router {
	t.Helper()
	router, err := NewRouter(Policy{
		Version: 1,
		LiveHosts: map[string]HostPolicy{
			"node01.example.edu": {Resources: []string{"system-messages"}},
		},
		Resources: map[string]Resource{
			"system-messages": {
				Operation: "filesystem.tail",
				Path:      "/var/log/messages",
				Params:    &OperationParams{MaxBytes: 8192},
			},
			"workspace-file": {
				Operation: "filesystem.read",
				Path:      "/workspace/sample.txt",
				Params:    &OperationParams{MaxBytes: 4096},
			},
		},
	})
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	return router
}

func TestRouterVerifyAcceptsPlansItProduced(t *testing.T) {
	router := newTestRouter(t)
	for _, request := range []RouteRequest{
		{Intent: IntentFleetInventory},
		{Intent: IntentAgentStatus, Host: "node01.example.edu"},
		{Intent: IntentMonitoringProblems},
		{Intent: IntentMonitoringProblems, Host: "node01.example.edu"},
		{Intent: IntentLiveEvidence, Host: "node01.example.edu", Resource: "system-messages"},
	} {
		t.Run(string(request.Intent)+"/"+request.Resource, func(t *testing.T) {
			plan, err := router.Plan(request)
			if err != nil {
				t.Fatalf("Plan() error = %v", err)
			}
			if err := router.Verify(plan); err != nil {
				t.Errorf("Verify() rejected a plan the router produced: %v", err)
			}
		})
	}
}

func TestRouterVerifyRejectsTamperedPlans(t *testing.T) {
	router := newTestRouter(t)
	base, err := router.Plan(RouteRequest{
		Intent: IntentLiveEvidence, Host: "node01.example.edu", Resource: "system-messages"})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(RoutePlan) RoutePlan
	}{
		{
			// The case this verification exists for: a hand-written plan
			// carrying a path no resource alias maps to.
			name: "substituted filesystem path",
			mutate: func(p RoutePlan) RoutePlan {
				steps := append([]RouteStep(nil), p.Steps...)
				target := *steps[0].Target
				target.Path = "/etc/shadow"
				steps[0].Target = &target
				p.Steps = steps
				return p
			},
		},
		{
			name: "substituted operation",
			mutate: func(p RoutePlan) RoutePlan {
				steps := append([]RouteStep(nil), p.Steps...)
				steps[0].Operation = "process.list"
				p.Steps = steps
				return p
			},
		},
		{
			name: "inflated read limit",
			mutate: func(p RoutePlan) RoutePlan {
				steps := append([]RouteStep(nil), p.Steps...)
				params := *steps[0].Params
				params.MaxBytes = 1 << 30
				steps[0].Params = &params
				p.Steps = steps
				return p
			},
		},
		{
			name: "unauthorized host",
			mutate: func(p RoutePlan) RoutePlan {
				steps := append([]RouteStep(nil), p.Steps...)
				steps[0].Host = "not-authorized.example.edu"
				p.Steps = steps
				return p
			},
		},
		{
			name: "extra step appended",
			mutate: func(p RoutePlan) RoutePlan {
				p.Steps = append(append([]RouteStep(nil), p.Steps...), p.Steps[0])
				return p
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := router.Verify(test.mutate(base)); err == nil {
				t.Fatal("Verify() accepted a tampered plan")
			}
		})
	}
}

func TestRouterVerifyRejectsEmptyPlan(t *testing.T) {
	if err := newTestRouter(t).Verify(RoutePlan{Version: planVersion}); err == nil {
		t.Fatal("Verify() accepted a plan with no steps")
	}
}

func TestSourceForIntentCoversEveryIntent(t *testing.T) {
	for _, intent := range AllIntents() {
		if _, ok := SourceForIntent(intent); !ok {
			t.Errorf("SourceForIntent(%q) has no source; a new intent must declare one", intent)
		}
	}
	if _, ok := SourceForIntent(Intent("nope")); ok {
		t.Error("SourceForIntent accepted an unknown intent")
	}
}

func TestParseSinceAcceptsTheFormsAModelReachesFor(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		value string
		want  time.Time
	}{
		{"2026-08-27T00:00:00Z", time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)},
		{"2026-08-27", time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)},
		{"24h", time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)},
		{"7d", time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)},
		// A model asked "did anything alert today" wrote since: "today". A
		// parser that rejects the obvious word denies a well-formed question
		// over vocabulary.
		{"today", time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)},
		{"yesterday", time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)},
		{"", time.Time{}},
	} {
		got, err := ParseSince(test.value, now)
		if err != nil {
			t.Errorf("ParseSince(%q) error = %v", test.value, err)
			continue
		}
		if !got.Equal(test.want) {
			t.Errorf("ParseSince(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestParseSinceRejectsUnboundedOrImpossibleWindows(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	for _, value := range []string{
		"2027-01-01",   // future
		"3000d",        // further back than the bound
		"-24h",         // not a past window
		"last tuesday", // not a form we accept
		"soon",         // not a time at all
	} {
		if _, err := ParseSince(value, now); err == nil {
			t.Errorf("ParseSince(%q) was accepted", value)
		}
	}
}

func TestSinceReachesThePlanAndSurvivesVerification(t *testing.T) {
	router := newTestRouter(t)
	plan, err := router.Plan(RouteRequest{Intent: IntentMonitoringProblems, Since: "24h"})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if plan.Steps[0].Since == "" {
		t.Fatal("since did not reach the step")
	}
	if _, err := time.Parse(time.RFC3339, plan.Steps[0].Since); err != nil {
		t.Errorf("since should be normalized to RFC 3339, got %q", plan.Steps[0].Since)
	}
	// A relative window becomes an absolute instant during planning, so
	// verification has to reconstruct from the absolute form.
	if err := router.Verify(plan); err != nil {
		t.Errorf("Verify() rejected a plan carrying since: %v", err)
	}
}

func TestDatabaseQueryRefusesSince(t *testing.T) {
	// SQL bounds its own time. Two mechanisms would disagree silently.
	router := newTestRouter(t)
	_, err := router.Plan(RouteRequest{
		Intent: IntentDatabaseQuery,
		Query:  "SELECT 1 FROM runTBL2 WHERE SubmitTime > 0",
		Since:  "24h",
	})
	if err == nil {
		t.Fatal("database.query should refuse since")
	}
}

// A time bound on a connection-state intent is applied to lastKeepAlive, so it
// removes exactly the agents the question is about. Asked how many agents were
// disconnected "right now", a model sent since: "1s", was given the four
// agents that had checked in within the second, and reported zero disconnected
// against a true count of 52. Refusing is the only safe answer: ignoring the
// bound would leave the model believing it asked a narrower question.
func TestConnectionStateIntentsRefuseTimeBounds(t *testing.T) {
	router := newTestRouter(t)
	for _, request := range []RouteRequest{
		{Intent: IntentFleetInventory, Since: "1s"},
		{Intent: IntentFleetInventory, Until: "2026-08-30"},
		{Intent: IntentAgentStatus, Host: "sgtstubby.arc.gwu.edu", Since: "24h"},
		{Intent: IntentAgentStatus, Host: "sgtstubby.arc.gwu.edu", Until: "2026-08-30"},
	} {
		t.Run(string(request.Intent)+"/"+request.Since+request.Until, func(t *testing.T) {
			_, err := router.Plan(request)
			if err == nil {
				t.Fatal("a time bound must be refused, not silently ignored")
			}
			// The message has to say why, or the model retries the same shape.
			if !strings.Contains(err.Error(), "last contact") {
				t.Fatalf("error does not explain the hazard: %v", err)
			}
		})
	}
}

// Without a bound they must still plan normally.
func TestConnectionStateIntentsPlanWithoutBounds(t *testing.T) {
	router := newTestRouter(t)
	for _, request := range []RouteRequest{
		{Intent: IntentFleetInventory},
		{Intent: IntentAgentStatus, Host: "sgtstubby.arc.gwu.edu"},
	} {
		plan, err := router.Plan(request)
		if err != nil {
			t.Fatalf("%s: %v", request.Intent, err)
		}
		if plan.Steps[0].Since != "" || plan.Steps[0].Until != "" {
			t.Fatalf("%s carries a bound it never accepted: %+v", request.Intent, plan.Steps[0])
		}
		if err := router.Verify(plan); err != nil {
			t.Fatalf("%s: verify: %v", request.Intent, err)
		}
	}
}

// The time-bound contract, in one place. Three documents describe it -- the
// system prompt, the tool schema, and this router -- and they had drifted:
// the prompt said every intent but database.query accepted a window, while
// three of the six refused one and live.evidence silently dropped it. Whether
// an intent takes since and until is now asserted here, so the next divergence
// fails a test instead of reaching a model.
func TestTimeBoundContract(t *testing.T) {
	router := newTestRouter(t)
	tests := []struct {
		name     string
		request  RouteRequest
		accepted bool
	}{
		{"fleet.inventory refuses", RouteRequest{Intent: IntentFleetInventory}, false},
		{"agent.status refuses", RouteRequest{Intent: IntentAgentStatus, Host: "node01.example.edu"}, false},
		{"database.query refuses", RouteRequest{Intent: IntentDatabaseQuery, Query: "SELECT 1 FROM runTBL2 WHERE id = 1"}, false},
		{"live.evidence refuses", RouteRequest{Intent: IntentLiveEvidence, Host: "node01.example.edu", Resource: "system-messages"}, false},
		{"monitoring.problems accepts", RouteRequest{Intent: IntentMonitoringProblems}, true},
		{"monitoring.history accepts", RouteRequest{Intent: IntentMonitoringHistory}, true},
		// A ticket's Created date never moves retroactively, so a bound can only
		// narrow which open tickets are in view, never hide one still open.
		{"tickets.open accepts", RouteRequest{Intent: IntentTicketsOpen}, true},
		{"tickets.for_host accepts", RouteRequest{Intent: IntentTicketsByHost, Host: "node01.example.edu"}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, bound := range []string{"since", "until"} {
				request := test.request
				if bound == "since" {
					request.Since = "24h"
				} else {
					// monitoring.history requires since regardless, so an
					// until-only case would fail for the wrong reason.
					request.Since = "24h"
					request.Until = "1h"
				}
				_, err := router.Plan(request)
				if test.accepted && err != nil {
					t.Fatalf("%s: expected %s to be accepted, got %v", bound, request.Intent, err)
				}
				if !test.accepted {
					var routeError *RouteError
					if !errors.As(err, &routeError) || routeError.Code != "invalid_request" {
						t.Fatalf("%s: expected %s to refuse the bound, got %v", bound, request.Intent, err)
					}
				}
			}
		})
	}
}

// TestTicketAgeBoundStandsAlone pins the shape a question about ticket age
// takes. "Older than 60 days" is an until with no since: the oldest tickets
// are the ones being asked about, so a lower bound would cut off the answer.
//
// This exists because the model got it wrong in the field on 2026-09-02. It
// sent no bound at all, received 100 of 428 matching tickets, and tallied
// created dates and owners off that page -- reporting a property of the page
// as a property of RT. The broker would have accepted the bounded request;
// nothing had ever told the model to make it.
func TestTicketAgeBoundStandsAlone(t *testing.T) {
	router := newTestRouter(t)
	tests := []struct {
		name    string
		request RouteRequest
	}{
		{"tickets.open", RouteRequest{Intent: IntentTicketsOpen, Until: "60d"}},
		{"tickets.for_host", RouteRequest{Intent: IntentTicketsByHost, Host: "node01.example.edu", Until: "60d"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := router.Plan(test.request)
			if err != nil {
				t.Fatalf("until without since must be a legal ticket bound, got %v", err)
			}
			if len(plan.Steps) != 1 {
				t.Fatalf("expected one step, got %d", len(plan.Steps))
			}
			// The planner resolves a relative window to an absolute instant so
			// the executor cannot re-resolve it later and answer a different
			// question than the one authorized.
			until, err := time.Parse(time.RFC3339, plan.Steps[0].Until)
			if err != nil {
				t.Fatalf("plan dropped or mangled the bound: until = %q (%v)", plan.Steps[0].Until, err)
			}
			if age := time.Since(until); age < 59*24*time.Hour || age > 61*24*time.Hour {
				t.Errorf("until resolved to %s, which is %v ago; want about 60 days", until, age)
			}
			if plan.Steps[0].Since != "" {
				t.Errorf("plan invented a lower bound: since = %q, want empty", plan.Steps[0].Since)
			}
		})
	}
}

// TestHostInfoIsRoutableWithoutAPath pins the shape that kept host.info
// unreachable. Every routable operation addressed a file, so the path was
// validated before the operation was looked at, and a resource with nothing to
// name was rejected before its operation could be considered.
func TestHostInfoIsRoutableWithoutAPath(t *testing.T) {
	router, err := NewRouter(Policy{
		Version:   1,
		LiveHosts: map[string]HostPolicy{"h1": {Resources: []string{"facts"}}},
		Resources: map[string]Resource{"facts": {Operation: "host.info"}},
	})
	if err != nil {
		t.Fatalf("host.info with no path was rejected: %v", err)
	}

	plan, err := router.Plan(RouteRequest{Intent: IntentLiveEvidence, Host: "h1", Resource: "facts"})
	if err != nil {
		t.Fatalf("plan host.info: %v", err)
	}
	// No target, rather than an empty one. An OperationTarget{Path: ""} would
	// travel to the agent as a target it must decide to ignore.
	if plan.Steps[0].Target != nil {
		t.Errorf("host.info step carried a target: %#v", plan.Steps[0].Target)
	}
}

// TestHostInfoRejectsAPathRatherThanIgnoringIt: a silently discarded path
// reads, to whoever wrote it, as a path being honoured.
func TestHostInfoRejectsAPathRatherThanIgnoringIt(t *testing.T) {
	_, err := NewRouter(Policy{
		Version:   1,
		LiveHosts: map[string]HostPolicy{"h1": {Resources: []string{"facts"}}},
		Resources: map[string]Resource{"facts": {Operation: "host.info", Path: "/etc/hostname"}},
	})
	if err == nil {
		t.Fatal("a path on host.info was accepted and would have been ignored")
	}
	if !strings.Contains(err.Error(), "addresses no path") {
		t.Errorf("error does not say why: %v", err)
	}
}

// TestFileOperationsStillRequireAPath guards the other direction: making the
// path conditional must not have made it optional for everything.
func TestFileOperationsStillRequireAPath(t *testing.T) {
	for _, operation := range []string{"filesystem.list", "filesystem.stat", "filesystem.read", "filesystem.tail"} {
		_, err := NewRouter(Policy{
			Version:   1,
			LiveHosts: map[string]HostPolicy{"h1": {Resources: []string{"r"}}},
			Resources: map[string]Resource{"r": {
				Operation: operation,
				Params:    &OperationParams{MaxEntries: 10, MaxBytes: 1024},
			}},
		})
		if err == nil {
			t.Errorf("%s was accepted with no path", operation)
		}
	}
}

// TestUnroutableOperationSaysSo. Checking the path first meant an operation
// the broker will never route was reported as a path problem.
func TestUnroutableOperationSaysSo(t *testing.T) {
	_, err := NewRouter(Policy{
		Version:   1,
		LiveHosts: map[string]HostPolicy{"h1": {Resources: []string{"r"}}},
		Resources: map[string]Resource{"r": {Operation: "process.list"}},
	})
	if err == nil {
		t.Fatal("process.list is implemented by the agent but must not be broker-routable")
	}
	if !strings.Contains(err.Error(), "not broker-routable") {
		t.Errorf("misleading error for an unroutable operation: %v", err)
	}
}
