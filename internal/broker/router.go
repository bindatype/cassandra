package broker

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	planVersion         = 1
	fleetInventoryLimit = 500
	// ticketSearchLimit bounds an RT ticket search. It is fixed rather than
	// model-chosen, unlike the monitoring limit: a ticket list is answered by
	// looking at what is open, not by tallying it, and RT's own total already
	// tells a reader whether the page is complete.
	ticketSearchLimit = 100
)

type Router struct {
	liveHosts map[string]map[string]struct{}
	resources map[string]Resource
}

func NewRouter(policy Policy) (*Router, error) {
	if err := validatePolicy(policy); err != nil {
		return nil, fmt.Errorf("invalid broker policy: %w", err)
	}

	router := &Router{
		liveHosts: make(map[string]map[string]struct{}, len(policy.LiveHosts)),
		resources: make(map[string]Resource, len(policy.Resources)),
	}
	for name, resource := range policy.Resources {
		router.resources[name] = cloneResource(resource)
	}
	for host, hostPolicy := range policy.LiveHosts {
		allowed := make(map[string]struct{}, len(hostPolicy.Resources))
		for _, resource := range hostPolicy.Resources {
			allowed[resource] = struct{}{}
		}
		router.liveHosts[host] = allowed
	}
	return router, nil
}

func (r *Router) Plan(request RouteRequest) (RoutePlan, error) {
	// Normalized once here rather than in each connector, so every source
	// receives the same instant and a malformed bound is refused at planning
	// time instead of being interpreted differently by each API.
	since, err := ParseSince(request.Since, time.Now())
	if err != nil {
		return RoutePlan{}, newRouteError("invalid_since", err.Error())
	}
	until, err := ParseUntil(request.Until, time.Now())
	if err != nil {
		return RoutePlan{}, newRouteError("invalid_until", err.Error())
	}
	if !since.IsZero() && !until.IsZero() && !until.After(since) {
		return RoutePlan{}, newRouteError("invalid_until", "until must be after since")
	}
	sinceValue, untilValue := "", ""
	if !since.IsZero() {
		sinceValue = since.Format(time.RFC3339)
	}
	if !until.IsZero() {
		untilValue = until.Format(time.RFC3339)
	}

	// The monitoring selectors are honoured by the two Zabbix intents and by
	// nothing else. Silently ignoring them elsewhere is the failure this
	// codebase keeps finding: a request narrowed by a filter that was never
	// applied comes back wide, and a wide result read as a narrow one is wrong
	// in the direction that looks right.
	switch request.Intent {
	case IntentMonitoringProblems, IntentMonitoringHistory:
	default:
		if request.Match != "" || request.Severity != "" || request.State != "" || request.Limit != 0 {
			return RoutePlan{}, newRouteError("invalid_request",
				fmt.Sprintf("%s does not accept match, severity, state, or limit; "+
					"those apply to monitoring.problems and monitoring.history", request.Intent))
		}
	}

	switch request.Intent {
	case IntentFleetInventory:
		if request.Host != "" || request.Resource != "" {
			return RoutePlan{}, newRouteError("invalid_request", "fleet.inventory does not accept host or resource")
		}
		if request.Since != "" || request.Until != "" {
			// A time bound here is worse than useless, because it is applied to
			// lastKeepAlive. A disconnected agent has by definition stopped
			// checking in, so bounding the inventory by recent contact removes
			// precisely the agents the question is about, and the empty result
			// reads as good news. Asked "how many agents are disconnected right
			// now", a model added since: "1s", got four active agents, and
			// answered "zero agents are disconnected" against a true count of
			// 52.
			//
			// Connection state is current state and has no window. Refusing is
			// the only safe answer: silently ignoring the bound would leave the
			// model believing it had asked a narrower question than it had.
			return RoutePlan{}, newRouteError("invalid_request",
				"fleet.inventory reports current connection state and takes no since or until; "+
					"a time bound filters on last contact, which hides the disconnected agents")
		}
		return newPlan(request.Intent, RouteStep{
			Source: SourceWazuhAPI,
			Action: "agents.list",
			Limit:  fleetInventoryLimit,
		}), nil

	case IntentAgentStatus:
		if err := requireHostOnly(request); err != nil {
			return RoutePlan{}, err
		}
		if request.Since != "" || request.Until != "" {
			// Same trap as fleet.inventory: the bound is applied to
			// lastKeepAlive, so a disconnected agent falls out of its own
			// status query.
			return RoutePlan{}, newRouteError("invalid_request",
				"agent.status reports current connection state and takes no since or until; "+
					"a time bound filters on last contact, which hides a disconnected agent")
		}
		return newPlan(request.Intent, RouteStep{
			Source: SourceWazuhAPI,
			Action: "agents.status",
			Host:   request.Host,
		}), nil

	case IntentMonitoringProblems:
		if request.Resource != "" {
			return RoutePlan{}, newRouteError("invalid_request", "monitoring.problems does not accept resource")
		}
		if request.Host != "" {
			if err := validateHostSelector(request.Host); err != nil {
				return RoutePlan{}, newRouteError("invalid_host", err.Error())
			}
		}
		match, severity, _, limit, err := monitoringSelectors(request, false)
		if err != nil {
			return RoutePlan{}, err
		}
		return newPlan(request.Intent, RouteStep{
			Source:   SourceZabbixAPI,
			Action:   "trigger.get",
			Host:     request.Host,
			Limit:    limit,
			Since:    sinceValue,
			Until:    untilValue,
			Match:    match,
			Severity: severity,
		}), nil

	case IntentDatabaseQuery:
		if request.Host != "" || request.Resource != "" {
			// Naming the correct field matters: a caller told only what is wrong
			// has to guess, and a model given this error repeated the same
			// mistake on retry.
			return RoutePlan{}, newRouteError("invalid_request",
				"database.query takes the SQL in the \"query\" field; it does not accept \"host\" or \"resource\"")
		}
		if request.Since != "" || request.Until != "" {
			return RoutePlan{}, newRouteError("invalid_request",
				"database.query bounds time in its WHERE clause; it does not take since or until")
		}
		if err := ValidateQuery(request.Query); err != nil {
			return RoutePlan{}, newRouteError("invalid_query", err.Error())
		}
		return newPlan(request.Intent, RouteStep{
			Source: SourcePegasusDB,
			Action: "query.execute",
			Query:  strings.TrimSpace(request.Query),
			Limit:  maxQueryRows,
		}), nil

	case IntentMonitoringHistory:
		// The event log, not current trigger state. A question about a past day
		// cannot be answered from trigger.get, which reports what is wrong now:
		// May 21st had no triggers whose state last changed that day, and 5011
		// events.
		if request.Resource != "" {
			return RoutePlan{}, newRouteError("invalid_request", "monitoring.history does not accept resource")
		}
		if request.Host != "" {
			if err := validateHostSelector(request.Host); err != nil {
				return RoutePlan{}, newRouteError("invalid_host", err.Error())
			}
		}
		if sinceValue == "" {
			return RoutePlan{}, newRouteError("missing_since", "monitoring.history requires since, and usually until")
		}
		match, severity, state, limit, err := monitoringSelectors(request, true)
		if err != nil {
			return RoutePlan{}, err
		}
		return newPlan(request.Intent, RouteStep{
			Source:   SourceZabbixAPI,
			Action:   "event.get",
			Host:     request.Host,
			Limit:    limit,
			Since:    sinceValue,
			Until:    untilValue,
			Match:    match,
			Severity: severity,
			State:    state,
		}), nil

	case IntentLiveEvidence:
		return r.planLiveEvidence(request)

	case IntentTicketsOpen:
		if request.Host != "" || request.Resource != "" {
			return RoutePlan{}, newRouteError("invalid_request", "tickets.open does not accept host or resource")
		}
		// Unlike fleet.inventory's connection state or a Zabbix trigger's
		// last-changed time, a ticket's Created date never moves retroactively:
		// bounding by it cannot hide a ticket that is still open, only select
		// which open tickets to look at. So since/until are honoured here, filtered
		// on Created, to answer "how many old open tickets" with RT's own exact
		// count rather than a model counting dates off a truncated page.
		return newPlan(request.Intent, RouteStep{
			Source: SourceRequestTracker,
			Action: "tickets.search",
			Limit:  ticketSearchLimit,
			Since:  sinceValue,
			Until:  untilValue,
		}), nil

	case IntentTicketsByHost:
		if err := requireHostOnly(request); err != nil {
			return RoutePlan{}, err
		}
		return newPlan(request.Intent, RouteStep{
			Source: SourceRequestTracker,
			Action: "tickets.search",
			Host:   request.Host,
			Limit:  ticketSearchLimit,
			Since:  sinceValue,
			Until:  untilValue,
		}), nil

	default:
		return RoutePlan{}, newRouteError("unknown_intent", fmt.Sprintf("intent %q is not supported", request.Intent))
	}
}

func (r *Router) planLiveEvidence(request RouteRequest) (RoutePlan, error) {
	if request.Host == "" {
		return RoutePlan{}, newRouteError("missing_host", "live.evidence requires host")
	}
	if err := validateHostSelector(request.Host); err != nil {
		return RoutePlan{}, newRouteError("invalid_host", err.Error())
	}
	if request.Resource == "" {
		return RoutePlan{}, newRouteError("missing_resource", "live.evidence requires a resource alias")
	}
	if err := validateResourceName(request.Resource); err != nil {
		return RoutePlan{}, newRouteError("invalid_resource", err.Error())
	}
	if request.Since != "" || request.Until != "" {
		// live.evidence reads a file from the endpoint as it stands now. There
		// is no history to bound, so a window has nothing to filter and was
		// silently dropped here for as long as this intent has existed -- the
		// third state the rest of the router does not have, and the one this
		// codebase keeps paying for: the caller believes it asked a narrower
		// question than it asked, and reads a wide answer as a narrow one.
		return RoutePlan{}, newRouteError("invalid_request",
			"live.evidence reads the resource as it stands now and takes no since or until; "+
				"there is no history at the endpoint for a window to filter")
	}

	allowedResources, ok := r.liveHosts[request.Host]
	if !ok {
		return RoutePlan{}, newRouteError("host_not_authorized", "host is not authorized for live Cass access")
	}
	if _, ok := allowedResources[request.Resource]; !ok {
		return RoutePlan{}, newRouteError("resource_not_authorized", "resource is not authorized for this host")
	}
	resource := r.resources[request.Resource]

	step := RouteStep{
		Source:    SourceCass,
		Action:    "operations.execute",
		Host:      request.Host,
		Operation: resource.Operation,
		Target:    &OperationTarget{Path: resource.Path},
	}
	if resource.Params != nil {
		params := *resource.Params
		step.Params = &params
	}
	return newPlan(request.Intent, step), nil
}

func requireHostOnly(request RouteRequest) error {
	if request.Host == "" {
		return newRouteError("missing_host", fmt.Sprintf("%s requires host", request.Intent))
	}
	if request.Resource != "" {
		return newRouteError("invalid_request", fmt.Sprintf("%s does not accept resource", request.Intent))
	}
	if err := validateHostSelector(request.Host); err != nil {
		return newRouteError("invalid_host", err.Error())
	}
	return nil
}

func newPlan(intent Intent, steps ...RouteStep) RoutePlan {
	return RoutePlan{
		Version: planVersion,
		Intent:  intent,
		Steps:   steps,
	}
}

func cloneResource(resource Resource) Resource {
	clone := resource
	if resource.Params != nil {
		params := *resource.Params
		clone.Params = &params
	}
	return clone
}

// Verify reports whether a plan is one this router would have produced under
// the current policy.
//
// Policy is enforced when a plan is created, but a plan is an ordinary JSON
// document: anything that can execute one must not assume it came from the
// planner. Rather than trusting the plan or re-deriving authorization from it,
// Verify reconstructs every plan the router could legitimately have produced
// for this intent and requires the submitted plan to equal one of them. A
// hand-edited path, an inflated limit, or a substituted operation all fail.
func (r *Router) Verify(plan RoutePlan) error {
	if len(plan.Steps) == 0 {
		return newRouteError("invalid_plan", "plan contains no steps")
	}
	candidates := r.candidateRequests(plan)
	if len(candidates) == 0 {
		return newRouteError("plan_not_authorized", "no authorized request could produce this plan")
	}
	for _, candidate := range candidates {
		produced, err := r.Plan(candidate)
		if err != nil {
			continue
		}
		if reflect.DeepEqual(produced, plan) {
			return nil
		}
	}
	return newRouteError("plan_not_authorized", "plan does not match any plan this policy would produce")
}

// candidateRequests enumerates the route requests that could have produced a
// plan with this intent and host. Every field the router derives rather than
// copies -- operation, path, limits -- is deliberately not read from the plan,
// so a modified value cannot steer the reconstruction toward itself.
func (r *Router) candidateRequests(plan RoutePlan) []RouteRequest {
	host := plan.Steps[0].Host

	switch plan.Intent {
	case IntentFleetInventory:
		return []RouteRequest{{Intent: plan.Intent}}

	case IntentAgentStatus:
		return []RouteRequest{{Intent: plan.Intent, Host: host}}

	case IntentMonitoringProblems, IntentMonitoringHistory:
		// The selectors are carried verbatim in the plan rather than resolved
		// from policy, so reconstruction reads them back. Validation runs again
		// during the replan: a limit inflated after planning fails to
		// reconstruct, because the router refuses to produce that plan.
		return []RouteRequest{{
			Intent: plan.Intent, Host: host,
			Since: plan.Steps[0].Since, Until: plan.Steps[0].Until,
			Match: plan.Steps[0].Match, Severity: plan.Steps[0].Severity,
			State: plan.Steps[0].State, Limit: plan.Steps[0].Limit,
		}}

	case IntentDatabaseQuery:
		// The query is carried verbatim in the plan rather than resolved from
		// policy, so reconstruction uses it directly. Validation runs again
		// during the replan, so a query edited after planning is still caught.
		return []RouteRequest{{Intent: plan.Intent, Query: plan.Steps[0].Query}}

	case IntentLiveEvidence:
		// The resource alias is consumed during planning and does not appear in
		// the plan, so every alias this host is authorized for is a candidate.
		allowed, ok := r.liveHosts[host]
		if !ok {
			return nil
		}
		requests := make([]RouteRequest, 0, len(allowed))
		for resource := range allowed {
			requests = append(requests, RouteRequest{
				Intent:   plan.Intent,
				Host:     host,
				Resource: resource,
			})
		}
		return requests

	case IntentTicketsOpen:
		return []RouteRequest{{Intent: plan.Intent, Since: plan.Steps[0].Since, Until: plan.Steps[0].Until}}

	case IntentTicketsByHost:
		return []RouteRequest{{Intent: plan.Intent, Host: host, Since: plan.Steps[0].Since, Until: plan.Steps[0].Until}}

	default:
		return nil
	}
}

// LiveTargets reports the hosts authorized for live.evidence and the resource
// names they may be asked for.
//
// The policy has always known both, and the model was never told either. Asked
// to list a directory on a host it had just been told about by name, it
// proposed host "sgtstubby" where the policy says "sgtstubby.arc.gwu.edu", and
// resource "/var/log" and then "var_log" where the policy says "log-dir" --
// three refusals in a row, each correct, none of them informative enough to be
// the last. Guessing an alias out of a set the caller holds is not something a
// model can be prompted into doing reliably, and it is not something it should
// have to: if code can determine it, code must.
//
// Hosts and resources are returned separately rather than as a map because
// they are used differently. A resource name is meaningful only for
// live.evidence, so it can be offered as a closed set. A host is also a Wazuh
// agent name and an RT subject, where any hostname is legitimate, so the live
// list can only be advice.
func (r *Router) LiveTargets() (hosts []string, resources []string) {
	seen := make(map[string]struct{})
	for host, allowed := range r.liveHosts {
		hosts = append(hosts, host)
		for name := range allowed {
			if _, done := seen[name]; done {
				continue
			}
			seen[name] = struct{}{}
			resources = append(resources, name)
		}
	}
	sort.Strings(hosts)
	sort.Strings(resources)
	return hosts, resources
}
