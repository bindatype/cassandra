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
	// ticketSearchLimit bounds an RT ticket search. It is fixed, not
	// model-chosen: RT's own total says whether the page is complete, and the
	// counts come from RT.
	ticketSearchLimit = 100
)

type Router struct {
	liveHosts map[string]map[string]struct{}
	resources map[string]Resource
	disabled  map[Intent]struct{}
}

func NewRouter(policy Policy) (*Router, error) {
	if err := validatePolicy(policy); err != nil {
		return nil, fmt.Errorf("invalid broker policy: %w", err)
	}

	router := &Router{
		liveHosts: make(map[string]map[string]struct{}, len(policy.LiveHosts)),
		resources: make(map[string]Resource, len(policy.Resources)),
		disabled:  make(map[Intent]struct{}, len(policy.DisabledIntents)),
	}
	for _, intent := range policy.DisabledIntents {
		router.disabled[intent] = struct{}{}
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

// Enabled reports whether the policy leaves an intent switched on.
func (r *Router) Enabled(intent Intent) bool {
	_, off := r.disabled[intent]
	return !off
}

func disabledError(intent Intent) *RouteError {
	return newRouteError("intent_disabled",
		fmt.Sprintf("%s is switched off in this deployment's broker policy (disabled_intents)", intent))
}

func (r *Router) Plan(request RouteRequest) (RoutePlan, error) {
	// First, so nothing about a switched-off intent is planned. Verify plans
	// again, so a plan made before the switch was set is refused too.
	if !r.Enabled(request.Intent) {
		return RoutePlan{}, disabledError(request.Intent)
	}

	// Normalized once here, so every source gets the same instant and a
	// malformed bound is refused at planning time.
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

	// The monitoring selectors apply only to the two Zabbix intents, and are
	// refused elsewhere rather than ignored: an unapplied filter returns a
	// wide result that reads as narrow.
	switch request.Intent {
	case IntentMonitoringProblems, IntentMonitoringHistory:
	case IntentInventoryProcesses, IntentInventoryListeners:
		if request.Severity != "" || request.State != "" || request.Limit != 0 {
			return RoutePlan{}, newRouteError("invalid_request",
				fmt.Sprintf("%s accepts match but not severity, state, or limit", request.Intent))
		}
	default:
		if request.Match != "" || request.Severity != "" || request.State != "" || request.Limit != 0 {
			return RoutePlan{}, newRouteError("invalid_request",
				fmt.Sprintf("%s does not accept match, severity, state, or limit; "+
					"those apply to monitoring.problems and monitoring.history", request.Intent))
		}
	}

	if request.Order != "" {
		switch request.Intent {
		case IntentTicketsOpen, IntentTicketsByHost:
			if request.Order != TicketOrderOldestFirst && request.Order != TicketOrderNewestFirst {
				return RoutePlan{}, newRouteError("invalid_request",
					fmt.Sprintf("order must be %s or %s", TicketOrderOldestFirst, TicketOrderNewestFirst))
			}
		default:
			return RoutePlan{}, newRouteError("invalid_request",
				fmt.Sprintf("%s does not accept order; it applies to tickets.open and tickets.for_host", request.Intent))
		}
	}

	if request.Owner != "" {
		switch request.Intent {
		case IntentTicketsOpen, IntentTicketsByHost:
			if err := validateOwnerSelector(request.Owner); err != nil {
				return RoutePlan{}, newRouteError("invalid_owner", err.Error())
			}
		default:
			return RoutePlan{}, newRouteError("invalid_request",
				fmt.Sprintf("%s does not accept owner; it applies to tickets.open and tickets.for_host", request.Intent))
		}
	}

	if len(request.Queues) > 0 || request.Status != "" {
		switch request.Intent {
		case IntentTicketsOpen, IntentTicketsByHost:
			if err := validateQueueSelectors(request.Queues); err != nil {
				return RoutePlan{}, newRouteError("invalid_queue", err.Error())
			}
			if request.Status != "" && request.Status != TicketStatusActive {
				return RoutePlan{}, newRouteError("invalid_request", fmt.Sprintf(
					"status must be %s or omitted; omitted means new, open and stalled", TicketStatusActive))
			}
		default:
			return RoutePlan{}, newRouteError("invalid_request",
				fmt.Sprintf("%s does not accept queues or status; they apply to tickets.open and tickets.for_host", request.Intent))
		}
	}

	switch request.Intent {
	case IntentFleetInventory:
		if request.Host != "" || request.Resource != "" {
			return RoutePlan{}, newRouteError("invalid_request", "fleet.inventory does not accept host or resource")
		}
		if request.Since != "" || request.Until != "" {
			// Refused: Wazuh applies a time bound to lastKeepAlive, so it
			// removes exactly the disconnected agents, and the empty result
			// reads as good news. Connection state has no window.
			return RoutePlan{}, newRouteError("invalid_request",
				"fleet.inventory reports current connection state and takes no since or until; "+
					"a time bound filters on last contact, which hides the disconnected agents")
		}
		return newPlan(request.Intent, RouteStep{
			Source: SourceWazuhAPI,
			Action: "agents.list",
			Limit:  fleetInventoryLimit,
		}), nil

	case IntentFleetGroups:
		if request.Host != "" || request.Resource != "" {
			return RoutePlan{}, newRouteError("invalid_request", "fleet.groups does not accept host or resource")
		}
		if request.Since != "" || request.Until != "" {
			// Group membership is current state; a bound would imply a window
			// the answer doesn't have.
			return RoutePlan{}, newRouteError("invalid_request",
				"fleet.groups reports current group membership and takes no since or until")
		}
		return newPlan(request.Intent, RouteStep{
			Source: SourceWazuhAPI,
			Action: "groups.list",
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

	case IntentInventoryProcesses, IntentInventoryListeners:
		if err := requireHostOnly(request); err != nil {
			return RoutePlan{}, err
		}
		if request.Query != "" {
			return RoutePlan{}, newRouteError("invalid_request", fmt.Sprintf("%s does not accept query", request.Intent))
		}
		if request.Since != "" || request.Until != "" {
			// Wazuh stamps a row when it last changed, not when it was last
			// checked, so a bound would drop every process that has simply
			// kept running.
			return RoutePlan{}, newRouteError("invalid_request", fmt.Sprintf(
				"%s reports the host's inventory as it stands and takes no since or until; "+
					"a bound would filter on when a row last changed and hide long-running processes", request.Intent))
		}
		if request.Match != "" {
			if err := validateInventoryMatch(request.Match); err != nil {
				return RoutePlan{}, newRouteError("invalid_match", err.Error())
			}
			// For listeners a number is a port, since that is what a port
			// question carries; it must be one, or the filter matches nothing.
			if port, isPort := InventoryMatchPort(request.Match); isPort && request.Intent == IntentInventoryListeners &&
				(port < 1 || port > 65535) {
				return RoutePlan{}, newRouteError("invalid_match", fmt.Sprintf(
					"match %q is read as a port for inventory.listeners and must be 1-65535", request.Match))
			}
		}
		action := "syscollector.processes"
		if request.Intent == IntentInventoryListeners {
			action = "syscollector.listeners"
		}
		return newPlan(request.Intent, RouteStep{
			Source: SourceWazuhAPI,
			Action: action,
			Host:   request.Host,
			Match:  request.Match,
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
			// Name the correct field; told only what was wrong, the model
			// repeated the mistake.
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
		// The event log, not current trigger state, which can't answer for a
		// past day.
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
		// since/until bound Created, which never changes, so a bound selects
		// which open tickets to look at without hiding any; RT counts the
		// result exactly.
		return newPlan(request.Intent, RouteStep{
			Source: SourceRequestTracker,
			Action: "tickets.search",
			Limit:  ticketSearchLimit,
			Since:  sinceValue,
			Until:  untilValue,
			Owner:  request.Owner,
			Order:  request.Order,
			Queues: request.Queues,
			Status: request.Status,
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
			Owner:  request.Owner,
			Order:  request.Order,
			Queues: request.Queues,
			Status: request.Status,
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
		// live.evidence reads current state; a bound is refused, not dropped.
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
	}
	if OperationTakesTarget(resource.Operation) {
		step.Target = &OperationTarget{Path: resource.Path}
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
// A plan is an ordinary JSON document, so an executor must not assume it came
// from the planner. Verify reconstructs every plan the router could have
// produced for this intent and requires an exact match: a hand-edited path,
// inflated limit or substituted operation fails.
func (r *Router) Verify(plan RoutePlan) error {
	if len(plan.Steps) == 0 {
		return newRouteError("invalid_plan", "plan contains no steps")
	}
	// Re-planning would refuse it anyway, as unauthorized; say why instead.
	if !r.Enabled(plan.Intent) {
		return disabledError(plan.Intent)
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
// plan with this intent and host. Derived fields (operation, path, limits)
// are never read from the plan, so a modified value can't steer the
// reconstruction toward itself.
func (r *Router) candidateRequests(plan RoutePlan) []RouteRequest {
	host := plan.Steps[0].Host

	switch plan.Intent {
	case IntentFleetInventory, IntentFleetGroups:
		return []RouteRequest{{Intent: plan.Intent}}

	case IntentAgentStatus:
		return []RouteRequest{{Intent: plan.Intent, Host: host}}

	case IntentInventoryProcesses, IntentInventoryListeners:
		// The match is carried verbatim; the replan validates it again.
		return []RouteRequest{{Intent: plan.Intent, Host: host, Match: plan.Steps[0].Match}}

	case IntentMonitoringProblems, IntentMonitoringHistory:
		// Selectors are carried verbatim, so they are read back; the replan
		// validates them again.
		return []RouteRequest{{
			Intent: plan.Intent, Host: host,
			Since: plan.Steps[0].Since, Until: plan.Steps[0].Until,
			Match: plan.Steps[0].Match, Severity: plan.Steps[0].Severity,
			State: plan.Steps[0].State, Limit: plan.Steps[0].Limit,
		}}

	case IntentDatabaseQuery:
		// The query is carried verbatim; the replan validates it again.
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

	case IntentTicketsOpen, IntentTicketsByHost:
		step := plan.Steps[0]
		request := RouteRequest{Intent: plan.Intent, Since: step.Since, Until: step.Until, Owner: step.Owner,
			Order: step.Order, Queues: step.Queues, Status: step.Status}
		if plan.Intent == IntentTicketsByHost {
			request.Host = host
		}
		return []RouteRequest{request}

	default:
		return nil
	}
}

// LiveTargets reports the hosts authorized for live.evidence and the resource
// names they may be asked for.
//
// They go into the tool schema so the model needn't guess names the policy
// already holds. Resources become a closed set; hosts only advice, since a
// host is also a Wazuh agent name and an RT subject.
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
