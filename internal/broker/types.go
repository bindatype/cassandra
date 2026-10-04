package broker

type Intent string

const (
	IntentFleetInventory     Intent = "fleet.inventory"
	IntentFleetGroups        Intent = "fleet.groups"
	IntentAgentStatus        Intent = "agent.status"
	IntentMonitoringProblems Intent = "monitoring.problems"
	IntentLiveEvidence       Intent = "live.evidence"
	IntentDatabaseQuery      Intent = "database.query"
	IntentMonitoringHistory  Intent = "monitoring.history"
	IntentTicketsOpen        Intent = "tickets.open"
	IntentTicketsByHost      Intent = "tickets.for_host"
)

type Source string

const (
	SourceWazuhAPI       Source = "wazuh-api"
	SourceZabbixAPI      Source = "zabbix-api"
	SourceCass           Source = "cass-agent"
	SourcePegasusDB      Source = "pegasus-db"
	SourceRequestTracker Source = "rt-api"
)

// SourceForIntent reports which data source an intent routes to. It lets a
// caller discover, before planning, whether an intent is executable at all --
// so a model is never offered an intent whose connector does not exist.
func SourceForIntent(intent Intent) (Source, bool) {
	switch intent {
	case IntentFleetInventory, IntentFleetGroups, IntentAgentStatus:
		return SourceWazuhAPI, true
	case IntentMonitoringProblems:
		return SourceZabbixAPI, true
	case IntentLiveEvidence:
		return SourceCass, true
	case IntentDatabaseQuery:
		return SourcePegasusDB, true
	case IntentMonitoringHistory:
		return SourceZabbixAPI, true
	case IntentTicketsOpen, IntentTicketsByHost:
		return SourceRequestTracker, true
	default:
		return "", false
	}
}

// AllIntents lists every intent the router can plan.
func AllIntents() []Intent {
	return []Intent{
		IntentFleetInventory,
		IntentFleetGroups,
		IntentAgentStatus,
		IntentMonitoringProblems,
		IntentLiveEvidence,
		IntentDatabaseQuery,
		IntentMonitoringHistory,
		IntentTicketsOpen,
		IntentTicketsByHost,
	}
}

type RouteRequest struct {
	Intent   Intent `json:"intent"`
	Host     string `json:"host,omitempty"`
	Resource string `json:"resource,omitempty"`
	// Query is model-authored SQL, for database.query only. That is
	// acceptable there because the credential is a read grant on one schema.
	Query string `json:"query,omitempty"`
	// Since bounds evidence to what changed after a moment, as RFC 3339; each
	// connector maps it to its own idiom. An intent that can't honour a bound
	// refuses it rather than returning unfiltered rows.
	Since string `json:"since,omitempty"`
	// Until closes the window Since opens. Without it a question about one
	// past day is answered from that day to now.
	Until string `json:"until,omitempty"`
	// Match narrows monitoring evidence to problems whose name contains this
	// text, so a question about one kind of problem isn't answered from a
	// general page. Model-authored, but a substring filter can only narrow the
	// intent that carries it.
	Match string `json:"match,omitempty"`
	// Severity is a floor, named rather than numbered ("high" means high and
	// above).
	Severity string `json:"severity,omitempty"`
	// State selects problem (opening) or resolved (closing) events, for
	// monitoring.history only: an incident that opened and closed in the
	// window appears twice in the event log.
	State string `json:"state,omitempty"`
	// Limit is how many rows to return, up to MaxMonitoringLimit. It is still
	// a page: a large result is answered with a narrower filter and the
	// aggregates, not a bigger page, which would overrun the evidence budget.
	Limit int `json:"limit,omitempty"`
	// Owner narrows ticket evidence to one Request Tracker owner login, as it
	// appears in evidence, or Nobody for unowned tickets. One owner per call.
	Owner string `json:"owner,omitempty"`
	// Order picks which end of a truncated ticket page to read: oldest_first
	// or newest_first. Without it the bound decides; it is needed for "the
	// oldest tickets created in the last N days" (since plus oldest_first).
	Order string `json:"order,omitempty"`
	// Queues narrows ticket evidence to some of the allowlisted RT queues.
	// Empty means every allowlisted queue; a queue outside the allowlist is
	// refused by the connector, which holds the allowlist.
	Queues []string `json:"queues,omitempty"`
	// Status picks which tickets count as open. Empty is new, open and
	// stalled; TicketStatusActive is RT's __Active__, which follows each
	// queue's own lifecycle.
	Status string `json:"status,omitempty"`
}

// Ticket page orderings a request may ask for explicitly.
const (
	TicketOrderOldestFirst = "oldest_first"
	TicketOrderNewestFirst = "newest_first"
)

// TicketStatusActive selects RT's __Active__ statuses instead of the default
// new, open and stalled. A queue with its own lifecycle can have active
// statuses that are none of those three.
const TicketStatusActive = "active"

type RoutePlan struct {
	Version int         `json:"version"`
	Intent  Intent      `json:"intent"`
	Steps   []RouteStep `json:"steps"`
}

type RouteStep struct {
	Source    Source           `json:"source"`
	Action    string           `json:"action"`
	Host      string           `json:"host,omitempty"`
	Limit     int              `json:"limit,omitempty"`
	Operation string           `json:"operation,omitempty"`
	Query     string           `json:"query,omitempty"`
	Since     string           `json:"since,omitempty"`
	Until     string           `json:"until,omitempty"`
	Match     string           `json:"match,omitempty"`
	Severity  string           `json:"severity,omitempty"`
	State     string           `json:"state,omitempty"`
	Owner     string           `json:"owner,omitempty"`
	Order     string           `json:"order,omitempty"`
	Queues    []string         `json:"queues,omitempty"`
	Status    string           `json:"status,omitempty"`
	Target    *OperationTarget `json:"target,omitempty"`
	Params    *OperationParams `json:"params,omitempty"`
}

type OperationTarget struct {
	Path string `json:"path"`
}

type OperationParams struct {
	Offset     int64 `json:"offset,omitempty"`
	MaxBytes   int64 `json:"max_bytes,omitempty"`
	MaxEntries int   `json:"max_entries,omitempty"`
}

type Policy struct {
	Version   int                   `json:"version"`
	LiveHosts map[string]HostPolicy `json:"live_hosts"`
	Resources map[string]Resource   `json:"resources"`
}

type HostPolicy struct {
	Resources []string `json:"resources"`
}

type Resource struct {
	Operation string           `json:"operation"`
	Path      string           `json:"path"`
	Params    *OperationParams `json:"params,omitempty"`
}

type RouteError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RouteError) Error() string {
	return e.Code + ": " + e.Message
}

func newRouteError(code, message string) *RouteError {
	return &RouteError{Code: code, Message: message}
}
