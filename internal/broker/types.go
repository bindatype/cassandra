package broker

type Intent string

const (
	IntentFleetInventory     Intent = "fleet.inventory"
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
	case IntentFleetInventory, IntentAgentStatus:
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
	// Query is the one field a model may author rather than choose from a
	// fixed set. It applies to database.query only, where the credential's
	// single-schema read grant bounds the damage class in a way that no
	// filesystem path could.
	Query string `json:"query,omitempty"`
	// Since bounds evidence to what changed after a moment, as RFC 3339. It is
	// a property of a request rather than of any one source: each connector
	// maps it to its own idiom. A connector that cannot honour it must say so
	// in the evidence rather than return unfiltered rows, because a time-scoped
	// question answered from unfiltered data is wrong in the direction that
	// looks right.
	Since string `json:"since,omitempty"`
	// Until closes the window Since opens. Without it a bound is a ray: asking
	// for issues "on May 21st" with only a lower bound returned everything from
	// May to now, sorted by recency, so the answer described today.
	Until string `json:"until,omitempty"`
	// Match narrows monitoring evidence to problems whose name contains this
	// text. It is the difference between a question and a page: asked which
	// hosts lost their Zabbix agent since 05:00, the only available move was to
	// fetch the newest 25 of 1,200 events and hope the relevant ones were among
	// them. They were not, and nothing in the result said so.
	//
	// Like Query this is authored rather than chosen, and like Query it is
	// bounded by what it reaches: a substring filter over a name column cannot
	// widen the request beyond the intent that carries it.
	Match string `json:"match,omitempty"`
	// Severity is the floor, named rather than numbered: "warning" and above,
	// "high" and above. The census already reports the breakdown, so a reader
	// asking only about disasters was being handed 25 rows of information-level
	// noise and a count they had to filter by eye.
	Severity string `json:"severity,omitempty"`
	// State selects problems that are still open or ones that have closed.
	// Applies to monitoring.history, whose event log carries both: an incident
	// that opened and resolved within the window appears twice, and "what broke
	// this morning" and "what is still broken" are different questions asked of
	// the same rows.
	State string `json:"state,omitempty"`
	// Limit is how many rows to return, up to MaxMonitoringLimit. It exists
	// because the default is a sample and was being read as a population. It is
	// still a page: raising it far enough to hold 1,200 events would overrun
	// the evidence budget, so the honest answers to a large result are a
	// narrower filter and the aggregates computed alongside it, not a bigger
	// page.
	Limit int `json:"limit,omitempty"`
}

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
