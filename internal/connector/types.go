// Package connector executes broker route plans against real data sources.
//
// Connectors are the trusted execution half of the broker. A route plan
// describes what to fetch; a connector decides how. Endpoints, credentials,
// and API methods are supplied by operator configuration and a fixed action
// table, never by the plan and never by a model.
package connector

import "time"

// Evidence is the normalized result of executing one route step.
//
// Provenance fields are recorded so that downstream synthesis can state where
// a claim came from, and so that an audit record can be written without
// re-deriving the request.
type Evidence struct {
	Source   string `json:"source"`
	Action   string `json:"action"`
	Endpoint string `json:"endpoint"`
	// Query records what actually ran, when a source executes a statement the
	// model composed. Without it an answer is unauditable by the person
	// reading it: the number looks authoritative and its derivation is
	// invisible.
	Query string `json:"query,omitempty"`
	// Since is the time bound this source actually applied. A request that
	// asked for one and gets evidence back without it has been answered from
	// unfiltered data, which for a time-scoped question is wrong in the
	// direction that reads as right.
	Since string `json:"since,omitempty"`
	// Until is the upper bound applied. Without one a window is a ray: a
	// request for issues on a single past day returned everything from that day
	// to now, sorted by recency, so the answer described today.
	Until string `json:"until,omitempty"`
	// Match, Severity, and State record the selectors the source actually
	// applied, for the same reason Since is recorded: a request narrowed by a
	// filter reads its result as narrow. If a filter was asked for and does not
	// appear here, it was not applied, and the rows describe a wider question
	// than the one asked.
	Match    string `json:"match,omitempty"`
	Severity string `json:"severity,omitempty"`
	State    string `json:"state,omitempty"`
	// Ordering records which end of the matching set the items came from, for
	// the same reason Since is recorded. A truncated page is a sample, and a
	// sample with an undeclared ordering reads as representative. Asked which
	// tickets had waited longest, a model was handed the hundred most recent
	// of several hundred, picked the earliest among them, and answered with
	// perfect reasoning over evidence that excluded every ticket it was asked
	// about.
	Ordering    string    `json:"ordering,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
	DurationMS  int64     `json:"duration_ms"`
	ItemCount   int       `json:"item_count"`
	// TotalAvailable is what the source reported as the full result size, when
	// it reports one. A value larger than ItemCount means the plan's limit
	// bounded the evidence, which a synthesizing model needs to know before it
	// characterizes a fleet.
	TotalAvailable int `json:"total_available,omitempty"`
	// Summary holds aggregate counts computed here, in code, rather than left
	// for a model to tally from Items. A model asked to count several hundred
	// records will sometimes get it wrong and state the wrong number with
	// confidence, so any population-level claim must come from this field.
	Summary map[string]int `json:"summary,omitempty"`
	// Warnings name checks that did not run, in words rather than as a missing
	// key. A count that was never computed is not zero, and every mechanism
	// that expressed this by omission has been resolved the reassuring way:
	// asked which critical agents were down with no critical groups
	// configured, a model answered "no critical agents are disconnected",
	// which was posted to a channel while five of them were.
	//
	// A warning is a defect in the answer, not a footnote to it.
	Warnings []string `json:"warnings,omitempty"`
	// Breakdown holds named aggregate tables computed here, in code, over every
	// matching row rather than over the returned page.
	//
	// It exists because a large result is not answerable by showing more of it.
	// Asked which systems were degraded one morning, the only available reply
	// was the newest 25 of 1,200 events, which named a handful of hosts and
	// implied the rest were fine. The rows cannot be widened far enough to fix
	// that -- 1,200 of them would overrun the evidence budget and be discarded
	// whole -- but the question was never about the rows. It was "which hosts,
	// and how many each", and that is a table code can compute exactly.
	Breakdown map[string]map[string]int `json:"breakdown,omitempty"`
	Truncated bool                      `json:"truncated"`
	// Data carries a policy-approved endpoint-agent result whose shape depends
	// on the fixed operation. Unlike the vendor connectors, the agent already
	// returns bounded, normalized JSON; re-encoding it into synthetic rows
	// would obscure the path, content, or list entries an operator asked for.
	Data  any            `json:"data,omitempty"`
	Items []EvidenceItem `json:"items"`
}

// EvidenceItem is one normalized record. Connectors map source-specific
// payloads onto this shape so that a model never sees a raw vendor response.
type EvidenceItem struct {
	ID          string            `json:"id"`
	Host        string            `json:"host,omitempty"`
	Description string            `json:"description"`
	Severity    string            `json:"severity,omitempty"`
	State       string            `json:"state,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
}

// ConnectorError distinguishes failure classes so callers can decide whether
// a step is retryable without parsing error strings.
type ConnectorError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ConnectorError) Error() string {
	return e.Code + ": " + e.Message
}

func newConnectorError(code, message string) *ConnectorError {
	return &ConnectorError{Code: code, Message: message}
}
