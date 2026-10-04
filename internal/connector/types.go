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
// Provenance fields let an answer say where a claim came from, and let the
// audit record be written without re-deriving the request.
//
// The filter fields (Since through Owner) record what the source actually
// applied. A filter that was asked for and is missing here was not applied,
// and the rows answer a wider question than the one asked.
type Evidence struct {
	Source   string `json:"source"`
	Action   string `json:"action"`
	Endpoint string `json:"endpoint"`
	// Query is the statement that ran, when the model wrote it, so a reader
	// can check how a number was derived.
	Query string `json:"query,omitempty"`
	// Since is the lower time bound applied.
	Since string `json:"since,omitempty"`
	// Until is the upper time bound applied. Without it a window on a past
	// day runs to now, and a newest-first page describes today.
	Until    string `json:"until,omitempty"`
	Match    string `json:"match,omitempty"`
	Severity string `json:"severity,omitempty"`
	State    string `json:"state,omitempty"`
	Host     string `json:"host_filter,omitempty"`
	Owner    string `json:"owner_filter,omitempty"`
	// Queues and Status are set only when the request narrowed them; absent
	// means every allowlisted queue and new/open/stalled.
	Queues []string `json:"queue_filter,omitempty"`
	Status string   `json:"status_filter,omitempty"`
	// Ordering says which end of the matching set a truncated page came from.
	// Without it a newest-first page reads as representative, and "oldest"
	// gets answered from the newest rows.
	Ordering    string    `json:"ordering,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
	DurationMS  int64     `json:"duration_ms"`
	ItemCount   int       `json:"item_count"`
	// TotalAvailable is the full result size, when the source reports one.
	// Larger than ItemCount means the limit truncated the evidence.
	TotalAvailable int `json:"total_available,omitempty"`
	// Summary holds counts computed in code. Any population-level claim must
	// come from here: a model counting hundreds of Items gets it wrong, and
	// confidently.
	Summary map[string]int `json:"summary,omitempty"`
	// Warnings name, in words, checks that did not run or limits that shaped
	// the result. A missing key reads as zero; a count never computed is not
	// zero. A warning is a defect in the answer, not a footnote to it.
	Warnings []string `json:"warnings,omitempty"`
	// Breakdown holds named count tables computed in code over every matching
	// row, not just the returned page. A large result is answered by
	// aggregating it, not by returning more rows, which would overrun the
	// evidence budget.
	Breakdown map[string]map[string]int `json:"breakdown,omitempty"`
	// Earliest holds each group's earliest record over every matching row,
	// found by the source rather than read off a page by the model.
	Earliest  map[string]map[string]EvidenceItem `json:"earliest,omitempty"`
	Truncated bool                               `json:"truncated"`
	// Data carries a cassd agent result as-is. The agent already returns
	// bounded JSON whose shape depends on the operation; forcing it into
	// Items would obscure it.
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
