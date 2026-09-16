package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
)

const (
	rtDefaultTimeout   = 20 * time.Second
	rtMaxResponseBytes = 1 << 20
	// rtSearchFields is every field Cass will read from a ticket. Content,
	// Transactions, and CustomFields are deliberately absent: RT tickets carry
	// human correspondence, which routinely contains user PII and credentials
	// pasted into a support request, and nothing here has decided that belongs
	// in evidence handed to a model. The safe default is metadata only.
	rtSearchFields = "Subject,Status,Queue,Owner,Created,LastUpdated"

	// rtQueueNameField expands the Queue reference so RT returns the queue's
	// name alongside its id. RT 2.0 spells sub-object expansion this way, and
	// the live instance was checked before this was relied on.
	rtQueueNameField = "fields[Queue]"
	// maxRTQueueCensus bounds the per-queue breakdown fan-out. A queue
	// allowlist is operator-curated and expected to be short; a long one is a
	// configuration smell, not something to fan requests across silently.
	maxRTQueueCensus = 20
	// maxRTOwnerCensus bounds the per-owner breakdown fan-out. Unlike queues,
	// owners are not operator-curated -- they are discovered from whichever
	// tickets came back -- so this exists purely to cap the round-trip cost,
	// not to reflect a configuration decision.
	maxRTOwnerCensus = 20
)

// rtActions is the fixed action table. A plan may only name an action that
// appears here, so neither a client nor a model can reach an arbitrary
// endpoint. This matters more for RT than for read-only telemetry: RT can
// modify tickets, comment on them, and reassign ownership, and the only
// reliable way to keep those operations unreachable is to never compile them
// in. There is deliberately no ticket.comment, ticket.update, or
// ticket.create here.
var rtActions = map[string]string{
	"tickets.search": "/REST/2.0/tickets",
}

// RTConfig carries operator-supplied execution details. None of these are
// derived from a route plan.
type RTConfig struct {
	Endpoint string
	Token    string
	// Queues allowlists which RT queues are searchable. Empty means none: a
	// connector with no configured queues cannot search RT at all, rather
	// than searching every queue an operator never reviewed.
	Queues []string
	// Location is the zone RT parses a bare date literal in. Defaults to the
	// host's local zone, which is the right guess when RT and Cass sit at
	// the same institution, and is explicit here so a test can pin it and a
	// reader can see there is an assumption at all.
	Location         *time.Location
	Timeout          time.Duration
	MaxResponseBytes int64
}

// RTConnector executes rt-api route steps against Request Tracker's REST 2.0
// API.
//
// It returns ticket metadata only -- subject, queue, status, owner, and
// dates. Ticket content and transaction history never reach evidence; that is
// a deliberate scope decision, not an oversight to fix later. See
// docs/adding-a-connector.md, "How sensitive is the content?".
type RTConnector struct {
	location         *time.Location
	endpoint         string
	token            string
	queues           []string
	maxResponseBytes int64
	client           *http.Client
}

// NewRTConnector validates configuration and returns a connector.
func NewRTConnector(config RTConfig) (*RTConnector, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("rt endpoint is required")
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse rt endpoint: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("rt endpoint must be http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("rt endpoint must include a host")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("rt token is required")
	}

	queues := make([]string, 0, len(config.Queues))
	for _, queue := range config.Queues {
		if queue = strings.TrimSpace(queue); queue != "" {
			queues = append(queues, queue)
		}
	}
	if len(queues) == 0 {
		return nil, fmt.Errorf("rt requires at least one allowed queue; an empty allowlist searches nothing")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = rtDefaultTimeout
	}
	maxBytes := config.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = rtMaxResponseBytes
	}

	location := config.Location
	if location == nil {
		location = time.Local
	}

	return &RTConnector{
		location:         location,
		endpoint:         strings.TrimRight(config.Endpoint, "/"),
		token:            config.Token,
		queues:           queues,
		maxResponseBytes: maxBytes,
		client:           &http.Client{Timeout: timeout},
	}, nil
}

// Source reports which route-step source this connector serves.
func (c *RTConnector) Source() broker.Source {
	return broker.SourceRequestTracker
}

// Execute runs one route step and returns normalized evidence.
func (c *RTConnector) Execute(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Source != broker.SourceRequestTracker {
		return Evidence{}, newConnectorError("wrong_source", "step is not an rt-api step")
	}
	if _, ok := rtActions[step.Action]; !ok {
		return Evidence{}, newConnectorError("unsupported_action", fmt.Sprintf("action %q is not executable", step.Action))
	}

	limit := step.Limit
	if limit <= 0 {
		limit = 100
	}

	// Created never moves retroactively, unlike a Wazuh agent's last-contact
	// time or a Zabbix trigger's last-changed time: bounding by it narrows
	// which open tickets are in view without ever hiding one that is still
	// open. RT computes the exact count for the bounded query itself, so
	// "how many tickets older than 60 days" never has to be answered by
	// counting dates off a truncated page.
	since, err := rtDateBound(step.Since, c.location)
	if err != nil {
		return Evidence{}, err
	}
	until, err := rtDateBound(step.Until, c.location)
	if err != nil {
		return Evidence{}, err
	}

	query := ticketSearchQuery(step.Host, "", since, until, c.queues)
	requestedAt := time.Now().UTC()
	items, total, err := c.search(ctx, query, limit)
	if err != nil {
		return Evidence{}, err
	}

	summary := map[string]int{
		"returned":       len(items),
		"total_matching": total,
	}

	evidence := Evidence{
		Source:         string(broker.SourceRequestTracker),
		Action:         step.Action,
		Endpoint:       redactEndpoint(c.endpoint),
		Query:          query,
		Since:          step.Since,
		Until:          step.Until,
		RequestedAt:    requestedAt,
		DurationMS:     time.Since(requestedAt).Milliseconds(),
		ItemCount:      len(items),
		TotalAvailable: total,
		Truncated:      total > len(items),
		Summary:        summary,
		Items:          items,
	}

	if len(c.queues) > maxRTQueueCensus {
		evidence.Warnings = append(evidence.Warnings, fmt.Sprintf(
			"tickets_by_queue was not computed: %d queues are configured, more than the %d this connector "+
				"will fan a single search out across", len(c.queues), maxRTQueueCensus))
	} else {
		breakdown, err := c.queueCensus(ctx, step.Host, since, until)
		if err != nil {
			return Evidence{}, err
		}
		evidence.Breakdown = map[string]map[string]int{"tickets_by_queue": breakdown}
	}

	// Owners are discovered from the page rather than configured, so in
	// general the breakdown is only a census over what this fetch happened to
	// see. But each owner's count comes from RT directly, not from the page,
	// and Owner is single-valued per ticket -- so if the counts already sum to
	// every matching ticket, no owner outside the discovered set can exist,
	// and the breakdown is exactly as complete as tickets_by_queue is. This is
	// the same reasoning the Zabbix connector uses for its severity census:
	// severities partition the result, so their sum needs no separate total
	// call to be trusted as exact.
	owners, ownersCapped := ownersOnPage(items)
	if len(owners) > 0 {
		breakdown, err := c.ownerCensus(ctx, owners, step.Host, since, until)
		if err != nil {
			return Evidence{}, err
		}
		if evidence.Breakdown == nil {
			evidence.Breakdown = make(map[string]map[string]int, 1)
		}
		evidence.Breakdown["tickets_by_owner"] = breakdown

		accounted := 0
		for _, count := range breakdown {
			accounted += count
		}
		switch {
		case ownersCapped:
			evidence.Warnings = append(evidence.Warnings, fmt.Sprintf(
				"tickets_by_owner covers only the first %d distinct owners seen on this page; "+
					"%d matching ticket(s) belong to owners not accounted for above",
				maxRTOwnerCensus, total-accounted))
		case accounted < total:
			evidence.Warnings = append(evidence.Warnings, fmt.Sprintf(
				"tickets_by_owner accounts for %d of %d matching tickets; the other %d belong to owners "+
					"with no ticket on this returned page, so they were never discovered -- "+
					"report these counts as a floor, never as the full distribution",
				accounted, total, total-accounted))
		default:
			// Every matching ticket's owner was discovered and counted exactly,
			// so the breakdown is complete even though the page itself was
			// truncated: no warning is a claim, not an omission.
		}
	}

	return evidence, nil
}

// rtDateBound converts a broker-normalized RFC 3339 time bound into the
// literal RT's TicketSQL date comparison expects. Empty stays empty: an
// unset bound must not become a comparison against the zero time.
func rtDateBound(value string, loc *time.Location) (string, error) {
	if value == "" {
		return "", nil
	}
	moment, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return "", newConnectorError("invalid_time_bound", err.Error())
	}
	// Rendered in local time, because RT parses a bare date literal in the
	// server's zone while returning Created in UTC. A ticket created at
	// 2026-09-03T07:49:10Z matches Created > '2026-09-03 00:00:00' and not
	// Created > '2026-09-03 04:00:00', which is only true if the literal is
	// read as 03:49 local.
	//
	// This was masked until 8e52f8c. The broker used to hand over a local
	// calendar date stamped midnight UTC, which formatted to local midnight
	// here and was right by accident. Fixing the broker to resolve a real
	// local day moved this bound four hours late, and "how many tickets were
	// submitted today" answered 21 against a true 22, missing one filed at
	// 03:49 in the morning.
	//
	// RT and the host running Cass are both America/New_York, and RT's half
	// of that was measured rather than assumed. Ticket 111093, created
	// 2026-01-10T06:30:07Z, matches Created > '2026-01-10 01:00:00' and not
	// '2026-01-10 02:00:00', so RT read it as 01:30 local: offset -5 in
	// January. In September the offset was -4. RT observes daylight saving and
	// follows US Eastern.
	//
	// If RT ever moves zone, this is where it breaks, and the symptom is a
	// bound wrong by exactly the offset between them -- which is invisible in
	// any test that pins both sides to the same location.
	return moment.In(loc).Format("2006-01-02 15:04:05"), nil
}

// search runs one bounded ticket search and returns normalized items plus the
// true count RT reports for the query, not just the page.
func (c *RTConnector) search(ctx context.Context, query string, limit int) ([]EvidenceItem, int, error) {
	values := url.Values{}
	values.Set("query", query)
	values.Set("fields", rtSearchFields)
	// Without this RT returns Queue as a bare reference and the only readable
	// thing in it is a numeric id. Evidence then names "queue 10" where an
	// operator, and every other part of this connector, means "alerts".
	values.Set(rtQueueNameField, "Name")
	values.Set("per_page", strconv.Itoa(limit))
	// Newest first: a reader asking what is open wants the most recent activity
	// at the top, not whatever order the ticket IDs happen to sort in.
	values.Set("orderby", "-Created")

	body, status, err := c.get(ctx, "/REST/2.0/tickets", values)
	if err != nil {
		return nil, 0, err
	}
	if status != http.StatusOK {
		return nil, 0, rtStatusError(status, body)
	}

	var envelope rtSearchResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, 0, newConnectorError("decode_response", err.Error())
	}

	items := make([]EvidenceItem, 0, len(envelope.Items))
	for _, ticket := range envelope.Items {
		items = append(items, normalizeTicket(ticket))
	}
	return items, envelope.Total, nil
}

// queueCensus counts matching tickets per allowlisted queue, so an answer can
// say where the open work actually is rather than only how much of it there
// is. It costs one extra round trip per queue, bounded by maxRTQueueCensus,
// the same trade the Zabbix connector makes for its own per-host breakdown.
func (c *RTConnector) queueCensus(ctx context.Context, host, since, until string) (map[string]int, error) {
	counts := make(map[string]int, len(c.queues))
	for _, queue := range c.queues {
		values := url.Values{}
		values.Set("query", ticketSearchQuery(host, "", since, until, []string{queue}))
		values.Set("per_page", "1")

		body, status, err := c.get(ctx, "/REST/2.0/tickets", values)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, rtStatusError(status, body)
		}
		var envelope struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, newConnectorError("decode_response", err.Error())
		}
		if envelope.Total > 0 {
			counts[queue] = envelope.Total
		}
	}
	return counts, nil
}

// ownersOnPage lists the distinct ticket owners present in a fetched page, in
// first-seen order, capped at maxRTOwnerCensus. Unlike the queue allowlist
// this is not configuration -- it is only ever what happened to come back on
// this one fetch, which is exactly what the caller must warn about when the
// page was truncated.
func ownersOnPage(items []EvidenceItem) (owners []string, capped bool) {
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		owner := item.Fields["owner"]
		if owner == "" {
			continue
		}
		if _, ok := seen[owner]; ok {
			continue
		}
		seen[owner] = struct{}{}
		owners = append(owners, owner)
	}
	if len(owners) > maxRTOwnerCensus {
		owners = owners[:maxRTOwnerCensus]
		capped = true
	}
	return owners, capped
}

// ownerCensus counts matching tickets per discovered owner, the same
// exact-count-via-a-narrower-search technique queueCensus uses, applied to a
// set this connector discovered rather than one an operator configured.
func (c *RTConnector) ownerCensus(ctx context.Context, owners []string, host, since, until string) (map[string]int, error) {
	counts := make(map[string]int, len(owners))
	for _, owner := range owners {
		values := url.Values{}
		values.Set("query", ticketSearchQuery(host, owner, since, until, c.queues))
		values.Set("per_page", "1")

		body, status, err := c.get(ctx, "/REST/2.0/tickets", values)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, rtStatusError(status, body)
		}
		var envelope struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, newConnectorError("decode_response", err.Error())
		}
		if envelope.Total > 0 {
			counts[owner] = envelope.Total
		}
	}
	return counts, nil
}

// get performs the bounded HTTP round trip and returns the response body and
// status, leaving status interpretation to the caller.
func (c *RTConnector) get(ctx context.Context, path string, query url.Values) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path+"?"+query.Encode(), nil)
	if err != nil {
		return nil, 0, newConnectorError("build_request", err.Error())
	}
	request.Header.Set("Authorization", "token "+c.token)
	request.Header.Set("Accept", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return nil, 0, newConnectorError("transport", err.Error())
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, 0, newConnectorError("read_response", err.Error())
	}
	if int64(len(body)) > c.maxResponseBytes {
		return nil, 0, newConnectorError("response_too_large", fmt.Sprintf("response exceeded %d bytes", c.maxResponseBytes))
	}
	return body, response.StatusCode, nil
}

// rtStatusError classifies a non-200 RT response. Authentication failures get
// their own code so a caller can tell "credential rejected" from "the request
// itself was malformed" without parsing prose.
func rtStatusError(status int, body []byte) error {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return newConnectorError("authentication_failed", fmt.Sprintf("rt returned HTTP %d", status))
	}
	message := strings.TrimSpace(string(body))
	var envelope struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Message != "" {
		message = envelope.Message
	}
	if len(message) > 200 {
		message = message[:200]
	}
	return newConnectorError("http_status", fmt.Sprintf("rt returned HTTP %d: %s", status, message))
}

// ticketSearchQuery composes RT's TicketSQL server-side, from the host the
// broker already validated and the operator's queue allowlist. Neither a
// model nor a plan supplies this string directly: it is built here from
// values that already passed policy, the same separation the Zabbix and
// Wazuh connectors keep between an authorized request and the query that
// implements it.
// owner narrows to one ticket owner, used by ownerCensus; empty means every
// owner. since and until are RT-formatted date literals (see rtDateBound),
// already bounded and normalized by the broker before this function ever
// sees them -- never raw request text.
func ticketSearchQuery(host, owner, since, until string, queues []string) string {
	// New, open, and stalled are RT's active statuses. Resolved, rejected, and
	// deleted tickets are excluded: "what is open" means work nobody has
	// closed out, not a full history of the queue.
	parts := []string{"(Status = 'new' OR Status = 'open' OR Status = 'stalled')"}
	if len(queues) > 0 {
		queueParts := make([]string, 0, len(queues))
		for _, queue := range queues {
			queueParts = append(queueParts, fmt.Sprintf("Queue = '%s'", rtEscape(queue)))
		}
		parts = append(parts, "("+strings.Join(queueParts, " OR ")+")")
	}
	if host != "" {
		// Subject only, not Content: matching against ticket body text would
		// require RT to search correspondence to decide relevance, which is a
		// different sensitivity decision than filtering by subject line and one
		// this connector does not make silently.
		parts = append(parts, fmt.Sprintf("Subject LIKE '%s'", rtEscape(host)))
	}
	if owner != "" {
		parts = append(parts, fmt.Sprintf("Owner = '%s'", rtEscape(owner)))
	}
	if since != "" {
		parts = append(parts, fmt.Sprintf("Created > '%s'", since))
	}
	if until != "" {
		parts = append(parts, fmt.Sprintf("Created < '%s'", until))
	}
	return strings.Join(parts, " AND ")
}

// rtEscape escapes a value for RT's TicketSQL string literal syntax. Every
// value that reaches this function has already passed broker host validation
// or comes from operator configuration, so this is defense in depth rather
// than the only thing standing between a caller and a malformed query.
func rtEscape(value string) string {
	return strings.ReplaceAll(value, "'", "\\'")
}

// rtRef decodes an RT REST 2.0 reference value, which the API renders as a
// plain string for some fields and as a hyperlink object, {"id": "...", ...},
// for reference fields such as Queue and Owner. Deciding this from the shape
// of the response rather than assuming one form keeps the connector correct
// across RT versions that differ here.
type rtRef string

func (r *rtRef) UnmarshalJSON(data []byte) error {
	var plain string
	if err := json.Unmarshal(data, &plain); err == nil {
		*r = rtRef(plain)
		return nil
	}
	var object struct {
		ID   string `json:"id"`
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	// Name when RT expanded the reference, id otherwise. A queue id is a
	// number and means nothing to a reader; a user id is already the login
	// name, which is why Owner needs no expansion and still reads correctly.
	if object.Name != "" {
		*r = rtRef(object.Name)
		return nil
	}
	*r = rtRef(object.ID)
	return nil
}

// rtTicket mirrors only the fields this connector requests. Additional
// fields in a response are ignored rather than rejected, because the remote
// API may add fields without our involvement.
type rtTicket struct {
	ID          rtRef  `json:"id"`
	Subject     string `json:"Subject"`
	Status      string `json:"Status"`
	Queue       rtRef  `json:"Queue"`
	Owner       rtRef  `json:"Owner"`
	Created     string `json:"Created"`
	LastUpdated string `json:"LastUpdated"`
}

type rtSearchResponse struct {
	Total int        `json:"total"`
	Items []rtTicket `json:"items"`
}

// normalizeTicket maps an RT ticket onto EvidenceItem. Only metadata crosses
// this boundary: no Content, no Transactions, no CustomFields.
func normalizeTicket(ticket rtTicket) EvidenceItem {
	fields := map[string]string{}
	if ticket.Queue != "" {
		fields["queue"] = string(ticket.Queue)
	}
	if ticket.Owner != "" {
		fields["owner"] = string(ticket.Owner)
	}
	if ticket.Created != "" {
		fields["created"] = ticket.Created
	}
	if ticket.LastUpdated != "" {
		fields["last_updated"] = ticket.LastUpdated
	}
	return EvidenceItem{
		ID:          strings.TrimPrefix(string(ticket.ID), "ticket/"),
		Description: ticket.Subject,
		State:       ticket.Status,
		Fields:      fields,
	}
}
