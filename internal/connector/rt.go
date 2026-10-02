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
	// rtSearchFields is every field Cass reads from a ticket: metadata only.
	// Content, Transactions and CustomFields are deliberately absent, because
	// correspondence routinely holds PII and pasted credentials.
	rtSearchFields = "Subject,Status,Queue,Owner,Created,LastUpdated"

	// rtQueueNameField expands the Queue reference so RT returns the queue's
	// name, not only its id (RT 2.0's sub-object expansion syntax).
	rtQueueNameField = "fields[Queue]"
	// maxRTQueueCensus bounds the per-queue fan-out. The allowlist should be
	// short; past this the breakdown is skipped with a warning.
	maxRTQueueCensus = 20
	// maxRTOwnerCensus bounds the per-owner fan-out. Owners are discovered
	// from the page, not configured, so this only caps round trips.
	maxRTOwnerCensus = 20
)

// rtActions is the fixed action table; a plan may only name an action listed
// here. RT can modify, comment on and reassign tickets, and the reliable way
// to keep that unreachable is never to compile it in: there is deliberately no
// ticket.comment, ticket.update or ticket.create.
var rtActions = map[string]string{
	"tickets.search": "/REST/2.0/tickets",
}

// RTConfig carries operator-supplied execution details. None of these are
// derived from a route plan.
type RTConfig struct {
	Endpoint string
	Token    string
	// Queues allowlists which RT queues are searchable. Empty means none, not
	// all.
	Queues []string
	// Location is the zone RT parses a bare date literal in (see rtDateBound).
	// Defaults to the host's local zone; explicit so tests can pin it.
	Location         *time.Location
	Timeout          time.Duration
	MaxResponseBytes int64
}

// RTConnector executes rt-api route steps against Request Tracker's REST 2.0
// API.
//
// It returns ticket metadata only (subject, queue, status, owner, dates).
// Content and transaction history never reach evidence, by design; see
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

	// Bounds apply to Created, which never changes, so a bound narrows which
	// open tickets are in view without hiding one that is still open (unlike
	// Zabbix lastchange or Wazuh last-contact). RT counts the bounded query
	// itself.
	since, err := rtDateBound(step.Since, c.location)
	if err != nil {
		return Evidence{}, err
	}
	until, err := rtDateBound(step.Until, c.location)
	if err != nil {
		return Evidence{}, err
	}

	query := ticketSearchQuery(step.Host, step.Owner, since, until, c.queues)
	requestedAt := time.Now().UTC()
	order := ticketOrder(since, until, step.Owner, step.Order)
	items, total, err := c.search(ctx, query, limit, order)
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
		Owner:          step.Owner,
		RequestedAt:    requestedAt,
		DurationMS:     time.Since(requestedAt).Milliseconds(),
		ItemCount:      len(items),
		TotalAvailable: total,
		Truncated:      total > len(items),
		Ordering:       orderingDescription(order),
		Summary:        summary,
		Items:          items,
	}

	// Ordering is also said in words when the page is partial: the model
	// otherwise answers "oldest" from a newest-first page.
	if evidence.Truncated {
		missing := "oldest"
		if order == "ASC" {
			missing = "most recent"
		}
		evidence.Warnings = append(evidence.Warnings, fmt.Sprintf(
			"these are the %d %s of %d matching tickets; the %s are not in this page, "+
				"so do not describe them as the extreme of any ordering other than this one",
			len(items), orderingDescription(order), total, missing))
	}

	if len(c.queues) > maxRTQueueCensus {
		evidence.Warnings = append(evidence.Warnings, fmt.Sprintf(
			"tickets_by_queue was not computed: %d queues are configured, more than the %d this connector "+
				"will fan a single search out across", len(c.queues), maxRTQueueCensus))
	} else {
		breakdown, err := c.queueCensus(ctx, step.Host, step.Owner, since, until)
		if err != nil {
			return Evidence{}, err
		}
		evidence.Breakdown = map[string]map[string]int{"tickets_by_queue": breakdown}
	}

	if step.Owner != "" && total == 0 {
		// A misspelled login and an owner with nothing open both come back
		// empty, and this token cannot look users up to tell them apart.
		evidence.Warnings = append(evidence.Warnings, fmt.Sprintf(
			"no open tickets owned by %q match this search in the allowlisted queues; an RT login that "+
				"does not exist, or is spelled differently, returns this same empty result, so check the "+
				"spelling against tickets_by_owner before reporting that this owner has none", step.Owner))
	}

	// Owners are discovered from the page, but each count comes from RT and a
	// ticket has one owner, so if the counts sum to total_matching the
	// breakdown is complete; otherwise it is a floor and says so. Skipped
	// under an owner filter, where it would only restate total_matching.
	owners, ownersCapped := ownersOnPage(items)
	if step.Owner == "" && len(owners) > 0 {
		breakdown, oldest, err := c.ownerCensus(ctx, owners, step.Host, since, until)
		if err != nil {
			return Evidence{}, err
		}
		if evidence.Breakdown == nil {
			evidence.Breakdown = make(map[string]map[string]int, 1)
		}
		evidence.Breakdown["tickets_by_owner"] = breakdown
		if len(oldest) > 0 {
			evidence.Earliest = map[string]map[string]EvidenceItem{"oldest_ticket_of_each_owner": oldest}
			// In the evidence, not only the prompt: the prompt rule alone did
			// not stop the model presenting per-owner oldest as oldest overall.
			evidence.Warnings = append(evidence.Warnings,
				"earliest.oldest_ticket_of_each_owner holds one ticket per owner, so it is not the oldest "+
					"tickets overall -- one owner can hold all of those; for \"the N oldest tickets\", ask "+
					"again with an until bound, which returns the page oldest first")
		}

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
	// Rendered in local time: RT parses a bare date literal in its own zone
	// (measured: America/New_York, with daylight saving) but returns Created
	// in UTC. If RT and this host ever differ in zone, every bound is off by
	// the difference, and tests that pin both sides to one zone won't show it.
	return moment.In(loc).Format("2006-01-02 15:04:05"), nil
}

// ticketOrder chooses which end of the matching set a truncated page shows,
// as RT's "ASC" or "DESC". An explicit order from the plan wins. Otherwise
// it is inferred from the bounds, because the connector never sees the
// question: an until-only bound ("older than") and a single owner with no
// since ("X's oldest") are oldest first; everything else is newest first.
func ticketOrder(since, until, owner, explicit string) string {
	switch explicit {
	case broker.TicketOrderOldestFirst:
		return "ASC"
	case broker.TicketOrderNewestFirst:
		return "DESC"
	}
	if since == "" && owner != "" {
		return "ASC"
	}
	if until != "" && since == "" {
		return "ASC"
	}
	return "DESC"
}

// search runs one bounded ticket search and returns normalized items plus the
// true count RT reports for the query, not just the page.
func (c *RTConnector) search(ctx context.Context, query string, limit int, order string) ([]EvidenceItem, int, error) {
	values := url.Values{}
	values.Set("query", query)
	values.Set("fields", rtSearchFields)
	// Otherwise Queue comes back as a numeric id ("queue 10", not "alerts").
	values.Set(rtQueueNameField, "Name")
	values.Set("per_page", strconv.Itoa(limit))
	// RT REST 2.0 takes field and direction as separate parameters. It
	// silently ignores `orderby=-Created` and returns an arbitrary order.
	values.Set("orderby", "Created")
	values.Set("order", order)

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

// queueCensus counts matching tickets per allowlisted queue, at one round trip
// per queue (bounded by maxRTQueueCensus).
func (c *RTConnector) queueCensus(ctx context.Context, host, owner, since, until string) (map[string]int, error) {
	counts := make(map[string]int, len(c.queues))
	for _, queue := range c.queues {
		values := url.Values{}
		values.Set("query", ticketSearchQuery(host, owner, since, until, []string{queue}))
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

// ownersOnPage lists the distinct owners on a fetched page, in first-seen
// order, capped at maxRTOwnerCensus. On a truncated page it can miss owners;
// the caller warns when that matters.
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

// ownerCensus counts matching tickets per discovered owner, one narrowed
// search each, as queueCensus does. Each search returns one ticket sorted
// oldest first, so it also yields that owner's oldest ticket at no extra cost.
func (c *RTConnector) ownerCensus(ctx context.Context, owners []string, host, since, until string) (map[string]int, map[string]EvidenceItem, error) {
	counts := make(map[string]int, len(owners))
	oldest := make(map[string]EvidenceItem, len(owners))
	for _, owner := range owners {
		values := url.Values{}
		values.Set("query", ticketSearchQuery(host, owner, since, until, c.queues))
		values.Set("fields", rtSearchFields)
		values.Set(rtQueueNameField, "Name")
		values.Set("per_page", "1")
		values.Set("orderby", "Created")
		values.Set("order", "ASC")

		body, status, err := c.get(ctx, "/REST/2.0/tickets", values)
		if err != nil {
			return nil, nil, err
		}
		if status != http.StatusOK {
			return nil, nil, rtStatusError(status, body)
		}
		var envelope rtSearchResponse
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, nil, newConnectorError("decode_response", err.Error())
		}
		if envelope.Total > 0 {
			counts[owner] = envelope.Total
			if len(envelope.Items) > 0 {
				oldest[owner] = normalizeTicket(envelope.Items[0])
			}
		}
	}
	return counts, oldest, nil
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

// ticketSearchQuery builds RT's TicketSQL here, from values that already
// passed broker policy and the operator's queue allowlist; no model or plan
// supplies the string. An empty owner means every owner. since and until are
// RT date literals from rtDateBound.
func ticketSearchQuery(host, owner, since, until string, queues []string) string {
	// RT's active statuses. Resolved, rejected and deleted are excluded.
	parts := []string{"(Status = 'new' OR Status = 'open' OR Status = 'stalled')"}
	if len(queues) > 0 {
		queueParts := make([]string, 0, len(queues))
		for _, queue := range queues {
			queueParts = append(queueParts, fmt.Sprintf("Queue = '%s'", rtEscape(queue)))
		}
		parts = append(parts, "("+strings.Join(queueParts, " OR ")+")")
	}
	if host != "" {
		// Subject only: searching Content would reach into correspondence,
		// which this connector deliberately never touches.
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

// rtEscape escapes a value for a TicketSQL string literal. Values here have
// already passed broker validation or come from configuration, so this is
// defense in depth.
func rtEscape(value string) string {
	return strings.ReplaceAll(value, "'", "\\'")
}

// rtRef decodes an RT REST 2.0 reference, which is a plain string for some
// fields and an object {"id": "...", ...} for references such as Queue and
// Owner. It goes by the response's shape, since RT versions differ.
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
	// Name when RT expanded the reference, id otherwise. A user's id is
	// already the login name, so Owner needs no expansion.
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
		// Computed here: the model's own date arithmetic on Created was off
		// by a year between two identical runs.
		if created, err := time.Parse(time.RFC3339, ticket.Created); err == nil {
			fields["age_days"] = strconv.Itoa(int(time.Since(created).Hours() / 24))
		}
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

// orderingDescription says which end of the matching set a page came from, in
// the words an answer would use rather than as a sort direction.
func orderingDescription(order string) string {
	if order == "ASC" {
		return "earliest created first"
	}
	return "most recently created first"
}
