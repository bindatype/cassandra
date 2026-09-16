package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
)

const (
	zabbixDefaultTimeout   = 15 * time.Second
	zabbixMaxResponseBytes = 1 << 20
	zabbixMaxLimit         = 500
	// maxCensusRows bounds the severity census. It returns one small integer
	// per matching row, so a few thousand is cheap, but it must still be
	// bounded: an unbounded fetch is the thing every other limit here prevents.
	maxCensusRows = 20000
	// maxHostCensusRows bounds the per-host breakdown. It carries a host object
	// per row rather than a single integer, so it costs several times what the
	// severity census does and cannot share its ceiling without risking the
	// response cap -- which fails the whole step rather than shortening it.
	maxHostCensusRows = 5000
	// maxBreakdownHosts keeps the breakdown itself from becoming the thing that
	// overruns the evidence budget. The hosts that matter are the ones with the
	// most events; the tail is reported as a count, not as names.
	maxBreakdownHosts = 25
)

// zabbixMethods is the fixed action table. A plan may only name an action that
// appears here, so neither a client nor a model can select an arbitrary Zabbix
// API method.
var zabbixMethods = map[string]string{
	"trigger.get": "trigger.get",
	// The event log. trigger.get reports which triggers are firing now and when
	// each last changed state, which cannot answer what happened on a past day:
	// 21 May had no trigger whose state last changed then, and 5011 events.
	"event.get": "event.get",
}

// ZabbixConfig carries operator-supplied execution details. None of these are
// derived from a route plan.
type ZabbixConfig struct {
	Endpoint         string
	Token            string
	Timeout          time.Duration
	MaxResponseBytes int64
}

// ZabbixConnector executes zabbix-api route steps.
type ZabbixConnector struct {
	endpoint         string
	token            string
	maxResponseBytes int64
	client           *http.Client
}

// NewZabbixConnector validates configuration and returns a connector.
func NewZabbixConnector(config ZabbixConfig) (*ZabbixConnector, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("zabbix endpoint is required")
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse zabbix endpoint: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("zabbix endpoint must be http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("zabbix endpoint must include a host")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("zabbix token is required")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = zabbixDefaultTimeout
	}
	maxBytes := config.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = zabbixMaxResponseBytes
	}

	return &ZabbixConnector{
		endpoint:         config.Endpoint,
		token:            config.Token,
		maxResponseBytes: maxBytes,
		client:           &http.Client{Timeout: timeout},
	}, nil
}

// Source reports which route-step source this connector serves.
func (c *ZabbixConnector) Source() broker.Source {
	return broker.SourceZabbixAPI
}

// Execute runs one route step and returns normalized evidence.
func (c *ZabbixConnector) Execute(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Source != broker.SourceZabbixAPI {
		return Evidence{}, newConnectorError("wrong_source", "step is not a zabbix-api step")
	}
	method, ok := zabbixMethods[step.Action]
	if !ok {
		return Evidence{}, newConnectorError("unsupported_action", fmt.Sprintf("action %q is not executable", step.Action))
	}

	limit := step.Limit
	if limit <= 0 || limit > zabbixMaxLimit {
		limit = zabbixMaxLimit
	}

	if method == "event.get" {
		return c.executeEvents(ctx, step, limit)
	}

	params := map[string]any{
		"output":      []string{"triggerid", "description", "priority", "value", "lastchange"},
		"selectHosts": []string{"host"},
		// Without this, trigger descriptions come back with unresolved macros
		// such as {HOST.NAME}, which a model will faithfully recite at a reader.
		"expandDescription": true,
		"only_true":         true,
		"monitored":         true,
		"skipDependent":     true,
		"sortfield":         "priority",
		"sortorder":         "DESC",
		"limit":             limit,
	}
	if step.Host != "" {
		params["host"] = step.Host
	}
	if step.Since != "" {
		moment, err := time.Parse(time.RFC3339, step.Since)
		if err != nil {
			return Evidence{}, newConnectorError("invalid_since", err.Error())
		}
		params["lastChangeSince"] = moment.Unix()
		// Severity order is wrong for a question about recency: the most severe
		// problems here have been firing since 2024, so the top of that list
		// contains nothing from today.
		params["sortfield"] = "lastchange"
	}
	if step.Until != "" {
		moment, err := time.Parse(time.RFC3339, step.Until)
		if err != nil {
			return Evidence{}, newConnectorError("invalid_until", err.Error())
		}
		params["lastChangeTill"] = moment.Unix()
	}
	if err := applySelectors(params, method, step); err != nil {
		return Evidence{}, err
	}

	requestedAt := time.Now().UTC()
	result, _, err := c.call(ctx, method, params)
	if err != nil {
		return Evidence{}, err
	}

	// Zabbix does not report how many rows matched, so a limited result is
	// indistinguishable from a complete one. Ask separately for the true count,
	// otherwise a model will state the plan's limit as though it were the
	// population.
	total, severities, err := c.census(ctx, method, params)
	if err != nil {
		return Evidence{}, err
	}

	items := normalizeTriggers(result)

	summary := summarizeTriggers(items, total, severities)
	boundedTotal := total
	if step.Host != "" && total == 0 {
		// Zero rows for a named host is ambiguous: the host may be healthy, or
		// it may not exist. Reporting "no problems" for a host Zabbix has never
		// heard of reads as an assurance about a machine we know nothing about.
		known, err := c.hostExists(ctx, step.Host)
		if err != nil {
			return Evidence{}, err
		}
		summary["host_known"] = 0
		if known {
			summary["host_known"] = 1
		}
	}

	evidence := Evidence{
		Source:         string(broker.SourceZabbixAPI),
		Action:         step.Action,
		Endpoint:       redactEndpoint(c.endpoint),
		Since:          step.Since,
		Until:          step.Until,
		Match:          step.Match,
		Severity:       step.Severity,
		RequestedAt:    requestedAt,
		DurationMS:     time.Since(requestedAt).Milliseconds(),
		ItemCount:      len(items),
		TotalAvailable: total,
		Truncated:      total > len(items),
		Summary:        summary,
		Items:          items,
	}
	if evidence.Truncated {
		if err := c.attachHostBreakdown(ctx, &evidence, method, params, total); err != nil {
			return Evidence{}, err
		}
	} else {
		countHostsInPage(&evidence)
	}
	if step.Since != "" || step.Until != "" {
		if err := c.compareAgainstNoTimeBound(ctx, &evidence, method, params, boundedTotal); err != nil {
			return Evidence{}, err
		}
	}
	return evidence, nil
}

// executeEvents answers from the event log rather than current trigger state.
func (c *ZabbixConnector) executeEvents(ctx context.Context, step broker.RouteStep, limit int) (Evidence, error) {
	params := map[string]any{
		"source":      0, // triggers
		"object":      0,
		"output":      []string{"eventid", "clock", "name", "severity", "value"},
		"selectHosts": []string{"host"},
		"sortfield":   "clock",
		"sortorder":   "DESC",
		"limit":       limit,
	}
	if step.Host != "" {
		params["host"] = step.Host
	}
	from, till, err := windowOf(step)
	if err != nil {
		return Evidence{}, err
	}
	if !from.IsZero() {
		params["time_from"] = from.Unix()
	}
	if !till.IsZero() {
		params["time_till"] = till.Unix()
	}
	if err := applySelectors(params, "event.get", step); err != nil {
		return Evidence{}, err
	}

	requestedAt := time.Now().UTC()
	payload, err := c.rawCall(ctx, "event.get", params)
	if err != nil {
		return Evidence{}, err
	}
	var envelope struct {
		Result []struct {
			EventID  string `json:"eventid"`
			Clock    string `json:"clock"`
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Value    string `json:"value"`
			Hosts    []struct {
				Host string `json:"host"`
			} `json:"hosts"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return Evidence{}, newConnectorError("decode_response", err.Error())
	}
	if envelope.Error != nil {
		return Evidence{}, newConnectorError("zabbix_error", envelope.Error.Message+": "+envelope.Error.Data)
	}

	items := make([]EvidenceItem, 0, len(envelope.Result))
	for _, event := range envelope.Result {
		host := ""
		if len(event.Hosts) > 0 {
			host = event.Hosts[0].Host
		}
		severity, ok := zabbixPriority[event.Severity]
		if !ok {
			severity = "unknown"
		}
		// value 1 is a problem starting, 0 is one resolving. Reporting both as
		// "issues" would double-count an incident that opened and closed.
		state := "resolved"
		if event.Value == "1" {
			state = "problem"
		}
		items = append(items, EvidenceItem{
			ID:          event.EventID,
			Host:        host,
			Description: event.Name,
			Severity:    severity,
			State:       state,
			Fields:      map[string]string{"occurred": formatEpoch(event.Clock)},
		})
	}

	total, severities, err := c.census(ctx, "event.get", params)
	if err != nil {
		return Evidence{}, err
	}
	summary := map[string]int{"returned": len(items), "total_matching": total}
	for severity, count := range severities {
		summary[severity] = count
	}

	evidence := Evidence{
		Source:         string(broker.SourceZabbixAPI),
		Action:         step.Action,
		Endpoint:       redactEndpoint(c.endpoint),
		Since:          step.Since,
		Until:          step.Until,
		Match:          step.Match,
		Severity:       step.Severity,
		State:          step.State,
		RequestedAt:    requestedAt,
		DurationMS:     time.Since(requestedAt).Milliseconds(),
		ItemCount:      len(items),
		TotalAvailable: total,
		Truncated:      total > len(items),
		Summary:        summary,
		Items:          items,
	}
	if evidence.Truncated {
		if err := c.attachHostBreakdown(ctx, &evidence, "event.get", params, total); err != nil {
			return Evidence{}, err
		}
	} else {
		countHostsInPage(&evidence)
	}
	return evidence, nil
}

// applySelectors adds the request's narrowing filters to a set of API
// parameters.
//
// The two methods spell the same three ideas differently, which is exactly the
// kind of detail a caller should not have to carry: trigger.get takes a
// severity floor as min_severity, event.get takes an explicit list; the
// searchable column is description on one and name on the other; and only the
// event log has a resolved state to select at all.
func applySelectors(params map[string]any, method string, step broker.RouteStep) error {
	if step.Match != "" {
		column := "description"
		if method == "event.get" {
			column = "name"
		}
		// Zabbix binds the value and wraps it in wildcards, so this is a
		// substring filter rather than a pattern language. A caller who writes
		// "*agent*" gets rows containing literal asterisks, which is to say
		// none, so the stars are stripped rather than passed through to produce
		// a confident empty result.
		//
		// On trigger.get the search runs against the stored description, while
		// expandDescription resolves macros only in what comes back. So a
		// trigger displayed as "Zabbix agent is not available on node01" is
		// stored as "... on {HOST.NAME}", and matching the literal part works
		// while matching the hostname does not. Filter by host instead.
		params["search"] = map[string]any{column: strings.Trim(step.Match, "*")}
	}
	if step.Severity != "" {
		floor, ok := broker.SeverityFloor(step.Severity)
		if !ok {
			return newConnectorError("invalid_severity", fmt.Sprintf("severity %q is not a known level", step.Severity))
		}
		if method == "event.get" {
			levels := make([]int, 0, 6)
			for level := floor; level <= 5; level++ {
				levels = append(levels, level)
			}
			params["severities"] = levels
		} else {
			params["min_severity"] = floor
		}
	}
	if step.State != "" {
		if method != "event.get" {
			return newConnectorError("unsupported_filter", "only the event log records a resolved state")
		}
		// 1 is a problem starting, 0 is one resolving.
		value := 1
		if step.State == broker.StateResolved {
			value = 0
		}
		params["value"] = []int{value}
	}
	return nil
}

// countMatching asks Zabbix how many rows match, without fetching any.
//
// countOutput is answered from the database and has no row ceiling of its own,
// which is the whole reason to prefer it over counting what came back.
func (c *ZabbixConnector) countMatching(ctx context.Context, method string, params map[string]any) (int, error) {
	countParams := make(map[string]any, len(params)+1)
	for key, value := range params {
		switch key {
		case "limit", "output", "sortfield", "sortorder", "selectHosts", "expandDescription":
			continue
		}
		countParams[key] = value
	}
	countParams["countOutput"] = true

	payload, err := c.rawCall(ctx, method, countParams)
	if err != nil {
		return 0, err
	}
	var envelope struct {
		// Zabbix returns countOutput as a JSON string, not a number.
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return 0, newConnectorError("decode_response", err.Error())
	}
	if envelope.Error != nil {
		return 0, newConnectorError("zabbix_error", envelope.Error.Message+": "+envelope.Error.Data)
	}
	count, err := strconv.Atoi(envelope.Result)
	if err != nil {
		return 0, newConnectorError("decode_response", "countOutput was not a number: "+envelope.Result)
	}
	return count, nil
}

// compareAgainstNoTimeBound reports how many problems match once the time bound
// is removed.
//
// A bound on trigger.get is applied to lastchange, so what it selects is
// "changed state inside the window and is still firing". A problem that began
// before the window and is still firing is excluded by it -- and its absence
// reads as health. Asked whether any host had lost its Zabbix agent since 05:00,
// the model bounded a current-state query to today and answered "no host has
// lost its Zabbix agent" while 19 were down; the same query without the bound
// returned all 19.
//
// This is the trap fleet.inventory refuses outright. It cannot be refused here,
// because "what started failing today" is a real question and this is how it is
// asked. So the comparison is computed instead: the model is told what it
// filtered out, rather than being left to infer it from a zero.
func (c *ZabbixConnector) compareAgainstNoTimeBound(ctx context.Context, evidence *Evidence, method string, params map[string]any, bounded int) error {
	unbounded := make(map[string]any, len(params))
	for key, value := range params {
		switch key {
		case "lastChangeSince", "lastChangeTill", "time_from", "time_till":
			continue
		}
		unbounded[key] = value
	}
	total, err := c.countMatching(ctx, method, unbounded)
	if err != nil {
		return err
	}
	evidence.Summary["total_ignoring_time_bound"] = total
	if total > bounded {
		evidence.Warnings = append(evidence.Warnings, fmt.Sprintf(
			"the time bound selects problems whose state CHANGED in the window, so it excluded %d "+
				"problem(s) that began earlier and are still firing now; %d match the window against %d "+
				"currently firing in total. For \"what is still broken\" ask again with no since or until, "+
				"and never report the bounded count as the number of problems",
			total-bounded, bounded, total))
	}
	return nil
}

// hostCensus counts matching rows by host.
//
// It runs only when the page is short of the population, because that is the
// only time it changes an answer: when every matching row is already in the
// evidence, a model can be trusted to read the hosts off them, and the extra
// round trip buys nothing.
//
// The subset it examines is the most recent maxHostCensusRows, ordered
// explicitly rather than left to the server, so that a capped census can be
// described precisely instead of being reported as though it covered
// everything.
func (c *ZabbixConnector) hostCensus(ctx context.Context, method string, params map[string]any) (map[string]int, int, error) {
	censusParams := make(map[string]any, len(params))
	for key, value := range params {
		switch key {
		case "limit", "output", "sortfield", "sortorder", "selectHosts", "expandDescription":
			continue
		}
		censusParams[key] = value
	}
	censusParams["output"] = []string{"triggerid"}
	censusParams["sortfield"] = "lastchange"
	if method == "event.get" {
		censusParams["output"] = []string{"eventid"}
		censusParams["sortfield"] = "clock"
	}
	censusParams["sortorder"] = "DESC"
	censusParams["selectHosts"] = []string{"host"}
	censusParams["limit"] = maxHostCensusRows

	payload, err := c.rawCall(ctx, method, censusParams)
	if err != nil {
		return nil, 0, err
	}
	var envelope struct {
		Result []struct {
			Hosts []struct {
				Host string `json:"host"`
			} `json:"hosts"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, 0, newConnectorError("decode_response", err.Error())
	}
	if envelope.Error != nil {
		return nil, 0, newConnectorError("zabbix_error", envelope.Error.Message+": "+envelope.Error.Data)
	}

	counts := make(map[string]int)
	for _, row := range envelope.Result {
		host := "unknown"
		if len(row.Hosts) > 0 {
			host = row.Hosts[0].Host
		}
		counts[host]++
	}
	return counts, len(envelope.Result), nil
}

// topHosts trims a host census to the busiest maxBreakdownHosts entries.
//
// Ties are broken by name so that two runs over the same data produce the same
// table; an aggregate that reshuffles between runs invites a reader to see
// movement that is not there.
func topHosts(counts map[string]int) map[string]int {
	if len(counts) <= maxBreakdownHosts {
		return counts
	}
	type entry struct {
		host  string
		count int
	}
	entries := make([]entry, 0, len(counts))
	for host, count := range counts {
		entries = append(entries, entry{host, count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].host < entries[j].host
	})
	trimmed := make(map[string]int, maxBreakdownHosts)
	for _, e := range entries[:maxBreakdownHosts] {
		trimmed[e.host] = e.count
	}
	return trimmed
}

// attachHostBreakdown runs the host census and records it, together with a
// warning whenever the census itself was capped -- because a partial breakdown
// presented as a whole one is a more convincing wrong answer than no breakdown
// at all.
// countHostsInPage fills hosts_affected from the returned rows.
//
// It is exact only when the page holds every matching row, which is the one
// case the host census deliberately skips. Asked which hosts had lost their
// agent, a model was handed 19 complete rows, counted the distinct hosts by
// eye, and reported "19 triggers" above a list of 14 names without reconciling
// them. Nothing was wrong and the answer still had to be puzzled over; the
// count is free here.
func countHostsInPage(evidence *Evidence) {
	hosts := make(map[string]struct{}, len(evidence.Items))
	for _, item := range evidence.Items {
		if item.Host != "" {
			hosts[item.Host] = struct{}{}
		}
	}
	evidence.Summary["hosts_affected"] = len(hosts)
}

func (c *ZabbixConnector) attachHostBreakdown(ctx context.Context, evidence *Evidence, method string, params map[string]any, total int) error {
	counts, examined, err := c.hostCensus(ctx, method, params)
	if err != nil {
		return err
	}
	evidence.Summary["hosts_affected"] = len(counts)
	if evidence.Breakdown == nil {
		evidence.Breakdown = make(map[string]map[string]int, 1)
	}
	evidence.Breakdown["events_by_host"] = topHosts(counts)
	if len(counts) > maxBreakdownHosts {
		evidence.Warnings = append(evidence.Warnings, fmt.Sprintf(
			"events_by_host names only the %d hosts with the most rows, of %d hosts affected; "+
				"the remainder are counted in hosts_affected but not named",
			maxBreakdownHosts, len(counts)))
	}
	if examined >= maxHostCensusRows && total > examined {
		// hosts_affected is derived from the same capped fetch, so it is a
		// floor too. Naming only the per-host counts here left the more
		// quotable number looking exact: "29 hosts affected" is the sentence a
		// reader repeats, and a host whose only rows fell outside the window is
		// missing from it entirely.
		evidence.Warnings = append(evidence.Warnings, fmt.Sprintf(
			"events_by_host and hosts_affected cover the most recent %d rows, not all %d that matched; "+
				"both the per-host counts and the count of hosts are lower bounds, "+
				"so report them as \"at least\" and never as totals",
			examined, total))
	}
	return nil
}

// windowOf parses the bounds a step carries.
func windowOf(step broker.RouteStep) (time.Time, time.Time, error) {
	var from, till time.Time
	var err error
	if step.Since != "" {
		if from, err = time.Parse(time.RFC3339, step.Since); err != nil {
			return from, till, newConnectorError("invalid_since", err.Error())
		}
	}
	if step.Until != "" {
		if till, err = time.Parse(time.RFC3339, step.Until); err != nil {
			return from, till, newConnectorError("invalid_until", err.Error())
		}
	}
	return from, till, nil
}

// census asks how many rows match the same filters, and how they break down by
// severity.
//
// It fetches only the priority column for every matching row and counts them
// here. That is one round trip rather than the countOutput call it replaces,
// and it buys the difference between "844 alerts today" and "844 alerts today,
// three of them disaster". Counting severities among the returned page instead
// describes the page, which is not what a reader asked about.
func (c *ZabbixConnector) census(ctx context.Context, method string, params map[string]any) (int, map[string]int, error) {
	censusParams := make(map[string]any, len(params))
	for key, value := range params {
		switch key {
		case "limit", "sortfield", "sortorder", "selectHosts", "expandDescription":
			continue
		}
		censusParams[key] = value
	}
	if method == "event.get" {
		censusParams["output"] = []string{"severity"}
	} else {
		censusParams["output"] = []string{"priority"}
	}
	censusParams["limit"] = maxCensusRows

	payload, err := c.rawCall(ctx, method, censusParams)
	if err != nil {
		return 0, nil, err
	}
	var envelope struct {
		Result []struct {
			Priority string `json:"priority"`
			Severity string `json:"severity"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return 0, nil, newConnectorError("decode_response", err.Error())
	}
	if envelope.Error != nil {
		return 0, nil, newConnectorError("zabbix_error", envelope.Error.Message+": "+envelope.Error.Data)
	}

	if len(envelope.Result) >= maxCensusRows {
		// The fetch hit its own ceiling, so len() is the cap rather than the
		// count. Live Zabbix had 21,296 events since 05:00 one morning against
		// a 20,000-row census, which would have been reported as a total of
		// exactly 20,000 -- a round number that is a limit wearing the costume
		// of a measurement, and the severity breakdown under it would have
		// described 20,000 of them as though it described all.
		return c.exactCensus(ctx, method, params)
	}

	counts := make(map[string]int, 6)
	for _, row := range envelope.Result {
		level := row.Priority
		if level == "" {
			level = row.Severity
		}
		severity, ok := zabbixPriority[level]
		if !ok {
			severity = "unknown"
		}
		counts[severity]++
	}
	return len(envelope.Result), counts, nil
}

// exactCensus counts each severity separately with countOutput, which Zabbix
// answers from the database without returning rows and so without any ceiling.
//
// It costs one round trip per severity, which is why it runs only when the row
// census overflows. Severities partition the result -- every event carries
// exactly one -- so their sum is the exact total, and no separate total call is
// needed.
func (c *ZabbixConnector) exactCensus(ctx context.Context, method string, params map[string]any) (int, map[string]int, error) {
	column := "priority"
	if method == "event.get" {
		column = "severity"
	}

	counts := make(map[string]int, 6)
	total := 0
	for level := 0; level <= 5; level++ {
		levelParams := make(map[string]any, len(params)+2)
		for key, value := range params {
			switch key {
			case "limit", "output", "sortfield", "sortorder", "selectHosts", "expandDescription":
				continue
			}
			levelParams[key] = value
		}
		// An exact-value filter alongside whatever floor the caller asked for.
		// The two agree rather than fight: a level below the requested floor is
		// excluded by the floor and correctly counts zero.
		levelParams["filter"] = map[string]any{column: level}
		levelParams["countOutput"] = true

		count, err := c.countMatching(ctx, method, levelParams)
		if err != nil {
			return 0, nil, err
		}
		counts[zabbixPriority[strconv.Itoa(level)]] = count
		total += count
	}
	return total, counts, nil
}

// hostExists reports whether Zabbix monitors a host by this exact name.
func (c *ZabbixConnector) hostExists(ctx context.Context, host string) (bool, error) {
	payload, err := c.rawCall(ctx, "host.get", map[string]any{
		"filter": map[string]any{"host": []string{host}},
		"output": []string{"hostid"},
		"limit":  1,
	})
	if err != nil {
		return false, err
	}
	var envelope struct {
		Result []struct {
			HostID string `json:"hostid"`
		} `json:"result"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false, newConnectorError("decode_response", err.Error())
	}
	return len(envelope.Result) > 0, nil
}

// zabbixTrigger mirrors only the fields we consume. Additional fields in a
// response are ignored rather than rejected, because the remote API may add
// fields without our involvement.
type zabbixTrigger struct {
	TriggerID   string `json:"triggerid"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Value       string `json:"value"`
	LastChange  string `json:"lastchange"`
	Hosts       []struct {
		Host string `json:"host"`
	} `json:"hosts"`
}

type zabbixEnvelope struct {
	Result []zabbixTrigger `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	} `json:"error"`
}

// rawCall performs the bounded HTTP round trip and returns the response body.
func (c *ZabbixConnector) rawCall(ctx context.Context, method string, params map[string]any) ([]byte, error) {
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
	if err != nil {
		return nil, newConnectorError("encode_request", err.Error())
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, newConnectorError("build_request", err.Error())
	}
	request.Header.Set("Content-Type", "application/json-rpc")
	request.Header.Set("Authorization", "Bearer "+c.token)

	response, err := c.client.Do(request)
	if err != nil {
		return nil, newConnectorError("transport", err.Error())
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, newConnectorError("http_status", "zabbix returned HTTP "+strconv.Itoa(response.StatusCode))
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, newConnectorError("read_response", err.Error())
	}
	if int64(len(body)) > c.maxResponseBytes {
		return nil, newConnectorError("response_too_large", fmt.Sprintf("response exceeded %d bytes", c.maxResponseBytes))
	}
	return body, nil
}

func (c *ZabbixConnector) call(ctx context.Context, method string, params map[string]any) ([]zabbixTrigger, bool, error) {
	body, err := c.rawCall(ctx, method, params)
	if err != nil {
		return nil, false, err
	}

	var envelope zabbixEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false, newConnectorError("decode_response", err.Error())
	}
	if envelope.Error != nil {
		return nil, false, newConnectorError("zabbix_error", envelope.Error.Message+": "+envelope.Error.Data)
	}
	return envelope.Result, false, nil
}

// zabbixPriority maps Zabbix numeric trigger priorities to readable severities.
var zabbixPriority = map[string]string{
	"0": "not classified",
	"1": "information",
	"2": "warning",
	"3": "average",
	"4": "high",
	"5": "disaster",
}

func normalizeTriggers(triggers []zabbixTrigger) []EvidenceItem {
	items := make([]EvidenceItem, 0, len(triggers))
	for _, trigger := range triggers {
		host := ""
		if len(trigger.Hosts) > 0 {
			host = trigger.Hosts[0].Host
		}
		severity, ok := zabbixPriority[trigger.Priority]
		if !ok {
			severity = "unknown"
		}
		state := "ok"
		if trigger.Value == "1" {
			state = "problem"
		}

		item := EvidenceItem{
			ID:          trigger.TriggerID,
			Host:        host,
			Description: trigger.Description,
			Severity:    severity,
			State:       state,
		}
		if trigger.LastChange != "" {
			// Zabbix reports epoch seconds. Passing that through unchanged
			// invites a model to repeat the raw integer at a reader, so it is
			// rendered here instead.
			item.Fields = map[string]string{"last_change": formatEpoch(trigger.LastChange)}
		}
		items = append(items, item)
	}
	return items
}

// redactEndpoint records the host a request went to without carrying any
// credential material that may sit in the URL.
func redactEndpoint(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "invalid-endpoint"
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.Path
}

// summarizeTriggers counts problems by severity so a model never has to tally
// them itself.
func summarizeTriggers(items []EvidenceItem, totalMatching int, severities map[string]int) map[string]int {
	// Severity counts describe every matching row, not the returned page. A
	// breakdown of the page answers a question nobody asked: a reader wants to
	// know how many of the 844 are disasters, not how many of the 25 shown are.
	summary := map[string]int{
		"returned":       len(items),
		"total_matching": totalMatching,
	}
	for severity, count := range severities {
		summary[severity] = count
	}
	return summary
}

// formatEpoch renders Zabbix epoch seconds as RFC 3339, leaving anything
// unparseable untouched rather than guessing.
func formatEpoch(value string) string {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return value
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}
