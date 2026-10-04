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
	// maxCensusRows bounds the severity census: one small integer per row, so
	// cheap, but still bounded. Past it, exactCensus takes over.
	maxCensusRows = 20000
	// maxHostCensusRows bounds the per-host census. Each row carries a host
	// object, so it is lower than maxCensusRows to stay under the response
	// cap, which fails the whole step rather than shortening it.
	maxHostCensusRows = 5000
	// maxBreakdownHosts keeps the breakdown within the evidence budget: the
	// busiest hosts are named, the rest only counted.
	maxBreakdownHosts = 25
)

// zabbixMethods is the fixed action table. A plan may only name an action that
// appears here, so neither a client nor a model can select an arbitrary Zabbix
// API method.
var zabbixMethods = map[string]string{
	"trigger.get": "trigger.get",
	// The event log. trigger.get reports current state and each trigger's
	// last change, so it can't answer what happened on a past day.
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
		// Sort by recency: the most severe problems here have fired for years,
		// so a severity-ordered page holds nothing from the window.
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

	// Zabbix doesn't report how many rows matched, so ask separately; without
	// it a model states the page limit as the population.
	total, severities, err := c.census(ctx, method, params)
	if err != nil {
		return Evidence{}, err
	}

	items := normalizeTriggers(result)

	summary := summarizeTriggers(items, total, severities)
	boundedTotal := total
	if step.Host != "" && total == 0 {
		// Zero rows for a named host means healthy or unknown; check which
		// before it reads as an all-clear.
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
		Host:           step.Host,
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
	// event.get takes hostids, not host, and silently ignores parameters it
	// doesn't know, so a host name sent here would filter nothing.
	// (trigger.get does accept host.)
	if step.Host != "" {
		hostIDs, err := c.resolveHostIDs(ctx, step.Host)
		if err != nil {
			return Evidence{}, err
		}
		if len(hostIDs) == 0 {
			// Refuse rather than fall back to the whole cluster's events.
			return Evidence{}, newConnectorError("unknown_host",
				"zabbix does not monitor a host named "+step.Host+"; no event history can be scoped to it")
		}
		params["hostids"] = hostIDs
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
		Host:           step.Host,
		Ordering:       "newest first by event time",
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
// The two methods spell the same ideas differently: trigger.get takes
// min_severity and searches description; event.get takes a severity list and
// searches name; only event.get has a resolved state.
func applySelectors(params map[string]any, method string, step broker.RouteStep) error {
	if step.Match != "" {
		column := "description"
		if method == "event.get" {
			column = "name"
		}
		// Zabbix wraps the value in wildcards itself; literal "*" would match
		// nothing, so strip it.
		//
		// trigger.get searches the stored description, where the host is still
		// a macro ("... on {HOST.NAME}"), so matching a hostname fails. Filter
		// by host instead.
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
// countOutput is answered from the database with no row ceiling, unlike
// counting what came back.
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
// A bound on trigger.get applies to lastchange, so it selects "changed state
// in the window and still firing". A problem that started earlier and is
// still firing is excluded, and its absence reads as health. "What started
// failing today" is a real question, so the bound can't be refused as
// fleet.inventory does; instead the model is told what it filtered out.
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
// It runs only when the page is short of the population; otherwise the hosts
// are already in the evidence. It examines the most recent maxHostCensusRows,
// ordered explicitly, so a capped census can say exactly what it covered.
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
// Ties break by name so the same data gives the same table every run.
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

// countHostsInPage fills hosts_affected from the returned rows. It is used
// only when the page holds every matching row (the case hostCensus skips), so
// the count is exact.
func countHostsInPage(evidence *Evidence) {
	hosts := make(map[string]struct{}, len(evidence.Items))
	for _, item := range evidence.Items {
		if item.Host != "" {
			hosts[item.Host] = struct{}{}
		}
	}
	evidence.Summary["hosts_affected"] = len(hosts)
}

// attachHostBreakdown runs the host census and records it, with a warning
// whenever the census was capped: a partial breakdown presented as whole is
// worse than none.
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
		// hosts_affected comes from the same capped fetch, so it is a lower
		// bound too, and it is the number a reader quotes.
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
// It fetches only the priority column of every matching row and counts here:
// one round trip that gives both the total and the severity split over all
// rows, not just the page.
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
		// The fetch hit its ceiling, so len() is the cap, not the count.
		// Count exactly instead.
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
// It costs one round trip per severity, so it runs only when the row census
// overflows. Every event has exactly one severity, so the sum is the total.
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
	ids, err := c.resolveHostIDs(ctx, host)
	if err != nil {
		return false, err
	}
	return len(ids) > 0, nil
}

// resolveHostIDs turns a host name into the ids event.get filters on. An empty
// result is not an error; the caller decides what absence means.
func (c *ZabbixConnector) resolveHostIDs(ctx context.Context, host string) ([]string, error) {
	payload, err := c.rawCall(ctx, "host.get", map[string]any{
		"filter": map[string]any{"host": []string{host}},
		"output": []string{"hostid"},
	})
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Result *[]struct {
			HostID string `json:"hostid"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, newConnectorError("decode_response", err.Error())
	}
	if envelope.Error != nil {
		return nil, newConnectorError("zabbix_error", envelope.Error.Message+": "+envelope.Error.Data)
	}
	if envelope.Result == nil {
		return nil, newConnectorError("decode_response", "zabbix host.get returned no result")
	}
	ids := make([]string, 0, len(*envelope.Result))
	for _, entry := range *envelope.Result {
		if entry.HostID != "" {
			ids = append(ids, entry.HostID)
		}
	}
	return ids, nil
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
			// Render epoch seconds so the model doesn't repeat raw integers.
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
	// Severity counts describe every matching row, not the returned page.
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
