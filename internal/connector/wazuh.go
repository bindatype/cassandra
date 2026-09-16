package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
)

const (
	wazuhDefaultTimeout   = 20 * time.Second
	wazuhMaxResponseBytes = 1 << 21
	wazuhMaxLimit         = 500
	wazuhTokenTTL         = 10 * time.Minute
	wazuhAgentFields      = "id,name,ip,status,version,lastKeepAlive,group"
	// managerAgentID is the Wazuh manager's own entry. GET /agents includes it;
	// the manager's own summary endpoint does not. Excluding it from aggregate
	// counts keeps our numbers equal to what the Wazuh dashboard reports.
	managerAgentID = "000"
	// fleetItemCap bounds how many agent records travel back to the model. The
	// summary already carries exact counts for the whole fleet, so the items
	// exist to be named, not to be tallied, and 275 full records overran the
	// orchestrator's 64 KB evidence budget once group membership was added --
	// which the orchestrator answers by discarding the result whole.
	//
	// Items are ordered before the cap applies, so what survives is what a
	// reader would ask about first.
	fleetItemCap = 60
)

// wazuhActions is the fixed action table. Route plans may only name an action
// listed here, so no client or model can reach an arbitrary API path.
var wazuhActions = map[string]struct{}{
	"agents.list":   {},
	"agents.status": {},
}

// WazuhConfig carries operator-supplied execution details. None are derived
// from a route plan.
type WazuhConfig struct {
	Endpoint         string
	Username         string
	Password         string
	Timeout          time.Duration
	MaxResponseBytes int64
	// InsecureSkipVerify disables TLS verification. The RTS deployment presents
	// a self-signed certificate, so this is required in practice there, but it
	// is never the default: an operator must opt in deliberately.
	InsecureSkipVerify bool
	// CriticalGroups names the agent groups whose loss is worth escalating, and
	// is site configuration rather than a property of Wazuh: at RTS these are
	// RTS_Ops and Viper. When set, the evidence summary carries a count of
	// agents that are both disconnected and in one of these groups.
	//
	// The count is computed here rather than left to a model, for the same
	// reason every other aggregate is. Deciding which of several hundred agents
	// are both down and in a named group is arithmetic over a list, and a model
	// asked to do that gets it wrong occasionally and states the wrong number
	// with confidence.
	CriticalGroups []string
}

// WazuhConnector executes wazuh-api route steps against the manager plane.
//
// This connector deliberately speaks only to the Wazuh API on 55000, never to
// the Indexer on 9200. Inventory and status are manager-plane questions; alert
// search belongs to the Indexer and is out of scope here.
type WazuhConnector struct {
	endpoint         string
	username         string
	password         string
	maxResponseBytes int64
	client           *http.Client

	criticalGroups map[string]struct{}

	mu        sync.Mutex
	token     string
	tokenTime time.Time
}

// NewWazuhConnector validates configuration and returns a connector.
func NewWazuhConnector(config WazuhConfig) (*WazuhConnector, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("wazuh endpoint is required")
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse wazuh endpoint: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("wazuh endpoint must be http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("wazuh endpoint must include a host")
	}
	if config.Username == "" || config.Password == "" {
		return nil, fmt.Errorf("wazuh username and password are required")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = wazuhDefaultTimeout
	}
	maxBytes := config.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = wazuhMaxResponseBytes
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if config.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	critical := make(map[string]struct{}, len(config.CriticalGroups))
	for _, group := range config.CriticalGroups {
		if group = strings.TrimSpace(group); group != "" {
			// Wazuh group names are case sensitive: "RTS_Ops" and "rts_ops" are
			// not the same group, and a silently non-matching name would report
			// zero critical agents rather than an error.
			critical[group] = struct{}{}
		}
	}

	return &WazuhConnector{
		endpoint:         strings.TrimRight(config.Endpoint, "/"),
		username:         config.Username,
		password:         config.Password,
		maxResponseBytes: maxBytes,
		client:           &http.Client{Timeout: timeout, Transport: transport},
		criticalGroups:   critical,
	}, nil
}

// Source reports which route-step source this connector serves.
func (c *WazuhConnector) Source() broker.Source {
	return broker.SourceWazuhAPI
}

// Execute runs one route step and returns normalized evidence.
func (c *WazuhConnector) Execute(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Source != broker.SourceWazuhAPI {
		return Evidence{}, newConnectorError("wrong_source", "step is not a wazuh-api step")
	}
	if _, ok := wazuhActions[step.Action]; !ok {
		return Evidence{}, newConnectorError("unsupported_action", fmt.Sprintf("action %q is not executable", step.Action))
	}

	query := url.Values{}
	query.Set("select", wazuhAgentFields)

	switch step.Action {
	case "agents.list":
		limit := step.Limit
		if limit <= 0 || limit > wazuhMaxLimit {
			limit = wazuhMaxLimit
		}
		query.Set("limit", strconv.Itoa(limit))
	case "agents.status":
		if step.Host == "" {
			return Evidence{}, newConnectorError("missing_host", "agents.status requires a host")
		}
		query.Set("name", step.Host)
	}

	if step.Since != "" {
		moment, err := time.Parse(time.RFC3339, step.Since)
		if err != nil {
			return Evidence{}, newConnectorError("invalid_since", err.Error())
		}
		query.Set("q", "lastKeepAlive>"+moment.Format("2006-01-02T15:04:05Z"))
	}

	requestedAt := time.Now().UTC()
	payload, err := c.get(ctx, "/agents", query)
	if err != nil {
		return Evidence{}, err
	}

	items := normalizeAgents(payload.Data.AffectedItems, c.criticalGroups)
	if step.Action == "agents.list" && len(items) > fleetItemCap {
		items = items[:fleetItemCap]
	}
	var warnings []string
	if len(c.criticalGroups) == 0 {
		warnings = append(warnings, "critical group membership was NOT evaluated: no critical groups are "+
			"configured, so this evidence says nothing about whether critical agents are affected. "+
			"Do not report that none are.")
	}

	return Evidence{
		Source:         string(broker.SourceWazuhAPI),
		Action:         step.Action,
		Warnings:       warnings,
		Endpoint:       redactEndpoint(c.endpoint),
		Since:          step.Since,
		RequestedAt:    requestedAt,
		DurationMS:     time.Since(requestedAt).Milliseconds(),
		ItemCount:      len(items),
		TotalAvailable: payload.Data.TotalAffectedItems,
		Truncated:      payload.Data.TotalAffectedItems > len(items),
		Summary:        summarizeAgents(payload.Data.AffectedItems, c.criticalGroups),
		Items:          items,
	}, nil
}

// wazuhAgent mirrors only the fields we consume.
type wazuhAgent struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	LastKeepAlive string `json:"lastKeepAlive"`
	// Group is every group the agent belongs to. Wazuh returns an array, and an
	// agent is routinely in several: "default,RTS_Ops" is the common shape.
	Group []string `json:"group"`
}

// isCritical reports whether the agent belongs to any group an operator has
// designated critical.
func (a wazuhAgent) isCritical(critical map[string]struct{}) bool {
	for _, group := range a.Group {
		if _, found := critical[group]; found {
			return true
		}
	}
	return false
}

type wazuhEnvelope struct {
	Data struct {
		AffectedItems      []wazuhAgent `json:"affected_items"`
		TotalAffectedItems int          `json:"total_affected_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

// authenticate obtains a JWT from the manager and caches it briefly. Wazuh
// tokens are short-lived, so the cache is bounded well inside their lifetime
// rather than tracking expiry claims.
func (c *WazuhConnector) authenticate(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Since(c.tokenTime) < wazuhTokenTTL {
		return c.token, nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/security/user/authenticate?raw=true", nil)
	if err != nil {
		return "", newConnectorError("build_request", err.Error())
	}
	request.SetBasicAuth(c.username, c.password)

	response, err := c.client.Do(request)
	if err != nil {
		return "", newConnectorError("transport", err.Error())
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", newConnectorError("authentication_failed", "wazuh authenticate returned HTTP "+strconv.Itoa(response.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8192))
	if err != nil {
		return "", newConnectorError("read_response", err.Error())
	}
	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", newConnectorError("authentication_failed", "wazuh returned an empty token")
	}

	c.token = token
	c.tokenTime = time.Now()
	return token, nil
}

func (c *WazuhConnector) get(ctx context.Context, path string, query url.Values) (wazuhEnvelope, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return wazuhEnvelope{}, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path+"?"+query.Encode(), nil)
	if err != nil {
		return wazuhEnvelope{}, newConnectorError("build_request", err.Error())
	}
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := c.client.Do(request)
	if err != nil {
		return wazuhEnvelope{}, newConnectorError("transport", err.Error())
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return wazuhEnvelope{}, newConnectorError("http_status", "wazuh returned HTTP "+strconv.Itoa(response.StatusCode))
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return wazuhEnvelope{}, newConnectorError("read_response", err.Error())
	}
	if int64(len(body)) > c.maxResponseBytes {
		return wazuhEnvelope{}, newConnectorError("response_too_large", fmt.Sprintf("response exceeded %d bytes", c.maxResponseBytes))
	}

	var envelope wazuhEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return wazuhEnvelope{}, newConnectorError("decode_response", err.Error())
	}
	if envelope.Error != 0 {
		return wazuhEnvelope{}, newConnectorError("wazuh_error", fmt.Sprintf("wazuh error %d: %s", envelope.Error, envelope.Message))
	}
	return envelope, nil
}

func normalizeAgents(agents []wazuhAgent, critical map[string]struct{}) []EvidenceItem {
	items := make([]EvidenceItem, 0, len(agents))
	for _, agent := range agents {
		item := EvidenceItem{
			ID:          agent.ID,
			Host:        agent.Name,
			Description: strings.TrimSpace("Wazuh agent " + agent.Version),
			State:       agent.Status,
		}
		fields := map[string]string{}
		if agent.IP != "" {
			fields["ip"] = agent.IP
		}
		if agent.LastKeepAlive != "" {
			fields["last_keep_alive"] = agent.LastKeepAlive
		}
		if len(agent.Group) > 0 {
			fields["groups"] = strings.Join(agent.Group, ",")
		}
		// Marked on the item as well as counted in the summary, so an answer can
		// name which hosts are critical without the model deciding what counts.
		if agent.isCritical(critical) {
			fields["critical"] = "true"
		}
		if len(fields) > 0 {
			item.Fields = fields
		}
		items = append(items, item)
	}

	// Order before anything truncates, so a capped list still contains what a
	// reader would ask about first: critical agents that are down, then any
	// other agent that is down, then the rest. Within a tier, by name, so the
	// same fleet produces the same list twice running.
	sort.SliceStable(items, func(a, b int) bool {
		rankA, rankB := itemRank(items[a]), itemRank(items[b])
		if rankA != rankB {
			return rankA < rankB
		}
		return items[a].Host < items[b].Host
	})
	return items
}

// itemRank orders an agent by how much its absence matters.
func itemRank(item EvidenceItem) int {
	down := item.State != "active" && item.State != ""
	switch {
	case item.Fields["critical"] == "true" && down:
		return 0
	case down:
		return 1
	case item.Fields["critical"] == "true":
		return 2
	default:
		return 3
	}
}

// summarizeAgents counts agents by connection state, and separately counts the
// ones whose loss is worth escalating. The Wazuh manager's own record is
// excluded so these totals match the manager's summary endpoint and the Wazuh
// dashboard.
//
// disconnected_critical is computed here for the same reason every aggregate
// is: intersecting a status with membership of a named group, across several
// hundred agents, is arithmetic over a list. A model asked to do it will
// usually be right and occasionally be confidently wrong, and "which critical
// machines are down" is not a number to be occasionally wrong about.
func summarizeAgents(agents []wazuhAgent, critical map[string]struct{}) map[string]int {
	// Always stated, never inferred from a missing key. Omitting these when no
	// groups were configured let a model read the absence as zero: asked which
	// critical agents were down, it answered "no critical agents were
	// identified as disconnected, as the critical_disconnected count was absent
	// from the evidence summary" -- an all-clear posted to a channel, derived
	// from configuration that was simply not loaded.
	//
	// critical_groups_configured distinguishes "checked, none affected" from
	// "never checked". When it is zero the question was not answered at all.
	summary := map[string]int{
		"total":                      0,
		"critical_groups_configured": len(critical),
	}
	if len(critical) > 0 {
		// Present even at zero, so absence can never be mistaken for none.
		summary["critical_total"] = 0
		summary["critical_disconnected"] = 0
	}
	for _, agent := range agents {
		if agent.ID == managerAgentID {
			continue
		}
		state := agent.Status
		if state == "" {
			state = "unknown"
		}
		summary[state]++
		summary["total"]++

		if len(critical) > 0 && agent.isCritical(critical) {
			summary["critical_total"]++
			if state != "active" {
				summary["critical_"+state]++
			}
		}
	}
	return summary
}
