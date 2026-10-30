package connector

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	// fleetItemCap bounds the agent records returned; the summary carries the
	// exact counts, so items are there to be named, not tallied. A record is
	// ~219 bytes, so 200 is ~44 KB, under the orchestrator's 64 KB evidence
	// cap with room for a second source. Items are ordered before the cap, so
	// the ones a reader asks about first survive. Counting questions belong
	// to groups.list (IntentFleetGroups).
	fleetItemCap = 200
)

// wazuhActions is the fixed action table. Route plans may only name an action
// listed here, so no client or model can reach an arbitrary API path.
var wazuhActions = map[string]struct{}{
	"agents.list":            {},
	"agents.status":          {},
	"groups.list":            {},
	"syscollector.processes": {},
	"syscollector.listeners": {},
}

// WazuhConfig carries operator-supplied execution details. None are derived
// from a route plan.
type WazuhConfig struct {
	Endpoint         string
	Username         string
	Password         string
	Timeout          time.Duration
	MaxResponseBytes int64
	// InsecureSkipVerify disables TLS verification. It is never the default,
	// and with PinnedCertificatePEM available no deployment needs it; it
	// remains as an explicit, warned-about escape hatch.
	InsecureSkipVerify bool
	// PinnedCertificatePEM, when set, is the certificate the API must present,
	// compared byte for byte. It replaces hostname and chain checks rather
	// than skipping them: any other certificate is refused. It exists for a
	// manager whose certificate cannot verify by name, such as one still
	// serving Wazuh's factory certificate (self-signed, CN wazuh.com).
	// Mutually exclusive with InsecureSkipVerify.
	PinnedCertificatePEM []byte
	// CriticalGroups names the agent groups whose loss is worth escalating
	// (site configuration; at RTS, RTS_Ops and Viper). The summary counts
	// agents that are both disconnected and in one of them, in code.
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

	tlsConfig, err := wazuhTLSConfig(config)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

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

	if step.Action == "groups.list" {
		return c.executeGroups(ctx, step)
	}
	if step.Action == "syscollector.processes" || step.Action == "syscollector.listeners" {
		return c.executeInventory(ctx, step)
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
	var notes []string
	if step.Action == "agents.status" && len(payload.Data.AffectedItems) == 0 {
		name, err := c.expandShortName(ctx, step.Host)
		if err != nil {
			return Evidence{}, err
		}
		if name != "" {
			query.Set("name", name)
			if payload, err = c.get(ctx, "/agents", query); err != nil {
				return Evidence{}, err
			}
			notes = append(notes, resolvedNameNote(step.Host, name))
		}
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
		Notes:          notes,
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

// maxNameCandidates bounds the agent names an ambiguous short name lists.
const maxNameCandidates = 10

// expandShortName resolves a host given without its domain ("db01") to the
// one agent whose name begins with it and a dot ("db01.example.edu"). Agent
// names are exact in Wazuh, and on 2026-10-23 short names were refused as
// unknown agents. It returns "" when nothing begins with the name, and an
// unknown_agent error naming the candidates when more than one does.
func (c *WazuhConnector) expandShortName(ctx context.Context, host string) (string, error) {
	if host == "" || strings.Contains(host, ".") {
		return "", nil
	}
	payload, err := c.get(ctx, "/agents", url.Values{
		"select": {"name"},
		"q":      {"name~" + host + "."},
		"limit":  {"100"},
	})
	if err != nil {
		return "", err
	}
	prefix := strings.ToLower(host) + "."
	var candidates []string
	for _, agent := range payload.Data.AffectedItems {
		if strings.HasPrefix(strings.ToLower(agent.Name), prefix) {
			candidates = append(candidates, agent.Name)
		}
	}
	switch {
	case len(candidates) == 1:
		return candidates[0], nil
	case len(candidates) > 1:
		sort.Strings(candidates)
		if len(candidates) > maxNameCandidates {
			candidates = candidates[:maxNameCandidates]
		}
		return "", newConnectorError("unknown_agent", fmt.Sprintf(
			"Wazuh has no agent named %q, and several begin with it: %s. Ask again with the full name",
			host, strings.Join(candidates, ", ")))
	}
	return "", nil
}

// resolvedNameNote says that a short name was expanded, so the answer names
// the agent Wazuh actually reported on.
func resolvedNameNote(asked, resolved string) string {
	return fmt.Sprintf("host %q was resolved to the Wazuh agent %q, the only agent whose name begins with it; "+
		"refer to it by that name", asked, resolved)
}

// executeGroups answers a group-census question from Wazuh's own per-group
// totals: about ten rows instead of every agent record, counted by the source
// rather than by a model reading a page that may be capped.
func (c *WazuhConnector) executeGroups(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Since != "" || step.Until != "" {
		// Group membership is current state. A time bound here would filter
		// nothing and imply a window the answer does not have.
		return Evidence{}, newConnectorError("unsupported_bound",
			"groups.list reports current group membership and takes no since or until")
	}

	query := url.Values{}
	query.Set("limit", strconv.Itoa(wazuhMaxLimit))

	requestedAt := time.Now().UTC()
	payload, err := c.getGroups(ctx, query)
	if err != nil {
		return Evidence{}, err
	}

	items := normalizeGroups(payload.Data.AffectedItems)
	return Evidence{
		Source:         string(broker.SourceWazuhAPI),
		Action:         step.Action,
		Endpoint:       redactEndpoint(c.endpoint),
		RequestedAt:    requestedAt,
		DurationMS:     time.Since(requestedAt).Milliseconds(),
		ItemCount:      len(items),
		TotalAvailable: payload.Data.TotalAffectedItems,
		Truncated:      payload.Data.TotalAffectedItems > len(items),
		Summary:        summarizeGroups(payload.Data.AffectedItems),
		Items:          items,
	}, nil
}

// wazuhGroup mirrors only the fields we consume from GET /groups. Count is
// Wazuh's own tally for the group and is reported as given: whether it counts
// the manager's own record is Wazuh's convention, not ours to reinterpret.
type wazuhGroup struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type wazuhGroupEnvelope struct {
	Data struct {
		AffectedItems      []wazuhGroup `json:"affected_items"`
		TotalAffectedItems int          `json:"total_affected_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

// normalizeGroups turns each group into one item carrying its own count, so
// the answer never depends on the model adding numbers up.
func normalizeGroups(groups []wazuhGroup) []EvidenceItem {
	items := make([]EvidenceItem, 0, len(groups))
	for _, group := range groups {
		items = append(items, EvidenceItem{
			ID:          group.Name,
			Description: fmt.Sprintf("Wazuh agent group %q", group.Name),
			Fields: map[string]string{
				"group":  group.Name,
				"agents": strconv.Itoa(group.Count),
			},
		})
	}
	sort.Slice(items, func(i, j int) bool {
		left, _ := strconv.Atoi(items[i].Fields["agents"])
		right, _ := strconv.Atoi(items[j].Fields["agents"])
		if left != right {
			return left > right
		}
		return items[i].ID < items[j].ID
	})
	return items
}

// summarizeGroups reports totals over every group, not the page returned.
// agents_total sums group membership, which exceeds the fleet size whenever an
// agent belongs to more than one group -- the common case, since "default"
// overlaps the others. It is named as a membership total for that reason.
func summarizeGroups(groups []wazuhGroup) map[string]int {
	summary := map[string]int{
		"groups_total":            len(groups),
		"group_memberships_total": 0,
	}
	for _, group := range groups {
		summary["group_memberships_total"] += group.Count
	}
	return summary
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
	body, err := c.getRaw(ctx, path, query)
	if err != nil {
		return wazuhEnvelope{}, err
	}
	var envelope wazuhEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return wazuhEnvelope{}, newConnectorError("decode_response", err.Error())
	}
	return envelope, nil
}

// getGroups is get for the /groups endpoint, whose affected_items carry a
// different shape. It shares getRaw so authentication, the response size bound
// and Wazuh's own error envelope are enforced identically on both paths.
func (c *WazuhConnector) getGroups(ctx context.Context, query url.Values) (wazuhGroupEnvelope, error) {
	body, err := c.getRaw(ctx, "/groups", query)
	if err != nil {
		return wazuhGroupEnvelope{}, err
	}
	var envelope wazuhGroupEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return wazuhGroupEnvelope{}, newConnectorError("decode_response", err.Error())
	}
	return envelope, nil
}

// getRaw performs the request and returns a body that has passed the size
// bound and carries no Wazuh-level error. Decoding is the caller's.
func (c *WazuhConnector) getRaw(ctx context.Context, path string, query url.Values) ([]byte, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path+"?"+query.Encode(), nil)
	if err != nil {
		return nil, newConnectorError("build_request", err.Error())
	}
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := c.client.Do(request)
	if err != nil {
		return nil, newConnectorError("transport", err.Error())
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, newConnectorError("http_status", "wazuh returned HTTP "+strconv.Itoa(response.StatusCode))
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, newConnectorError("read_response", err.Error())
	}
	if int64(len(body)) > c.maxResponseBytes {
		return nil, newConnectorError("response_too_large", fmt.Sprintf("response exceeded %d bytes", c.maxResponseBytes))
	}

	// Wazuh reports application errors inside a 200 body, so this check belongs
	// on every path and not only the one that decodes agents.
	var status struct {
		Message string `json:"message"`
		Error   int    `json:"error"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, newConnectorError("decode_response", err.Error())
	}
	if status.Error != 0 {
		return nil, newConnectorError("wazuh_error", fmt.Sprintf("wazuh error %d: %s", status.Error, status.Message))
	}
	return body, nil
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

// summarizeAgents counts agents by connection state, and separately the
// disconnected ones in critical groups. The manager's own record is excluded
// so the totals match the Wazuh dashboard.
func summarizeAgents(agents []wazuhAgent, critical map[string]struct{}) map[string]int {
	// Always present: a missing key was once read as zero and produced a
	// false all-clear. critical_groups_configured = 0 means "never checked",
	// not "none affected".
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

// wazuhTLSConfig decides how the API's certificate is checked: against a pinned
// certificate, normally, or -- only on explicit request -- not at all.
func wazuhTLSConfig(config WazuhConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	pinned := len(config.PinnedCertificatePEM) > 0
	switch {
	case pinned && config.InsecureSkipVerify:
		return nil, fmt.Errorf("wazuh: a pinned certificate and InsecureSkipVerify are mutually exclusive; with both, the pin would be ignored")
	case pinned:
		pins, err := parsePinnedCertificates(config.PinnedCertificatePEM)
		if err != nil {
			return nil, err
		}
		// Go's standard verification cannot accept this certificate at all: it
		// names no host Cassandra connects to, and Go no longer honours a bare
		// Common Name. VerifyConnection replaces that check with an exact match,
		// which is stricter than chain verification, not weaker.
		tlsConfig.InsecureSkipVerify = true // nosemgrep: replaced by the VerifyConnection pin below
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			return verifyPinned(state.PeerCertificates, pins, time.Now())
		}
	case config.InsecureSkipVerify:
		tlsConfig.InsecureSkipVerify = true
	}
	return tlsConfig, nil
}

func parsePinnedCertificates(data []byte) ([]*x509.Certificate, error) {
	var pins []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("wazuh: parse pinned certificate: %w", err)
		}
		pins = append(pins, cert)
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("wazuh: the pinned certificate file holds no PEM CERTIFICATE block")
	}
	return pins, nil
}

// verifyPinned accepts the connection only if the server's leaf certificate is
// one of the pins and has not expired. Several pins let a replacement be added
// before the old certificate is retired.
func verifyPinned(presented, pins []*x509.Certificate, now time.Time) error {
	if len(presented) == 0 {
		return fmt.Errorf("wazuh API presented no certificate")
	}
	leaf := presented[0]
	for _, pin := range pins {
		if !leaf.Equal(pin) {
			continue
		}
		if now.After(leaf.NotAfter) {
			return fmt.Errorf("wazuh API certificate matches the pin but expired %s; pin the renewed certificate",
				leaf.NotAfter.UTC().Format(time.RFC3339))
		}
		return nil
	}
	return fmt.Errorf("wazuh API presented a certificate that is not the pinned one (sha256 %x); if the manager's certificate was replaced, pin the new one",
		sha256.Sum256(leaf.Raw))
}
