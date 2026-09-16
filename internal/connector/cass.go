package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
)

const (
	cassDefaultTimeout   = 20 * time.Second
	cassMaxResponseBytes = 128 << 10
)

// CassAgentConfig is one endpoint agent an operator has explicitly made
// reachable. Host is the broker-policy name, not a DNS name selected by a
// route plan.
type CassAgentConfig struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
}

// CassConfig maps every permitted policy host to its endpoint and its own
// bearer token. Keeping the map in operator configuration prevents a route
// plan from selecting either a network destination or another host's token.
type CassConfig struct {
	Agents           map[string]CassAgentConfig
	Timeout          time.Duration
	MaxResponseBytes int64
}

// ParseCassAgents reads the value of SROIAAA_AGENT_CONFIG. It intentionally
// keeps endpoint and token together per host: a single shared token would make
// one endpoint credential authority for every configured agent.
func ParseCassAgents(value string) (map[string]CassAgentConfig, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("agent configuration is empty")
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var agents map[string]CassAgentConfig
	if err := decoder.Decode(&agents); err != nil {
		return nil, fmt.Errorf("decode agent configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("agent configuration contains multiple JSON values")
		}
		return nil, fmt.Errorf("decode agent configuration: %w", err)
	}
	if len(agents) == 0 {
		return nil, fmt.Errorf("agent configuration contains no hosts")
	}
	return agents, nil
}

type configuredAgent struct {
	endpoint string
	token    string
}

// CassConnector executes broker-approved operations against the endpoint
// agent. The broker has already fixed operation, path, and limits; this
// connector's job is only to bind that step to the configured host endpoint.
type CassConnector struct {
	agents           map[string]configuredAgent
	maxResponseBytes int64
	client           *http.Client
}

// NewCassConnector validates operator configuration before accepting any
// plan. HTTP is allowed only for loopback development agents; a remotely
// reachable endpoint must use HTTPS.
func NewCassConnector(config CassConfig) (*CassConnector, error) {
	if len(config.Agents) == 0 {
		return nil, fmt.Errorf("at least one endpoint agent is required")
	}

	agents := make(map[string]configuredAgent, len(config.Agents))
	for host, agent := range config.Agents {
		if strings.TrimSpace(host) == "" || strings.TrimSpace(host) != host {
			return nil, fmt.Errorf("endpoint agent host must be non-empty and have no surrounding whitespace")
		}
		if strings.TrimSpace(agent.Token) == "" {
			return nil, fmt.Errorf("endpoint agent %q token is required", host)
		}
		endpoint, err := validateCassEndpoint(host, agent.Endpoint)
		if err != nil {
			return nil, err
		}
		agents[host] = configuredAgent{endpoint: endpoint, token: agent.Token}
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = cassDefaultTimeout
	}
	maxBytes := config.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = cassMaxResponseBytes
	}

	return &CassConnector{
		agents:           agents,
		maxResponseBytes: maxBytes,
		// An agent controls its HTTP response, not the broker's destination.
		// Following a redirect would send its bearer token to an arbitrary URL.
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func validateCassEndpoint(host, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("endpoint agent %q endpoint is required", host)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse endpoint agent %q endpoint: %w", host, err)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("endpoint agent %q endpoint must be a bare HTTP(S) origin", host)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("endpoint agent %q endpoint must not contain a path", host)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return "", fmt.Errorf("endpoint agent %q endpoint must use https (http is permitted only for loopback development)", host)
	}
	return strings.TrimRight(value, "/"), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

// Source reports which route-step source this connector serves.
func (c *CassConnector) Source() broker.Source {
	return broker.SourceCass
}

type agentOperationRequest struct {
	Operation string                  `json:"operation"`
	Target    *broker.OperationTarget `json:"target,omitempty"`
	Params    *broker.OperationParams `json:"params,omitempty"`
}

type agentOperationResponse struct {
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
	Metadata  struct {
		Truncated bool `json:"truncated"`
	} `json:"metadata"`
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Execute sends only the policy-derived operation, target, and limits to the
// endpoint. A plan for one configured host cannot be sent to another.
func (c *CassConnector) Execute(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Source != broker.SourceCass {
		return Evidence{}, newConnectorError("wrong_source", "step is not a cass-agent step")
	}
	if step.Action != "operations.execute" || step.Operation == "" || step.Target == nil {
		return Evidence{}, newConnectorError("invalid_step", "cass-agent step must contain a policy-approved operation and target")
	}
	agent, ok := c.agents[step.Host]
	if !ok {
		return Evidence{}, newConnectorError("host_not_configured", "no endpoint agent is configured for the policy host")
	}

	payload, err := json.Marshal(agentOperationRequest{
		Operation: step.Operation,
		Target:    step.Target,
		Params:    step.Params,
	})
	if err != nil {
		return Evidence{}, fmt.Errorf("encode endpoint agent request: %w", err)
	}

	requestedAt := time.Now().UTC()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, agent.endpoint+"/v1/operations", bytes.NewReader(payload))
	if err != nil {
		return Evidence{}, fmt.Errorf("build endpoint agent request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+agent.token)

	response, err := c.client.Do(request)
	if err != nil {
		return Evidence{}, newConnectorError("transport_failed", err.Error())
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return Evidence{}, newConnectorError("read_response", err.Error())
	}
	if int64(len(raw)) > c.maxResponseBytes {
		return Evidence{}, newConnectorError("response_too_large", fmt.Sprintf("endpoint agent response exceeded %d bytes", c.maxResponseBytes))
	}

	var decoded agentOperationResponse
	if response.StatusCode != http.StatusOK {
		// A proxy or an agent may send an HTML error page. Its body is not
		// evidence and need not be valid agent JSON to report the failure.
		_ = json.Unmarshal(raw, &decoded)
		return Evidence{}, agentResponseError(response.StatusCode, decoded)
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Evidence{}, newConnectorError("decode_response", err.Error())
	}
	if decoded.Status != "ok" {
		return Evidence{}, agentResponseError(response.StatusCode, decoded)
	}
	if decoded.Operation != step.Operation {
		return Evidence{}, newConnectorError("response_mismatch", "endpoint agent response operation did not match the approved operation")
	}
	if len(decoded.Data) == 0 {
		return Evidence{}, newConnectorError("decode_response", "endpoint agent response omitted data")
	}
	var data any
	if err := json.Unmarshal(decoded.Data, &data); err != nil {
		return Evidence{}, newConnectorError("decode_response", fmt.Sprintf("endpoint agent data: %v", err))
	}

	summary, items, warnings := summarizeAgentData(step.Operation, data)
	if decoded.Metadata.Truncated {
		// A truncated result is a defect in the answer, not a footnote to it:
		// the figures below describe what arrived, not what exists.
		warnings = append(warnings, fmt.Sprintf(
			"the endpoint agent truncated this %s at its own limit; every count here describes "+
				"what was returned, not what is on the host", step.Operation))
	}

	return Evidence{
		Source:      string(broker.SourceCass),
		Action:      step.Action,
		Endpoint:    redactEndpoint(agent.endpoint),
		RequestedAt: requestedAt,
		DurationMS:  time.Since(requestedAt).Milliseconds(),
		ItemCount:   items,
		Summary:     summary,
		Warnings:    warnings,
		Truncated:   decoded.Metadata.Truncated,
		Data:        data,
	}, nil
}

// summarizeAgentData computes, in code, the counts a model is forbidden to
// tally for itself.
//
// Every other connector places population figures in Summary because a model
// asked to count several hundred records will sometimes get it wrong and state
// the wrong number with confidence: one asked to tally 275 rows answered 55
// against a true 52, and asked for a total reported the page limit of 25
// against a true 1841. Endpoint evidence arrives as the agent's own JSON in
// Data rather than as Items, which is the right shape for a file read or a
// directory listing, but it arrived without those figures -- leaving the model
// a raw array and a prompt rule telling it not to count arrays.
//
// Where the agent reports a figure of its own, it is checked rather than
// copied. A disagreement is a defect in the answer and is warned about, not
// quietly resolved in either direction.
func summarizeAgentData(operation string, data any) (map[string]int, int, []string) {
	object, ok := data.(map[string]any)
	if !ok {
		return nil, 0, []string{fmt.Sprintf(
			"no counts were computed: %s returned a %T rather than an object, so this evidence "+
				"supports no population claim", operation, data)}
	}

	summary := map[string]int{}
	warnings := []string{}
	items := 0

	countList := func(field string) (int, bool) {
		values, ok := object[field].([]any)
		if !ok {
			warnings = append(warnings, fmt.Sprintf(
				"no count was computed for %s: %s is missing or is not a list, so any number "+
					"quoted from this evidence would be read off the rows", operation, field))
			return 0, false
		}
		return len(values), true
	}

	// The agent's own figure, checked against what actually arrived.
	crossCheck := func(field string, counted int) {
		reported, ok := object[field].(float64)
		if !ok {
			return
		}
		if int(reported) != counted {
			warnings = append(warnings, fmt.Sprintf(
				"the endpoint agent reported %s=%d but returned %d; the computed figure is used, "+
					"and the disagreement means one of the two is wrong", field, int(reported), counted))
		}
	}

	switch operation {
	case "filesystem.list":
		if count, ok := countList("entries"); ok {
			summary["entries"] = count
			items = count
		}
	case "process.list":
		if count, ok := countList("processes"); ok {
			summary["processes"] = count
			items = count
			crossCheck("count", count)
		}
	case "filesystem.read", "filesystem.tail":
		if content, ok := object["content"].(map[string]any); ok {
			if raw, ok := content["raw"].(string); ok {
				// Bytes as they will be read, which for a base64 body is the
				// decoded length rather than the length of the encoding.
				measured := len(raw)
				if format, _ := content["format"].(string); strings.Contains(format, "base64") {
					if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
						measured = len(decoded)
					}
				}
				summary["bytes"] = measured
				crossCheck("bytes_read", measured)
			}
		}
		if lines, ok := object["lines"].(float64); ok {
			summary["lines"] = int(lines)
		}
	case "filesystem.stat", "host.info", "capabilities.describe":
		// Single records. There is no population to count, and inventing a
		// count of one would invite a model to treat it as a total.
	default:
		warnings = append(warnings, fmt.Sprintf(
			"no counts were computed: %s has no summary rule here, so this evidence supports "+
				"no population claim", operation))
	}

	if len(summary) == 0 {
		summary = nil
	}
	return summary, items, warnings
}

func agentResponseError(status int, response agentOperationResponse) error {
	code := "agent_error"
	switch status {
	case http.StatusUnauthorized:
		code = "authentication_failed"
	case http.StatusForbidden:
		code = "authorization_failed"
	case http.StatusNotFound:
		code = "not_found"
	}
	if response.Error != nil {
		if response.Error.Code != "" {
			code = response.Error.Code
		}
		if response.Error.Message != "" {
			return newConnectorError(code, response.Error.Message)
		}
	}
	return newConnectorError(code, fmt.Sprintf("endpoint agent returned HTTP %d", status))
}
