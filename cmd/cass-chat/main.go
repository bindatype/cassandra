package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
	"github.com/bindatype/cassandra/internal/connector"
	"github.com/bindatype/cassandra/internal/env"
	"github.com/bindatype/cassandra/internal/orchestrator"
)

const (
	mindrouterEndpointEnv = "CASS_MINDROUTER_ENDPOINT"
	mindrouterKeyEnv      = "MINDROUTER_API_KEY"
	mindrouterModelEnv    = "CASS_MODEL"
	thinkingEnv           = "CASS_THINKING"
	thinkingBudgetEnv     = "CASS_THINKING_BUDGET"
	zabbixEndpointEnv     = "CASS_ZABBIX_ENDPOINT"
	zabbixTokenEnv        = "ZABBIX_RO_TOKEN"
	wazuhEndpointEnv      = "CASS_WAZUH_ENDPOINT"
	wazuhUsernameEnv      = "WAZUH_API_USERNAME"
	wazuhPasswordEnv      = "WAZUH_API_PASSWORD"
	// wazuhCriticalGroupsEnv names the agent groups whose loss is escalated,
	// comma-separated (site configuration; at RTS, "RTS_Ops,Viper").
	wazuhCriticalGroupsEnv = "CASS_WAZUH_CRITICAL_GROUPS"
	pegasusDSNEnv          = "CASS_PEGASUS_DSN"
	pegasusMaxRowsEnv      = "CASS_PEGASUS_MAX_ROWS"
	pegasusTimeoutEnv      = "CASS_PEGASUS_TIMEOUT"
	pegasusMaxBytesEnv     = "CASS_PEGASUS_MAX_BYTES"
	auditPathEnv           = "CASS_BROKER_AUDIT"
	rtEndpointEnv          = "CASS_RT_ENDPOINT"
	rtTokenEnv             = "RT_API_TOKEN"
	cassAgentConfigEnv     = "CASS_AGENT_CONFIG"
	// Set by cass-mcp for the person and agent a question is answered for.
	callerEnv = "CASS_CALLER"
	clientEnv = "CASS_CLIENT"
	// rtQueuesEnv names the RT queues this deployment may search,
	// comma-separated. There is no safe default.
	rtQueuesEnv = "CASS_RT_QUEUES"

	// defaultModel should be chosen by scripts/eval_headtohead.py, which
	// grades six question shapes. gemma4-31b-vllm is what Cassandra's
	// evaluations run on, but it has not been graded head to head against
	// another model; it became the default when the gateway briefly served
	// nothing else.
	// CASS_MODEL selects a MindRouter alias per deployment; -model overrides
	// either per call.
	defaultModel = "gemma4-31b-vllm"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("cass-chat", flag.ContinueOnError)
	flags.SetOutput(stderr)
	policyPath := flags.String("policy", "", "path to a broker policy JSON file")
	model := flags.String("model", configuredModel(), "model or alias to ask")
	endpoint := flags.String("mindrouter-endpoint", env.Get(mindrouterEndpointEnv), "MindRouter base URL")
	zabbixEndpoint := flags.String("zabbix-endpoint", env.Get(zabbixEndpointEnv), "Zabbix JSON-RPC endpoint URL")
	wazuhEndpoint := flags.String("wazuh-endpoint", env.Get(wazuhEndpointEnv), "Wazuh API base URL")
	wazuhInsecure := flags.Bool("wazuh-insecure", false, "skip TLS verification for the Wazuh API")
	rtEndpoint := flags.String("rt-endpoint", env.Get(rtEndpointEnv), "Request Tracker REST 2.0 base URL")
	showTrace := flags.Bool("trace", false, "print the policy decision trace to stderr")
	auditPath := flags.String("audit", env.Get(auditPathEnv), "append a JSON-lines audit record for each question")
	timeout := flags.Duration("timeout", 180*time.Second, "overall timeout")
	asJSON := flags.Bool("json", false, "print {answer, evidence} as JSON instead of the answer alone")
	// Written out rather than left to PrintDefaults, because a list of flags
	// does not tell someone what the tool is for. The first thing a new user
	// needs is the shape of a question it can answer.
	flags.Usage = func() {
		fmt.Fprint(stderr, usageText)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	// After the flags have read their defaults, warn once if any came from
	// legacy names (see internal/env), so the shim doesn't outlive the rename.
	env.ReportLegacy(stderr)
	// One message per missing flag, naming the right one.
	if *policyPath == "" {
		fmt.Fprintln(stderr, "cass-chat: -policy is required")
		return 2
	}
	if *model == "" {
		fmt.Fprintln(stderr, "cass-chat: -model must name a model or alias")
		return 2
	}

	question := strings.TrimSpace(strings.Join(flags.Args(), " "))
	if question == "" {
		raw, err := io.ReadAll(io.LimitReader(stdin, 8192))
		if err != nil {
			fmt.Fprintf(stderr, "cass-chat: read question: %v\n", err)
			return 1
		}
		question = strings.TrimSpace(string(raw))
	}
	if question == "" {
		fmt.Fprintln(stderr, "cass-chat: no question supplied")
		return 2
	}

	session, err := buildSession(*policyPath, *model, *endpoint, *zabbixEndpoint, *wazuhEndpoint, *rtEndpoint, *wazuhInsecure, *showTrace)
	if err != nil {
		fmt.Fprintf(stderr, "cass-chat: %v\n", err)
		return 2
	}

	if *auditPath != "" {
		auditor, err := orchestrator.NewAuditor(*auditPath)
		if err != nil {
			fmt.Fprintf(stderr, "cass-chat: open audit: %v\n", err)
			return 2
		}
		defer auditor.Close()
		session = session.WithAudit(auditor, *model)
	}
	session = session.WithCaller(env.Get(callerEnv), env.Get(clientEnv))

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Ask the endpoint agents what they implement, since policy can advertise
	// an operation a host's agent lacks.
	session.ReconcileAgents(ctx)

	answer, askErr := session.Ask(ctx, question)
	if *showTrace {
		for _, entry := range session.Trace() {
			verdict := "allowed"
			if !entry.Allowed {
				verdict = "DENIED"
			}
			fmt.Fprintf(stderr, "  [%s] %s %s\n", verdict, entry.Stage, entry.Detail)
		}
	}
	if *asJSON {
		out := struct {
			Answer   string             `json:"answer,omitempty"`
			Error    string             `json:"error,omitempty"`
			Evidence []connector.Result `json:"evidence"`
		}{Answer: answer, Evidence: session.Evidence()}
		if askErr != nil {
			out.Error = askErr.Error()
		}
		if out.Evidence == nil {
			out.Evidence = []connector.Result{}
		}
		if err := json.NewEncoder(stdout).Encode(out); err != nil {
			fmt.Fprintf(stderr, "cass-chat: encode: %v\n", err)
			return 1
		}
		if askErr != nil {
			return 1
		}
		return 0
	}
	if askErr != nil {
		fmt.Fprintf(stderr, "cass-chat: %v\n", askErr)
		return 1
	}

	fmt.Fprintln(stdout, answer)
	return 0
}

func configuredModel() string {
	if model := env.Get(mindrouterModelEnv); model != "" {
		return model
	}
	return defaultModel
}

func buildSession(policyPath, model, endpoint, zabbixEndpoint, wazuhEndpoint, rtEndpoint string, wazuhInsecure, trace bool) (*orchestrator.Session, error) {
	policyFile, err := os.Open(policyPath)
	if err != nil {
		return nil, fmt.Errorf("open policy: %w", err)
	}
	defer policyFile.Close()

	policy, err := broker.LoadPolicy(policyFile)
	if err != nil {
		return nil, err
	}
	router, err := broker.NewRouter(policy)
	if err != nil {
		return nil, err
	}

	if endpoint == "" {
		return nil, fmt.Errorf("set -mindrouter-endpoint or %s", mindrouterEndpointEnv)
	}
	apiKey := env.Get(mindrouterKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("%s is not set (a value in ~/.bashrc must also be exported)", mindrouterKeyEnv)
	}
	thinking, thinkingBudget, err := thinkingSettings()
	if err != nil {
		return nil, err
	}
	client, err := orchestrator.NewMindRouterClient(orchestrator.MindRouterConfig{
		Endpoint:       endpoint,
		APIKey:         apiKey,
		Model:          model,
		Thinking:       thinking,
		ThinkingBudget: thinkingBudget,
	})
	if err != nil {
		return nil, err
	}

	// Every reachable connector is built up front: the intent isn't known
	// until the model proposes one.
	var connectors []connector.Connector

	// A half-configured source (endpoint without credential) is an error that
	// names the variable. Skipping it would hide the intent, and the model
	// would report the source "unavailable", which reads as an outage.
	for _, half := range []struct{ endpoint, endpointEnv, credential, credentialEnv string }{
		{zabbixEndpoint, zabbixEndpointEnv, env.Get(zabbixTokenEnv), zabbixTokenEnv},
		{wazuhEndpoint, wazuhEndpointEnv, env.Get(wazuhUsernameEnv), wazuhUsernameEnv},
		{wazuhEndpoint, wazuhEndpointEnv, env.Get(wazuhPasswordEnv), wazuhPasswordEnv},
		{rtEndpoint, rtEndpointEnv, env.Get(rtTokenEnv), rtTokenEnv},
	} {
		if half.endpoint != "" && half.credential == "" {
			return nil, fmt.Errorf("%s is set but %s is not; export it, or unset %s to disable that source deliberately",
				half.endpointEnv, half.credentialEnv, half.endpointEnv)
		}
	}

	// The connector refuses an empty queue allowlist but can't name the
	// variable that fixes it; this can.
	if rtEndpoint != "" && len(splitList(env.Get(rtQueuesEnv))) == 0 {
		return nil, fmt.Errorf("%s is set but %s is not; there is no safe default queue set, "+
			"so RT is refused rather than searched in full", rtEndpointEnv, rtQueuesEnv)
	}
	if zabbixEndpoint != "" && env.Get(zabbixTokenEnv) != "" {
		zabbix, err := connector.NewZabbixConnector(connector.ZabbixConfig{
			Endpoint: zabbixEndpoint,
			Token:    env.Get(zabbixTokenEnv),
		})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, zabbix)
	}
	if wazuhEndpoint != "" && env.Get(wazuhUsernameEnv) != "" && env.Get(wazuhPasswordEnv) != "" {
		wazuh, err := connector.NewWazuhConnector(connector.WazuhConfig{
			Endpoint:           wazuhEndpoint,
			Username:           env.Get(wazuhUsernameEnv),
			Password:           env.Get(wazuhPasswordEnv),
			InsecureSkipVerify: wazuhInsecure,
			CriticalGroups:     splitList(env.Get(wazuhCriticalGroupsEnv)),
		})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, wazuh)
	}
	if dsn := env.Get(pegasusDSNEnv); dsn != "" {
		pegasus, err := connector.NewPegasusConnector(connector.PegasusConfig{DSN: dsn, MaxRows: pegasusMaxRows(), MaxBytes: pegasusMaxBytes(), Timeout: pegasusTimeout()})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, pegasus)
	}
	if rtEndpoint != "" && env.Get(rtTokenEnv) != "" {
		rt, err := connector.NewRTConnector(connector.RTConfig{
			Endpoint: rtEndpoint,
			Token:    env.Get(rtTokenEnv),
			Queues:   splitList(env.Get(rtQueuesEnv)),
		})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, rt)
	}
	if rawAgents := env.Get(cassAgentConfigEnv); rawAgents != "" {
		agents, err := connector.ParseCassAgents(rawAgents)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", cassAgentConfigEnv, err)
		}
		agentConnector, err := connector.NewCassConnector(connector.CassConfig{Agents: agents})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, agentConnector)
	}
	if len(connectors) == 0 {
		return nil, fmt.Errorf("no connectors configured; set a source endpoint and its credentials")
	}

	// What is switched off, under -trace only: printed every run, it was
	// noise that trained people to ignore it.
	if trace {
		if off := unconfiguredSources(zabbixEndpoint, wazuhEndpoint, rtEndpoint); len(off) > 0 {
			fmt.Fprintf(os.Stderr, "not configured: %s\n", strings.Join(off, "; "))
		}
	}

	executor, err := connector.NewExecutor(connectors...)
	if err != nil {
		return nil, err
	}
	return orchestrator.NewSession(client, router, executor), nil
}

// pegasusMaxRows reads the row cap override, falling back to the connector's
// default when unset or unparseable.
func pegasusMaxRows() int {
	value := env.Get(pegasusMaxRowsEnv)
	if value == "" {
		return 0
	}
	rows, err := strconv.Atoi(value)
	if err != nil || rows <= 0 {
		return 0
	}
	return rows
}

// pegasusMaxBytes reads the evidence byte-cap override, falling back to the
// connector default when unset. Raise CASS_MAX_EVIDENCE with it.
func pegasusMaxBytes() int {
	value := env.Get(pegasusMaxBytesEnv)
	if value == "" {
		return 0
	}
	size, err := strconv.Atoi(value)
	if err != nil || size <= 0 {
		return 0
	}
	return size
}

// splitList parses a comma-separated environment value, discarding blanks.
func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// unconfiguredSources lists the evidence sources that are switched off, each
// with the variables that would switch it on. It reports only sources that are
// entirely absent; a half-configured one is an error raised in buildSession
// rather than a note here.
func unconfiguredSources(zabbixEndpoint, wazuhEndpoint, rtEndpoint string) []string {
	var off []string
	if zabbixEndpoint == "" {
		off = append(off, "Zabbix monitoring (set "+zabbixEndpointEnv+", "+zabbixTokenEnv+")")
	}
	if wazuhEndpoint == "" {
		off = append(off, "Wazuh fleet (set "+wazuhEndpointEnv+", "+wazuhUsernameEnv+", "+wazuhPasswordEnv+")")
	}
	if env.Get(pegasusDSNEnv) == "" {
		off = append(off, "PegasusDB accounting (set "+pegasusDSNEnv+")")
	}
	if rtEndpoint == "" {
		off = append(off, "Request Tracker tickets (set "+rtEndpointEnv+", "+rtTokenEnv+", "+rtQueuesEnv+")")
	}
	if env.Get(cassAgentConfigEnv) == "" {
		off = append(off, "endpoint evidence (set "+cassAgentConfigEnv+")")
	}
	return off
}

// pegasusTimeout reads the query time bound, falling back to the connector
// default when unset.
//
// One value sets the socket, connector and server statement limits, so the
// server-side limit fires first (see NewPegasusConnector).
func pegasusTimeout() time.Duration {
	value := env.Get(pegasusTimeoutEnv)
	if value == "" {
		return 0
	}
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout <= 0 {
		return 0
	}
	return timeout
}

// usageText is the front of -help: what the tool answers from, in plain
// words, and that it can answer questions about itself.
const usageText = `askcass -- ask a question about GW RTS infrastructure.

  askcass "how many Wazuh agents are disconnected right now?"
  askcass "what groups are in Wazuh and how many nodes in each?"
  askcass "which hosts have Zabbix triggers firing?"
  askcass "how many jobs failed yesterday on each partition?"
  askcass "are there open tickets mentioning sgtstubby?"
  askcass "what is sgtstubby's uptime and load?"

Answers come from live sources -- Wazuh, Zabbix, the pegasusdb accounting
database, Request Tracker, and policy-approved reads from Cassandra endpoint
agents. Every answer states which source it used. Nothing is answered from
memory: if no source covers the question, it says so.

You can also ask about the tool itself, and it will answer from its own
documentation rather than refusing:

  askcass "how does cassandra work?"
  askcass "what can I ask you about?"
  askcass "what is an intent?"

Flags:
`

// thinkingSettings reads CASS_THINKING (on/off) and CASS_THINKING_BUDGET
// (reasoning tokens, 0 for no cap). Thinking is off unless asked for.
func thinkingSettings() (bool, int, error) {
	var on bool
	switch strings.ToLower(strings.TrimSpace(env.Get(thinkingEnv))) {
	case "", "0", "off", "false", "no":
	case "1", "on", "true", "yes":
		on = true
	default:
		return false, 0, fmt.Errorf("%s must be on or off, got %q", thinkingEnv, env.Get(thinkingEnv))
	}
	value := strings.TrimSpace(env.Get(thinkingBudgetEnv))
	if value == "" {
		return on, 0, nil
	}
	budget, err := strconv.Atoi(value)
	if err != nil || budget < 0 {
		return false, 0, fmt.Errorf("%s must be a non-negative number of tokens, got %q", thinkingBudgetEnv, value)
	}
	if budget > 0 && !on {
		return false, 0, fmt.Errorf("%s is set but %s is not on", thinkingBudgetEnv, thinkingEnv)
	}
	return on, budget, nil
}
