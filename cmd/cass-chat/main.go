package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
	"github.com/bindatype/cassandra/internal/connector"
	"github.com/bindatype/cassandra/internal/orchestrator"
)

const (
	mindrouterEndpointEnv = "SROIAAA_MINDROUTER_ENDPOINT"
	mindrouterKeyEnv      = "MINDROUTER_API_KEY"
	mindrouterModelEnv    = "SROIAAA_MODEL"
	zabbixEndpointEnv     = "SROIAAA_ZABBIX_ENDPOINT"
	zabbixTokenEnv        = "ZABBIX_RO_TOKEN"
	wazuhEndpointEnv      = "SROIAAA_WAZUH_ENDPOINT"
	wazuhUsernameEnv      = "WAZUH_API_USERNAME"
	wazuhPasswordEnv      = "WAZUH_API_PASSWORD"
	// wazuhCriticalGroupsEnv names the agent groups whose loss is escalated, as
	// a comma-separated list. Site configuration, so it lives here rather than
	// in the connector: at RTS it is "RTS_Ops,Viper".
	wazuhCriticalGroupsEnv = "SROIAAA_WAZUH_CRITICAL_GROUPS"
	pegasusDSNEnv          = "SROIAAA_PEGASUS_DSN"
	pegasusMaxRowsEnv      = "SROIAAA_PEGASUS_MAX_ROWS"
	pegasusMaxBytesEnv     = "SROIAAA_PEGASUS_MAX_BYTES"
	auditPathEnv           = "SROIAAA_BROKER_AUDIT"
	rtEndpointEnv          = "SROIAAA_RT_ENDPOINT"
	rtTokenEnv             = "RT_API_TOKEN"
	cassAgentConfigEnv     = "SROIAAA_AGENT_CONFIG"
	// rtQueuesEnv names the RT queues this deployment allows searching, as a
	// comma-separated list. Site configuration, not a connector default: RT
	// queues are organization-specific and there is no safe default that
	// includes any of them.
	rtQueuesEnv = "SROIAAA_RT_QUEUES"

	// defaultModel is chosen by scripts/eval_headtohead.py, which grades six
	// question shapes rather than one: an aggregate, a grouped result that
	// engages the row cap, a two-step schema lookup, a question with no data
	// source that must be refused, a concept with no matching column that must
	// be derived rather than refused, and a listing that exceeds the cap.
	//
	// On 2026-08-28, gemma4:31b scored 30/30 at 9.8s per question against
	// llama3.3's 28/30 at 15.2s. Earlier single-question comparisons could not
	// separate them; the concept case did.
	//
	// That instruction stands, and this value no longer satisfies it. On
	// 2026-09-04 the gateway withdrew gemma4:31b and now serves exactly one
	// model, gemma4-31b-vllm, so the suite cannot be rerun as a comparison and
	// this fallback is a forced substitution rather than a graded choice. It
	// has been exercised end to end -- the evidence loop answers correctly on
	// it -- but it has not been scored against an alternative, because there
	// is none to score it against.
	//
	// Restore the grading the first time a second model is served. Deployments
	// can select a MindRouter alias with SROIAAA_MODEL, and callers can
	// override either value per call with -model.
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
	endpoint := flags.String("mindrouter-endpoint", os.Getenv(mindrouterEndpointEnv), "MindRouter base URL")
	zabbixEndpoint := flags.String("zabbix-endpoint", os.Getenv(zabbixEndpointEnv), "Zabbix JSON-RPC endpoint URL")
	wazuhEndpoint := flags.String("wazuh-endpoint", os.Getenv(wazuhEndpointEnv), "Wazuh API base URL")
	wazuhInsecure := flags.Bool("wazuh-insecure", false, "skip TLS verification for the Wazuh API")
	rtEndpoint := flags.String("rt-endpoint", os.Getenv(rtEndpointEnv), "Request Tracker REST 2.0 base URL")
	showTrace := flags.Bool("trace", false, "print the policy decision trace to stderr")
	auditPath := flags.String("audit", os.Getenv(auditPathEnv), "append a JSON-lines audit record for each question")
	timeout := flags.Duration("timeout", 180*time.Second, "overall timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	// Two separate failures, because a message naming the wrong flag sends the
	// operator to fix something that was never wrong.
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

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

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
	if askErr != nil {
		fmt.Fprintf(stderr, "cass-chat: %v\n", askErr)
		return 1
	}

	fmt.Fprintln(stdout, answer)
	return 0
}

func configuredModel() string {
	if model := os.Getenv(mindrouterModelEnv); model != "" {
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
	apiKey := os.Getenv(mindrouterKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("%s is not set (a value in ~/.bashrc must also be exported)", mindrouterKeyEnv)
	}
	client, err := orchestrator.NewMindRouterClient(orchestrator.MindRouterConfig{
		Endpoint: endpoint,
		APIKey:   apiKey,
		Model:    model,
	})
	if err != nil {
		return nil, err
	}

	// Every connector the model could reach is built up front, because the
	// intent it will propose is not known until it proposes one.
	var connectors []connector.Connector

	// A source configured halfway is a mistake, not a choice: nobody sets an
	// endpoint meaning to leave the credential out. Refusing here names the
	// variable. Skipping silently withholds the intent from the tool schema
	// instead, and the model then reports the source as "unavailable" -- which
	// reads as an outage rather than an unset variable. That cost an afternoon
	// on 2026-09-02, chasing RT through a pull, a rebuild and a merge before
	// anyone looked at the env file.
	for _, half := range []struct{ endpoint, endpointEnv, credential, credentialEnv string }{
		{zabbixEndpoint, zabbixEndpointEnv, os.Getenv(zabbixTokenEnv), zabbixTokenEnv},
		{wazuhEndpoint, wazuhEndpointEnv, os.Getenv(wazuhUsernameEnv), wazuhUsernameEnv},
		{wazuhEndpoint, wazuhEndpointEnv, os.Getenv(wazuhPasswordEnv), wazuhPasswordEnv},
		{rtEndpoint, rtEndpointEnv, os.Getenv(rtTokenEnv), rtTokenEnv},
	} {
		if half.endpoint != "" && half.credential == "" {
			return nil, fmt.Errorf("%s is set but %s is not; export it, or unset %s to disable that source deliberately",
				half.endpointEnv, half.credentialEnv, half.endpointEnv)
		}
	}

	// The queue allowlist is the third RT variable and the easiest to miss.
	// The connector refuses an empty one, correctly, but it is a library and
	// cannot name the variable that would fix it.
	if rtEndpoint != "" && len(splitList(os.Getenv(rtQueuesEnv))) == 0 {
		return nil, fmt.Errorf("%s is set but %s is not; there is no safe default queue set, "+
			"so RT is refused rather than searched in full", rtEndpointEnv, rtQueuesEnv)
	}
	if zabbixEndpoint != "" && os.Getenv(zabbixTokenEnv) != "" {
		zabbix, err := connector.NewZabbixConnector(connector.ZabbixConfig{
			Endpoint: zabbixEndpoint,
			Token:    os.Getenv(zabbixTokenEnv),
		})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, zabbix)
	}
	if wazuhEndpoint != "" && os.Getenv(wazuhUsernameEnv) != "" && os.Getenv(wazuhPasswordEnv) != "" {
		wazuh, err := connector.NewWazuhConnector(connector.WazuhConfig{
			Endpoint:           wazuhEndpoint,
			Username:           os.Getenv(wazuhUsernameEnv),
			Password:           os.Getenv(wazuhPasswordEnv),
			InsecureSkipVerify: wazuhInsecure,
			CriticalGroups:     splitList(os.Getenv(wazuhCriticalGroupsEnv)),
		})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, wazuh)
	}
	if dsn := os.Getenv(pegasusDSNEnv); dsn != "" {
		pegasus, err := connector.NewPegasusConnector(connector.PegasusConfig{DSN: dsn, MaxRows: pegasusMaxRows(), MaxBytes: pegasusMaxBytes()})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, pegasus)
	}
	if rtEndpoint != "" && os.Getenv(rtTokenEnv) != "" {
		rt, err := connector.NewRTConnector(connector.RTConfig{
			Endpoint: rtEndpoint,
			Token:    os.Getenv(rtTokenEnv),
			Queues:   splitList(os.Getenv(rtQueuesEnv)),
		})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, rt)
	}
	if rawAgents := os.Getenv(cassAgentConfigEnv); rawAgents != "" {
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

	// What is switched off, for -trace only. This printed on every run, so a
	// question about tickets was answered with a line about endpoint agents,
	// and a source deliberately left unconfigured produced the same line
	// forever. A notice that appears when it does not apply is read once and
	// then never again, which is the state a real one needs to avoid.
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
	value := os.Getenv(pegasusMaxRowsEnv)
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
// connector default when unset. Raise it only alongside a model whose context
// window can hold the result.
func pegasusMaxBytes() int {
	value := os.Getenv(pegasusMaxBytesEnv)
	if value == "" {
		return 0
	}
	size, err := strconv.Atoi(value)
	if err != nil || size <= 0 {
		return 0
	}
	return size
}

// splitList parses a comma-separated environment value, discarding blanks so a
// trailing comma or a stray space does not become a group name that matches
// nothing.
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
	if os.Getenv(pegasusDSNEnv) == "" {
		off = append(off, "PegasusDB accounting (set "+pegasusDSNEnv+")")
	}
	if rtEndpoint == "" {
		off = append(off, "Request Tracker tickets (set "+rtEndpointEnv+", "+rtTokenEnv+", "+rtQueuesEnv+")")
	}
	if os.Getenv(cassAgentConfigEnv) == "" {
		off = append(off, "endpoint evidence (set "+cassAgentConfigEnv+")")
	}
	return off
}
