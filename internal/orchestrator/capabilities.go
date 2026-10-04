package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
	"github.com/bindatype/cassandra/internal/connector"
)

// A policy says which resources a host offers, not which operations its agent
// implements, and the two drift when agents are upgraded unevenly. So the
// agent is asked, and a request it can't serve is refused here, naming what
// the host does offer, so the next attempt is informed rather than a repeat.

const agentProbeTimeout = 5 * time.Second

// agentCapabilities is one host's answer, including no answer. Unreachable (a
// transport problem that may clear) and "does not implement it" (a property
// of what is installed) are kept distinct.
type agentCapabilities struct {
	operations map[string]bool
	reachable  bool
	reason     string
}

func (a agentCapabilities) offered() []string {
	names := make([]string, 0, len(a.operations))
	for name := range a.operations {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// probeAgents asks each host's agent which operations it has enabled, in
// parallel under one deadline, so one unreachable host can't delay the rest.
func probeAgents(ctx context.Context, executor *connector.Executor, hosts []string) map[string]agentCapabilities {
	found := make(map[string]agentCapabilities, len(hosts))
	if executor == nil || len(hosts) == 0 {
		return found
	}

	ctx, cancel := context.WithTimeout(ctx, agentProbeTimeout)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			capability := probeOneAgent(ctx, executor, host)
			mu.Lock()
			found[host] = capability
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return found
}

func probeOneAgent(ctx context.Context, executor *connector.Executor, host string) agentCapabilities {
	plan := broker.RoutePlan{
		Version: 1,
		Intent:  broker.IntentLiveEvidence,
		Steps: []broker.RouteStep{{
			Source:    broker.SourceCass,
			Action:    "operations.execute",
			Host:      host,
			Operation: "capabilities.describe",
		}},
	}

	result, err := executor.Execute(ctx, plan)
	if err != nil {
		return agentCapabilities{reachable: false, reason: err.Error()}
	}
	if len(result.Evidence) == 0 {
		return agentCapabilities{reachable: false, reason: "agent returned no capability evidence"}
	}

	operations, err := operationsFromEvidence(result.Evidence[0])
	if err != nil {
		return agentCapabilities{reachable: false, reason: err.Error()}
	}
	return agentCapabilities{operations: operations, reachable: true}
}

// operationsFromEvidence pulls the operation names out of a capabilities
// response. A response naming no operation is treated as unreadable, not as
// "offers nothing".
func operationsFromEvidence(evidence connector.Evidence) (map[string]bool, error) {
	raw, err := json.Marshal(evidence.Data)
	if err != nil {
		return nil, fmt.Errorf("re-encode capability evidence: %w", err)
	}
	var described struct {
		Operations []struct {
			Name string `json:"name"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(raw, &described); err != nil {
		return nil, fmt.Errorf("decode capability evidence: %w", err)
	}
	if len(described.Operations) == 0 {
		return nil, fmt.Errorf("agent named no operations")
	}
	operations := make(map[string]bool, len(described.Operations))
	for _, operation := range described.Operations {
		if operation.Name != "" {
			operations[operation.Name] = true
		}
	}
	return operations, nil
}

// checkPlanAgainstAgents reports why a plan cannot run on the host it names, or
// nil if nothing is known to stand in the way.
//
// It refuses only when the agent replied and did not list the operation. An
// unprobed or unreachable host is let through to fail on its own terms;
// otherwise every transport blip would read as "this host cannot do that".
func checkPlanAgainstAgents(plan broker.RoutePlan, known map[string]agentCapabilities) error {
	if len(known) == 0 {
		return nil
	}
	for _, step := range plan.Steps {
		if step.Source != broker.SourceCass || step.Operation == "" {
			continue
		}
		capability, probed := known[step.Host]
		if !probed || !capability.reachable {
			continue
		}
		if capability.operations[step.Operation] {
			continue
		}
		return fmt.Errorf("%s does not implement %s; its agent offers only: %s. "+
			"Do not send this request again -- use one of the operations listed, or a different host",
			step.Host, step.Operation, strings.Join(capability.offered(), ", "))
	}
	return nil
}
