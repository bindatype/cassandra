package connector

import (
	"context"
	"fmt"

	"github.com/bindatype/cassandra/internal/broker"
)

// Connector executes a single route step against one data source.
type Connector interface {
	Source() broker.Source
	Execute(ctx context.Context, step broker.RouteStep) (Evidence, error)
}

// Executor runs a route plan by dispatching each step to the connector
// registered for that step's source. A plan naming a source with no registered
// connector fails; it never falls through to a default.
type Executor struct {
	connectors map[broker.Source]Connector
}

// Result is the outcome of executing one plan.
type Result struct {
	Intent   broker.Intent `json:"intent"`
	Evidence []Evidence    `json:"evidence"`
}

// NewExecutor registers connectors by their declared source.
func NewExecutor(connectors ...Connector) (*Executor, error) {
	registry := make(map[broker.Source]Connector, len(connectors))
	for _, c := range connectors {
		if c == nil {
			return nil, fmt.Errorf("nil connector")
		}
		source := c.Source()
		if _, exists := registry[source]; exists {
			return nil, fmt.Errorf("duplicate connector for source %q", source)
		}
		registry[source] = c
	}
	return &Executor{connectors: registry}, nil
}

// Execute runs every step in order and stops at the first failure. Steps are
// read-only, so a partial result is still sound evidence for what did run, but
// callers are told which step failed rather than receiving a silent short read.
func (e *Executor) Execute(ctx context.Context, plan broker.RoutePlan) (Result, error) {
	result := Result{Intent: plan.Intent, Evidence: make([]Evidence, 0, len(plan.Steps))}
	for index, step := range plan.Steps {
		c, ok := e.connectors[step.Source]
		if !ok {
			return result, newConnectorError("no_connector", fmt.Sprintf("step %d: no connector registered for source %q", index, step.Source))
		}
		evidence, err := c.Execute(ctx, step)
		if err != nil {
			return result, fmt.Errorf("step %d: %w", index, err)
		}
		result.Evidence = append(result.Evidence, evidence)
	}
	return result, nil
}

// Sources lists the sources this executor can reach. Callers use it to avoid
// offering a capability that would fail at execution time.
func (e *Executor) Sources() []broker.Source {
	sources := make([]broker.Source, 0, len(e.connectors))
	for source := range e.connectors {
		sources = append(sources, source)
	}
	return sources
}
