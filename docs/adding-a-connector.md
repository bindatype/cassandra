# Adding a data source to Cassandra

How Zabbix and Wazuh are wired in, what every connector must guarantee, and
what to work through before integrating a new system. Written while adding the
first two connectors, so the rules below are mostly scar tissue rather than
theory.

Request Tracker is used as the worked example throughout.

## The shape of the system

```
question ──> MindRouter ──> model proposes {intent, host?, resource?}
                                   │
                          broker.DecodeRouteRequest   strict decode
                                   │
                             router.Plan(policy)      authorize or deny
                                   │
                              executor dispatch       by RouteStep.Source
                                   │
                       connector ──> the real API
                                   │
                        normalized Evidence ──> model ──> answer
```

The model appears twice and holds no authority in either turn. It proposes an
intent and later writes prose about evidence. Everything between those two
points is decided by trusted policy and compiled-in code.

## The contract

One interface, in `internal/connector/executor.go`:

```go
type Connector interface {
	Source() broker.Source
	Execute(ctx context.Context, step broker.RouteStep) (Evidence, error)
}
```

A `RouteStep` goes in, `Evidence` comes out. The executor dispatches on
`step.Source` and returns an error if no connector is registered for it. There
is no default and no fallthrough.

## Five places you touch

### 1. Declare the source and intents

`internal/broker/types.go`:

```go
const (
	SourceWazuhAPI       Source = "wazuh-api"
	SourceZabbixAPI      Source = "zabbix-api"
	SourceCass           Source = "cass-agent"
	SourceRequestTracker Source = "rt-api"     // new
)

const (
	IntentTicketsOpen   Intent = "tickets.open"      // new
	IntentTicketsByHost Intent = "tickets.for_host"  // new
)
```

### 2. Teach the router to plan them

`internal/broker/router.go`, inside `Plan()`. This is the authorization point:

```go
case IntentTicketsByHost:
	if err := requireHostOnly(request); err != nil {
		return RoutePlan{}, err
	}
	return newPlan(request.Intent, RouteStep{
		Source: SourceRequestTracker,
		Action: "tickets.search",
		Host:   request.Host,
		Limit:  ticketSearchLimit,
	}), nil
```

Note what the plan does **not** carry: no URL, no HTTP method, no credential,
no query string. Those are resolved by the connector from operator
configuration.

### 3. Implement the connector

`internal/connector/rt.go`. Follow `zabbix.go` or `wazuh.go`; the skeleton is:

```go
// rtActions is the fixed action table. A plan may only name an action that
// appears here, so neither a client nor a model can reach an arbitrary
// endpoint. This matters more for RT than for read-only telemetry sources:
// RT can modify tickets, and the only reliable way to keep those operations
// unreachable is to never compile them in.
var rtActions = map[string]string{
	"tickets.search": "/REST/2.0/tickets",
	"ticket.get":     "/REST/2.0/ticket",
}

type RTConfig struct {
	Endpoint         string
	Token            string
	Queues           []string   // allowlist; empty means none
	Timeout          time.Duration
	MaxResponseBytes int64
}

func (c *RTConnector) Source() broker.Source { return broker.SourceRequestTracker }

func (c *RTConnector) Execute(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Source != broker.SourceRequestTracker {
		return Evidence{}, newConnectorError("wrong_source", "step is not an rt-api step")
	}
	path, ok := rtActions[step.Action]
	if !ok {
		return Evidence{}, newConnectorError("unsupported_action",
			fmt.Sprintf("action %q is not executable", step.Action))
	}
	// ... bounded request, normalize, summarize
}
```

### 4. Wire configuration and credentials

`cmd/cass-broker-exec/main.go` and `cmd/cass-chat/main.go`. Credentials
come from the environment; endpoints from a flag with an environment default.
Build a connector only when the plan needs it, so an operator can run a Zabbix
plan without holding RT credentials.

```go
if needed[broker.SourceRequestTracker] {
	token := os.Getenv(rtTokenEnv)
	if token == "" {
		return nil, fmt.Errorf("plan needs RT: %s is not set and exported", rtTokenEnv)
	}
	// ...
}
```

### 5. Expose the intent to the model

`internal/orchestrator/session.go`: add the intent to the tool schema's enum
and describe it in the system prompt, including what it does **not** cover.

## What every connector must guarantee

Each of these exists because something went wrong in testing.

### A fixed action table

A plan may only name an action compiled into the binary. Unknown actions are
rejected before any request is built. There are tests asserting `host.delete`
and `agents.delete` are refused.

For a write-capable API like RT this is the primary control. Do not rely on the
credential being read-only, and do not rely on policy alone: if
`ticket.comment` is not in the table, it cannot be reached.

### Endpoints and credentials from operator config only

Never from the plan, never from the model. A connector that accepts a URL from
its input has handed the model the ability to choose where data goes.

### Bounded responses

Wrap the body in `io.LimitReader` with an explicit cap and fail rather than
silently truncate. A remote system can always return more than you expect.

### Aggregates computed in code, never inferred

**This is the most important rule.** Any figure a reader might act on must be
computed in Go and placed in `Evidence.Summary`.

Two failures made the case:

- Handed 275 Wazuh agent records and asked how many were disconnected, the
  model answered 55. The true figure was 52.
- Asked how many Zabbix problems were active, it answered 25 -- the plan's
  limit, not a count. The true figure was 1841.

Both were stated with total confidence. The second was wrong by two orders of
magnitude. Neither was caught by anything in the pipeline.

Where a source reports a total separately from a page, carry both:
`returned` and `total_matching` are distinct keys so a page can never be
mistaken for a population. Where a source reports no total at all -- Zabbix
`trigger.get` does not -- ask for one explicitly with a second call.

### Normalize; never pass raw vendor payloads through

Map onto `EvidenceItem`. Two leaks that were invisible until a model repeated
them to a human:

- Zabbix returns epoch seconds, and the model recited `1786576250` at the
  reader. Now rendered as RFC 3339.
- Zabbix does not expand trigger macros unless asked, so descriptions arrived
  containing literal `{HOST.NAME}`. Now `expandDescription` is set.

Assume a raw payload is unfit for synthesis until shown otherwise.

### Distinguish "not found" from "none"

An empty result has two meanings and they are not interchangeable. Asked
whether a host had problems, the loop returned zero rows and reported the host
as clean. The host did not exist.

Where a source can tell you, record which case it is. The Zabbix connector
issues a `host.get` when a host-scoped query returns nothing and records
`host_known` in the summary.

### Fail closed on authentication

An expired or rejected credential must produce a typed error, never an empty
result that reads like an answer.

### Match the authoritative view

Where the source has its own dashboard or summary endpoint, make your numbers
equal it. Wazuh's `GET /agents` includes the manager's own record and its
summary endpoint does not, so agent totals exclude id `000` and match what an
operator sees in the Wazuh UI. Numbers that disagree with the console destroy
trust regardless of which is technically correct.

## Testing

Every connector is tested against `httptest`, with no network and no
credentials, so the suite runs anywhere. Cover at least:

- normalization of a representative payload
- an unsupported action is refused and no request is made
- a source-level API error is surfaced with its message intact
- an oversized response is rejected
- missing or invalid configuration is rejected at construction
- authentication failure produces the right typed error
- aggregate counts are correct, including any exclusions

`internal/connector/wazuh_test.go` and `zabbix_test.go` are the models.

## Evaluation

`make eval-zabbix` and `make eval-models` run the loop end to end against live
data and grade the answers. Add cases for a new source.

Two lessons from building them. Fetch ground truth live: the Zabbix problem
count moved between 1458 and 1847 in one afternoon, so volatile figures must be
bounded by sampling before and after each call. And be suspicious of your own
grader -- during the first model survey it was wrong more often than the models
were, failing correct answers over a thousands separator and a regex that would
not match a single digit.

## Before integrating a new source

Work these through before writing code.

**What can it actually answer?** Confirm empirically rather than from
documentation. Wazuh 4.8 moved vulnerability detection out of the API into the
Indexer; `/vulnerability` returns 404 on 4.14.5. A CVE intent backed by the
Wazuh API would have been built on an endpoint that no longer exists.

**What can it modify?** Read-only telemetry and a ticketing system are
different risk classes. Enumerate the destructive operations and confirm none
are reachable through the action table.

**How sensitive is the content?** Zabbix and Wazuh return operational
telemetry. RT returns human correspondence, which routinely contains user PII
and credentials pasted into logs. Decide what leaves the system *before*
evidence starts flowing to a model. The safe default for a ticketing system is
metadata only -- subject, queue, status, owner, dates -- with body text
excluded unless there is a specific decision to include it.

**What is the credential and its scope?** Prefer a dedicated read-only account,
as with `rts_wazuh_api_ro`. Store it in `~/.config/cass/env`, mode `0600`,
with an explicit `export`. A value set in `~/.bashrc` but not exported is
invisible to child processes; this has cost time on three separate occasions.

**What is the TLS posture?** The Wazuh manager presents a self-signed
certificate, so its connector requires an explicit `-wazuh-insecure` opt-in
that warns rather than defaulting to trust. Never make skipping verification
the default.

**What is the natural bound?** Every intent needs a limit that keeps evidence
inside the model's context. Do not hard-code what that context is: MindRouter's
ollama adapter clamped every model it polled to 32768 tokens regardless of
native capacity, the vLLM-backed `gemma4-31b-vllm` is served at its full
131072, and the orchestrator holds the current figure as `servedContextTokens`
with the measurement behind it. `scripts/ctx_marker_probe.py` re-measures it.

## Why Request Tracker is worth adding

The loop can already report that `dss01` has had a GPFS filesystem panic since
August 12. The natural next question is whether anyone is already working on
it, and RT is the only system that can answer it.

`tickets.for_host` would also be the first intent to combine two sources in one
plan: monitoring state and human response side by side. That correlation is a
genuinely different capability from either system alone, and it is the point at
which the broker's multi-step `RoutePlan` earns the shape it already has.
