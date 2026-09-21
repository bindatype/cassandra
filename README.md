# Cassandra

Cassandra answers questions about GW RTS infrastructure from bounded,
read-only sources, and states which source each answer came from.

It is a **policy broker**, not an agent. A question goes to a model; the model
may name an intent from a fixed list; the broker turns that intent into a route
plan against exactly one source; a connector executes it and returns normalized
evidence with its own counts. The model never reaches a source directly, and the
only text it authors that a source executes is a single read-only SQL `SELECT`
against one schema. Every decision is audited.

## What it can see

| Source | What it knows |
|---|---|
| **Wazuh** | endpoint agent inventory, connection state, group membership |
| **Zabbix** | triggers firing right now, and the event log for a past window |
| **pegasusdb** | HPC job accounting — what jobs actually did, in MariaDB |
| **Request Tracker** | open tickets in allowlisted queues, metadata only |
| **cassd** | policy-approved reads from a Linux host: files, host facts, uptime, disk, network, listening ports |

The point is the join. Zabbix reports what a monitor noticed, Request Tracker
what a person reported, and neither knows a job failed; the accounting database
knows the job failed and nothing about the alert or the ticket. A question that
spans them has no single system to ask, which is the gap this fills.

Adding a source is a defined exercise, not a fork: see
[docs/adding-a-connector.md](docs/adding-a-connector.md). A connector is two
methods and a normalization contract.

## The endpoint agent

`cassd` is one of those five sources — the one this repository also *implements*,
since the other four are systems we query rather than run. It is a native Linux
service under `systemd`, deployed on sgtstubby and winston. Docker appears in
this repository only as a development harness for it.

It intentionally does **not** expose arbitrary shell execution. It offers a
small bounded operation API and records structured audit events, so the
operation catalog is derived empirically rather than guessed.

The compiled operation catalog is deliberately narrow:

- `host.info`
- `host.uptime`
- `host.diskfree`
- `host.network`
- `host.listeners`
- `kernel.messages`
- `filesystem.list`
- `filesystem.stat`
- `filesystem.read`
- `filesystem.tail`
- `process.list`
- `capabilities.describe`

All except `process.list` are enabled by default. Process inspection is
an explicit opt-in and returns only PID, parent PID, name, and state; it
never reads or returns command-line arguments.

`host.uptime` and `host.diskfree` run programs. Every argument they pass is a
compile-time constant, so nothing a caller sends reaches a command line and
there is no parameter to validate; they take no target for that reason. No
shell is involved, the child environment is emptied rather than inherited, and
output is capped at the agent. `host.diskfree` runs both `df -h` and `df -i`,
because a filesystem can exhaust either alone and one at 40% capacity with no
inodes left still fails writes.

`host.network` runs no program at all: it reads interfaces and addresses from
netlink through the Go standard library and the routing tables from
`/proc/net`. It used to run `ip`, which is labelled `ifconfig_exec_t`; executing
it triggers an SELinux domain transition that `NoNewPrivileges` forbids, so the
unit exits 203 under enforcing. Any binary in the command table must be `bin_t`
for that reason, and a test enforces it.

`host.listeners` runs `ss -tuln` and deliberately omits `-p`: attribution is
reported only for the calling user's own sockets, so `-p` would yield a blank
process column on a list that otherwise looks complete. `kernel.messages` runs
`dmesg` and is implemented but **not enabled by default**, because the shipped
unit sets `ProtectKernelLogs=yes` and it could only refuse until that grant is
made. Both carry a `notes` entry stating the limit, so a reader does not have
to discover it.

Core constraints:

- absolute paths only
- allowlisted roots only
- symlink-aware root enforcement
- bounded reads, tails, and fan-out
- bounded HTTP request bodies and server deadlines
- explicit operation and host-information field allowlists
- read-only API surface
- audit-before-return for authenticated data responses
- private structured JSON-line audit log with caller fingerprints and target paths

## Layout

```text
cmd/cassd/         endpoint agent
cmd/cass-broker-plan/   turns an intent into a route plan
cmd/cass-broker-exec/   executes a route plan against live sources
cmd/cass-chat/          asks a question in natural language
internal/agent/            API, execution, validation, audit logic
internal/broker/           deterministic policy and routing kernel
internal/connector/        Zabbix, Wazuh, and Request Tracker connectors, plan executor
internal/orchestrator/     the model loop: intent in, evidence out
configs/                   example broker policy
docs/                      adding-a-connector.md
scripts/                   harness fitness survey, evidence-loop evaluations
bin/                       entry points: askcass, the probe suite, the digest
scripts/                   evaluation harnesses and their shared library
testdata/workspace/        sample files mounted into the container
testdata/varlog/           sample log files mounted into the container
```

## Quick start

```bash
git clone https://github.com/bindatype/cassandra.git
cd Cassandra
export CASS_AUTH_TOKEN="${CASS_AUTH_TOKEN:-dev-cass-token}"
```

Every command below runs from the repository root. `make help` lists the
targets, and `make install` puts `askcass` on your PATH:

```bash
make install
askcass "how many agents are disconnected right now?"
```

Joining the project rather than just running it? Start with
[docs/onboarding.md](docs/onboarding.md).

### Local

```bash
go test ./...
go run ./cmd/cassd
```

The native server listens on `127.0.0.1:8080` by default and requires a
bearer token on all API routes except `/healthz`. Remote exposure must be
enabled explicitly and should be constrained by host firewall policy or a
TLS-authenticated broker or reverse proxy.

To override the host-run port explicitly:

```bash
CASS_BIND_ADDR=127.0.0.1:18081 go run ./cmd/cassd
```

To listen on all IPv6 interfaces, including IPv4 where the host permits
dual-stack sockets:

```bash
CASS_BIND_ADDR='[::]:18081' go run ./cmd/cassd
```

### Cross-architecture builds

The agent is a pure-Go Linux binary, so the repository supports both
`linux/amd64` and `linux/arm64` builds.

```bash
make build-linux-all
```

This writes:

- `dist/cassd-linux-amd64`
- `dist/cassd-linux-arm64`

### Docker harness

```bash
docker compose up --build
```

The Docker harness publishes the container on host loopback port `18080`
so it does not collide with a direct local `go run` on port `8080` and is
not remotely reachable by default.

The compose harness:

- runs the agent as a non-root user
- mounts sample data read-only at `/workspace` and `/var/log/cass`
- uses a read-only container filesystem
- drops Linux capabilities
- explicitly enables the safe default operation and host-information policies
- writes audit logs to `./runtime/audit.log`

The Dockerfile also honors Docker's target platform arguments, so it can
participate in multi-architecture builds such as `linux/amd64` and
`linux/arm64` when used with a suitable Docker builder.

### Harness fitness

To survey whether the harness contains the read-only operator tools we
actually want to rely on, run:

```bash
make fitness
```

This writes a markdown report to `runtime/harness-fitness.md` with four
tiers:

- core read-only tools that should generally be present
- recommended network or operator probes
- optional specialized network diagnostics
- contextual host or HPC tools that may be absent in a minimal harness

## Example requests

Health:

```bash
curl -fsS http://127.0.0.1:18080/healthz | jq .
```

Capabilities:

```bash
curl -fsS \
  -H "Authorization: Bearer $CASS_AUTH_TOKEN" \
  http://127.0.0.1:18080/v1/capabilities | jq .
```

Host info:

```bash
curl -fsS -X POST http://127.0.0.1:18080/v1/operations \
  -H "Authorization: Bearer $CASS_AUTH_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "operation": "host.info"
  }' | jq .
```

List a directory:

```bash
curl -fsS -X POST http://127.0.0.1:18080/v1/operations \
  -H "Authorization: Bearer $CASS_AUTH_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "operation": "filesystem.list",
    "target": {"path": "/workspace"},
    "params": {"max_entries": 32}
  }' | jq .
```

Tail a log:

```bash
curl -fsS -X POST http://127.0.0.1:18080/v1/operations \
  -H "Authorization: Bearer $CASS_AUTH_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "operation": "filesystem.tail",
    "target": {"path": "/var/log/cass/system.log"},
    "params": {"max_bytes": 2048}
  }' | jq .
```

## Configuration

Configuration is environment-driven:

- `CASS_BIND_ADDR` default `127.0.0.1:8080`
- `CASS_AUTH_TOKEN` required single bearer token
- `CASS_AUTH_TOKENS` optional comma-separated additional valid tokens for rotation
- `CASS_ALLOWED_ROOTS` default `/workspace,/tmp,/var/log/cass`
- `CASS_PROC_ROOT` default `/proc`
- `CASS_ENABLED_OPERATIONS` default `capabilities.describe,host.info,filesystem.list,filesystem.stat,filesystem.read,filesystem.tail`
- `CASS_HOST_INFO_FIELDS` default `hostname,os,arch,cpus,uptime_seconds,kernel_version`
- `CASS_MAX_REQUEST_BYTES` default `65536`
- `CASS_MAX_READ_BYTES` default `65536`
- `CASS_MAX_TAIL_BYTES` default `65536`
- `CASS_MAX_LIST_ENTRIES` default `256`
- `CASS_MAX_PROCESS_ENTRIES` default `256`
- `CASS_AUDIT_PATH` default `runtime/audit.log`
- `CASS_READ_HEADER_TIMEOUT` default `5s`
- `CASS_READ_TIMEOUT` default `15s`
- `CASS_WRITE_TIMEOUT` default `30s`
- `CASS_IDLE_TIMEOUT` default `60s`

Unknown operation or host-information names are rejected during startup.
Setting `CASS_ENABLED_OPERATIONS` to an explicit empty value disables
all operations. If `host.info` is enabled, at least one allowed host field
must be configured.

To opt into bounded process metadata, append `process.list` explicitly:

```bash
export CASS_ENABLED_OPERATIONS='capabilities.describe,host.info,filesystem.list,filesystem.stat,filesystem.read,filesystem.tail,process.list'
```

The audit log is forced to mode `0600`. Authenticated events contain a
stable one-way token fingerprint as `caller_id`; bearer tokens are never
written to the log. Filesystem events also contain the requested
`target_path`. If an authenticated result cannot be audited, the agent
withholds it and returns `503 audit_unavailable`.

## Broker routing experiment

Broker v0 plans; `cass-broker-exec` executes. Neither listens on a
network port. The planner turns a small structured intent into a
deterministic route plan; the executor dispatches each step to a
connector.

Policy is enforced twice. The planner authorizes an intent; the executor
requires `-policy` and verifies, before running anything, that the plan it
was handed is one that policy would have produced. A plan is an ordinary
JSON document arriving from an untrusted caller, so authorization is
re-established rather than assumed: a substituted path, an inflated limit,
a swapped operation, or an extra step all fail verification.

| Intent | Route |
|---|---|
| `fleet.inventory` | Wazuh API `agents.list` |
| `fleet.groups` | Wazuh API `groups.list` |
| `agent.status` | Wazuh API `agents.status` |
| `monitoring.problems` | Zabbix API `trigger.get` |
| `monitoring.history` | Zabbix API `event.get` |
| `live.evidence` | A fixed Cassandra operation from broker policy |
| `database.query` | PegasusDB, one read-only `SELECT` |
| `tickets.open` | RT API, open tickets in allowlisted queues |
| `tickets.for_host` | RT API, open tickets whose subject names the host |

MindRouter is used before routing to propose the structured intent and
after evidence collection to synthesize an answer. It is not permitted to
choose connector URLs, API methods, Cassandra operations, or filesystem
paths.

The broker policy is versioned JSON. `live_hosts` is an authorization
scope for direct Cassandra access, not a replacement fleet inventory;
Wazuh remains the intended inventory source. Resource aliases map to
fixed operations, canonical paths, and limits. The current broker kernel
permits only bounded `filesystem.list`, `filesystem.stat`,
`filesystem.read`, and `filesystem.tail` routes.

Generate a route plan against the safe harness example:

```bash
printf '%s\n' \
  '{"intent":"live.evidence","host":"docker-harness","resource":"system-log"}' \
  | go run ./cmd/cass-broker-plan \
      -policy ./configs/broker-policy.example.json
```

Requests containing unrecognized fields are rejected. In particular,
adding a model-selected `path`, `operation`, or endpoint to the request
does not expand broker authority.

## The evidence loop

A question in natural language, answered from live evidence:

```bash
source ~/.config/cass/env
go run ./cmd/cass-chat \
  -policy ./configs/broker-policy.example.json \
  -wazuh-insecure \
  "what problems are active on dss01?"
```

Add `-trace` to print the decision chain to stderr: what the model
proposed, whether policy allowed it, and what executed. A denied request
shows where it stopped and executes nothing.

The same path without a model, one step per pipe:

```bash
echo '{"intent":"monitoring.problems","host":"dss01"}' \
  | go run ./cmd/cass-broker-plan -policy ./configs/broker-policy.example.json \
  | go run ./cmd/cass-broker-exec -policy ./configs/broker-policy.example.json
```

Both halves take the policy. The planner uses it to authorize; the executor
uses it to verify what it was given.

Model selection is `-model`, then `CASS_MODEL`, then the compiled
`gemma4-31b-vllm` fallback. Deployments should set `CASS_MODEL` to a
MindRouter alias such as `default-agent`; use `-model` for a one-off
challenger. Do not change a deployment default without rerunning the
evaluation suite -- and note that as of 2026-09-04 the gateway serves exactly
one model, so the comparison that is supposed to choose the default currently
has nothing to compare. See "Which model to use" in `docs/onboarding.md`.

### What it can and cannot answer

These intents, and nothing else:

| Ask about | Intent | Source |
|---|---|---|
| agent inventory and connection state | `fleet.inventory` | Wazuh API |
| which agent groups exist and how big each is | `fleet.groups` | Wazuh API (counts from Wazuh, not tallied from a page) |
| one agent's state, by exact name | `agent.status` | Wazuh API |
| active problem triggers, optionally per host | `monitoring.problems` | Zabbix API |
| what happened during a past window | `monitoring.history` | Zabbix API (event log) |
| a file, host facts, uptime, disk, network or listening ports from an endpoint | `live.evidence` | Cassandra endpoint agent (`cassd`, deployed on sgtstubby and winston) |
| aggregate/ad hoc HPC accounting questions | `database.query` | PegasusDB (one read-only `SELECT`) |
| open tickets in allowlisted queues | `tickets.open` | Request Tracker REST 2.0 |
| open tickets mentioning a host, by subject | `tickets.for_host` | Request Tracker REST 2.0 |

`tickets.open` and `tickets.for_host` accept `since`/`until`, bounding a
ticket's `Created` date -- ticket age, not last activity, and unlike
`fleet.inventory`'s connection state, a `Created` date never moves
retroactively, so the bound can only narrow which open tickets are in view,
never hide one that is still open. `total_matching` and
`breakdown.tickets_by_queue` reflect Request Tracker's own exact count for
the bounded query.

Request Tracker evidence is metadata only -- subject, queue, status, owner,
and dates. Ticket content and transaction history are never fetched; see
"How sensitive is the content?" in
[docs/adding-a-connector.md](docs/adding-a-connector.md).

How a second agent should reach the broker -- Unix socket versus TLS, and what
changes in the threat model once the token crosses a wire -- is argued in
[docs/beyond-loopback.html](docs/beyond-loopback.html). It is a decision memo
rather than a guide: nothing in it is built yet.

What the agent should be able to do beyond listing and stat-ing files -- and
the one question that has to be settled first, whether it may execute programs
at all -- is in [docs/cassd-capabilities.md](docs/cassd-capabilities.md). It
records the current capability state as well as the proposal, so it is the
place to look for what is enabled where.

Only intents whose connector is configured are offered to the model. Endpoint
evidence is enabled by `CASS_AGENT_CONFIG`, a host-to-agent map held in the
operator environment, never in a route plan. Each host has its own endpoint
and bearer token, and remote agents must use HTTPS:

**One endpoint agent is deployed**, on sgtstubby, as of 2026-09-16. It is a
systemd service bound to loopback, running under a `DynamicUser` with the
filesystem read-only in its own mount namespace and `@mount` denied outright.
It enables three operations -- `capabilities.describe`, `filesystem.list` and
`filesystem.stat` -- over two roots, `/var/log` and `/tmp`. `live.evidence`
answers. The unit, the environment template and the install runbook are in
`deploy/`.

Two things that deployment does not change. The agent enforces
`CASS_ALLOWED_ROOTS` and its enabled-operation list; it does **not** know the
broker's resource aliases, which exist only broker-side. So the policy bounds
what Cassandra issues, not what a token holder can ask for -- anyone with the
bearer token can call the agent directly for any enabled operation on any path
under the allowed roots. The roots are the real boundary, which is why they are
narrow.

And an agent that is *configured* is offered to the model whether or not it is
*running*: intents are derived from the connectors the executor can reach, not
from their health. A stopped agent produces an execution failure that returns
to the model as a correctable tool error and spends one of its turns.

```bash
export CASS_AGENT_CONFIG='{
  "sgtstubby.arc.gwu.edu": {
    "endpoint": "https://sgtstubby.arc.gwu.edu:8443",
    "token": "the-read-only-agent-token-for-sgtstubby"
  }
}'
```

`http://` is accepted only for a loopback development agent. The connector
does not follow redirects, so an agent cannot redirect its bearer token to a
different destination.

There is **no** source for vulnerabilities or CVEs, installed packages,
patch level, log contents, user accounts, configuration, or performance
history. Asking anyway should produce a refusal rather than an answer
drawn from the nearest available source; there are prompt rules and tests
enforcing that, because an early version answered a CVE question from
Zabbix trigger data and reported "no critical CVEs" for a host that did
not exist.

Wazuh vulnerability data lives in the Indexer, not the API. `/vulnerability`
returns 404 on 4.14.5. Reaching it needs an SSH tunnel and a separate
credential; see the Wazuh Interaction Guide.

### Runtime environment

Credentials live in a file that is sourced explicitly, never in the
repository:

```bash
mkdir -p ~/.config/cass && chmod 700 ~/.config/cass
umask 077
cat > ~/.config/cass/env <<'ENVEOF'
export MINDROUTER_API_KEY=...
export CASS_MINDROUTER_ENDPOINT=http://localhost:8000
export CASS_MODEL=default-agent
export CASS_ZABBIX_ENDPOINT=https://zabbix.example.edu/api_jsonrpc.php
export ZABBIX_RO_TOKEN=...
export CASS_WAZUH_ENDPOINT=https://wazuh.example.edu:55000
export WAZUH_API_USERNAME=...
export WAZUH_API_PASSWORD=...
export CASS_RT_ENDPOINT=https://rt.example.edu
export RT_API_TOKEN=...
export CASS_RT_QUEUES=Ops,Helpdesk
ENVEOF
chmod 600 ~/.config/cass/env
```

`CASS_RT_QUEUES` is a comma-separated allowlist of RT queue names. An
empty or unset value refuses to construct the RT connector: there is no
safe default queue set, so a plan that needs RT and finds no queues
configured fails closed rather than searching every queue in the instance.
Prefer a dedicated read-only RT API token scoped to those queues, the same
way `rts_wazuh_api_ro` is scoped for Wazuh.

Note `export`. A variable merely set in `~/.bashrc` is visible to an
interactive shell but not inherited by child processes, which has cost
time on three separate occasions.

`-wazuh-insecure` is required where the Wazuh manager presents a
self-signed certificate. It warns rather than defaulting to trust.

## Evaluations

```bash
source ~/.config/cass/env
make eval-zabbix    # one model against the monitoring plane
make eval-models    # several models, scored on routing and accuracy
```

Both fetch ground truth live and write a report to `runtime/`. Counts that
move during a run are bounded by sampling before and after each call.

Two rules learned the hard way. Any figure a reader might act on is
computed in Go and placed in `Evidence.Summary`; a model asked to tally
275 records answered 55 against a true 52, and asked for a total reported
the page limit of 25 against a true 1841. And be suspicious of the grader
before the model: during the first survey it failed correct answers over a
thousands separator and a regex that would not match a single digit.

## Adding a data source

See [docs/adding-a-connector.md](docs/adding-a-connector.md) for the
connector contract, the five places a new source touches, and the
invariants every connector must uphold.

## Empirical catalog workflow

Phase One is also a research exercise. For each admin or diagnostic task
we perform in the Docker harness, we should record:

- the task
- the operations actually used
- missing fields or limits that blocked progress
- candidate primitive splits or merges

That dataset should drive the finite operation catalog instead of
guesswork.
