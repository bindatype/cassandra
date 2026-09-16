# Onboarding a contributor

For a second developer joining Cassandra to add an API connector. Covers
accounts, environment, the git workflow, and how two people add sources to
the same broker without stepping on each other.

The technical contract for a connector lives in
[adding-a-connector.md](adding-a-connector.md). This document is about
everything around it.

## Use your own accounts

Work under your own Unix account on the runtime host and your own GitHub
identity. Do not share a login, even between people who trust each other.

Trust is not the reason to separate accounts. Attribution is. When a
credential leaks, a query behaves unexpectedly, or something needs to be
revoked, the question is always *which person did this*, and a shared
account cannot answer it. The project has already recorded this failure
mode in two places: the broker's `caller_id` identifies a credential
rather than a person, and the gateway risk register carries the same
finding for shared API keys. Adding a third instance would be a choice, not
an accident.

Practically this means:

- your own shell account on the runtime host
- your own MindRouter API key, named for its purpose, so it can be revoked
  without affecting anyone else
- your own `~/.config/sroiaaa/env`, mode `0600`
- your own GitHub account with collaborator access on the repository

Shared *service* credentials such as a read-only monitoring account are a
different case and may reasonably be shared, since they identify a role
rather than a person. Personal credentials are not.

## Setup

### 1. Repository access

You need collaborator access on the repository, or a fork. For two
partners working closely, collaborator access and shared branches is
simpler than forks and avoids a round trip on every change.

```bash
git clone https://github.com/bindatype/cassandra.git
cd Cassandra
go test ./...
```

If the tests pass you have a working toolchain. They need no credentials
and no network: every connector is tested against an in-process HTTP
server.

### 2. Credentials

Runtime configuration lives in a file you source explicitly. Never in
`~/.bashrc`, never in the repository.

```bash
mkdir -p ~/.config/sroiaaa && chmod 700 ~/.config/sroiaaa
umask 077
cat > ~/.config/sroiaaa/env <<'ENVEOF'
# The model gateway. Needed by everything that asks a question.
export MINDROUTER_API_KEY=...
export SROIAAA_MINDROUTER_ENDPOINT=http://localhost:8000
# Prefer a role alias so the gateway can change its backing model without a
# client deployment. Use the served model name until the alias is provisioned.
export SROIAAA_MODEL=default-agent

# Zabbix: monitoring problems and the event log.
export SROIAAA_ZABBIX_ENDPOINT=https://zabbix.example.edu/api_jsonrpc.php
export ZABBIX_RO_TOKEN=...

# Wazuh: agent inventory and connection state.
export SROIAAA_WAZUH_ENDPOINT=https://wazuh.example.edu:55000
export WAZUH_API_USERNAME=...
export WAZUH_API_PASSWORD=...
# Agents in these groups are escalated when they go down. Without it the
# check does not run, and the evidence says so rather than reporting zero.
export SROIAAA_WAZUH_CRITICAL_GROUPS=RTS_Ops,Viper

# Scheduler accounting. Needed by eval-pegasus and the morning digest.
export SROIAAA_PEGASUS_DSN='readonly:PASSWORD@tcp(db.example.edu:3306)/pegasusdb?timeout=10s&readTimeout=30s&parseTime=false'

# Request Tracker tickets. Metadata only -- subject, queue, status, owner and
# dates, never ticket bodies. SROIAAA_RT_QUEUES is a required allowlist: unset,
# the connector refuses to construct rather than searching every queue, so
# tickets.open and tickets.for_host are withheld from the model entirely and it
# will report RT as unavailable.
export SROIAAA_RT_ENDPOINT=https://rt.example.edu
export RT_API_TOKEN=...
export SROIAAA_RT_QUEUES=Ops,Helpdesk

# Endpoint agents: policy host -> one HTTPS endpoint and its own bearer token.
# Keep this in the sourced private env file, never in broker policy or a shell
# flag. HTTP is accepted only for a loopback development agent.
export SROIAAA_AGENT_CONFIG='{
  "sgtstubby.arc.gwu.edu": {
    "endpoint": "https://sgtstubby.arc.gwu.edu:8443",
    "token": "..."
  }
}'

# NetBox: source of truth for what a device is, where it lives, and what
# address it holds. No connector yet -- these are read by bin/netbox-probe.sh,
# which is the reconnaissance step that comes before one.
export SROIAAA_NETBOX_ENDPOINT=https://netbox.example.edu
export NETBOX_RO_TOKEN=...
# This deployment serves only its leaf certificate, so the chain cannot be
# built from the system trust store. Pin the issuing intermediate rather than
# disabling verification; see the NetBox Interaction Guide for how to fetch it.
export SROIAAA_NETBOX_CACERT=$HOME/.config/sroiaaa/netbox-ca.pem

# Where each answered question is recorded. Yours, not shared.
export SROIAAA_BROKER_AUDIT=$HOME/.local/share/sroiaaa/broker-audit.jsonl
ENVEOF
chmod 600 ~/.config/sroiaaa/env
mkdir -p ~/.local/share/sroiaaa
```

Ask for the real values rather than copying them out of someone's shell
history or another user's file. The Zoom variables are deliberately absent:
only the host that runs the 04:45 digest needs those, and a second copy of a
webhook secret is a second thing to rotate.

Every line needs `export`. A variable that is only *set* is visible to your
interactive shell but is not inherited by the programs you run. This has
cost time on three separate occasions in this project, including once
where the failure looked like a broken credential rather than a missing
one, and once where a scheduled job failed silently at 04:45 because the
values lived in `~/.bashrc`, which `cron` does not read.

### 3. Verify end to end

```bash
source ~/.config/sroiaaa/env
make eval-zabbix
```

This asks six real questions against live monitoring data and grades the
answers. It takes about a minute. Success looks like:

```
model: gemma4-31b-vllm   subject host: dss01
  total_problems      6.2s  PASS
  host_scoped         1.4s  PASS
  ...
===== gemma4-31b-vllm: 6/6 passed, avg 5.4s =====

report written to /home/you/Cassandra/runtime/eval-zabbix.md
```

**Where the output goes.** Every evaluation prints to your terminal *and*
writes `runtime/<name>.md` inside the repository. The suffix is `.md`, which
is why `find . -name eval-zabbix` finds nothing — look for `runtime/` in the
repo, or read the last line the script prints, which gives the full path.

`runtime/` is git-ignored. Nothing you run here commits anything.

If it does not pass, see [Troubleshooting](#troubleshooting) below.

### 4. Put `ask` on your PATH

```bash
make install
ask "how many agents are disconnected right now?"
```

`ask` is the everyday entry point: it sources your environment, rebuilds the
binary, and runs one question through the evidence loop. `make install`
symlinks it into `~/bin` if you have one, otherwise `~/.local/bin`, or
`make install PREFIX=...` to choose. It does not edit your shell config: if
that directory is not already on your PATH it prints a note, and putting it
there is your job. `make uninstall` removes the symlink.

Entry points live in `bin/`: `ask`, `zabbix-probe.sh`, and `zoom-digest.sh`,
which is the one cron runs. `scripts/` holds the evaluation harnesses and a
shared library that is not meant to be run directly. Nothing requires you to
put `bin/` itself on your PATH, and you should not: a repository on your PATH
means any commit becomes an executable you run by typing a common word.

It rebuilds every time, deliberately. A hand-placed binary in `~/bin` was
found two days and four connector changes behind the source, still answering
with behaviour that no longer existed — and nothing about the output said so.
A symlink to a script that rebuilds cannot drift.

Add `-model <name>` to try another model, or `-trace` to see the intent the
model proposed and what policy did with it:

```bash
ask -trace "what is broken on dss01?"
```

### 5. What else you can run

`make help` lists everything. The two worth knowing on day one:

```bash
make probe          # ask the Zabbix trap questions, judge the answers yourself
sh bin/zabbix-probe.sh -l    # list those questions; needs no credentials
```

`make probe` is not an evaluation. It asks the questions where a *wrong*
answer reads as good news, and prints what a right and a wrong answer look
like for each, for you to judge. It is the fastest way to build a sense of
what this system does badly. It found a live false all-clear on its first
run.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `missing environment: ...` | The env file is not sourced in *this* shell, or a line lacks `export`. Sourcing does not survive a new terminal. |
| Zabbix or Wazuh "connector error" | Usually a missing credential rather than a broken service. Check the variable exists: `printenv ZABBIX_RO_TOKEN \| wc -c`. |
| The model says a source is "unavailable" or "not covered" | Almost always an unset variable, not an outage. An intent whose connector is not configured is withheld from the model, which cannot tell the difference. `ask` prints a `note:` line on stderr naming every source that is off and the variables that turn it on -- read that first. |
| NetBox `http=000` | Not a bad token — nothing was sent. Either TLS (the chain is incomplete without `SROIAAA_NETBOX_CACERT`) or IPv6 (the AAAA record does not route; `curl -4` proves it). `bin/netbox-probe.sh reach` needs no token and separates the two. |
| `make: *** No rule to make target` | You are not in the repository root. |
| An answer that is confidently wrong | Expected, and the point of the probe suite. Record it. Most rules in the prompt exist because of one of these. |
| Answers ignore a feature you just added | You are running a stale binary. `ask` and the digest rebuild every run; a copy in `~/bin` does not. Use `make install`, not `cp`. |
| Everything passes but the answer looks thin | Check `runtime/*.md` for the graded detail; the terminal summary is a summary. |

A question answered from missing credentials tends to fail in the
reassuring direction — "no problems found" rather than "I could not ask".
If an answer seems too calm for the state of the estate, check your
environment before you believe it.

## Which model to use

Model selection is, in descending precedence: the per-call `-model` flag,
`SROIAAA_MODEL`, then the compiled fallback **`gemma4-31b-vllm`**. A deployment
should set `SROIAAA_MODEL` to a MindRouter role alias such as `default-agent`;
that lets the gateway change the backing model without rebuilding Cassandra.
Use `-model` to try a challenger without changing the deployment default.

The evaluation harnesses resolve the same way, through
`eval_common.default_model()`, so a harness cannot measure a different model
from the one the deployment runs. It could before: seven scripts each held
their own hard-coded default.

**As of 2026-09-04 the gateway serves exactly one model.** Ask it rather than
trusting this page:

```bash
curl -s -H "Authorization: Bearer $MINDROUTER_API_KEY" \
  "$SROIAAA_MINDROUTER_ENDPOINT/v1/models"
```

The compiled fallback should not be changed without rerunning the comparison
that chooses it, and right now that comparison cannot be run -- there is no
second model to run it against. `gemma4-31b-vllm` has been exercised end to
end (RT shape 40/40, Zabbix 6/6 at 5.4s average) but it has not been graded
against an alternative. Restore the grading the first time a second model is
served.

```bash
python3 scripts/eval_headtohead.py <model> <other>   # needs two; no default pair
```

That suite grades six question shapes with ground truth computed live: an
aggregate, a grouped result that engages the row cap, a two-step schema
lookup, a question with no data source that must be refused, a concept with no
matching column that must be derived rather than refused, and a listing that
exceeds the cap. When it last ran as a comparison, on 2026-08-28, `gemma4:31b`
scored 30/30 at 9.8s per question against `llama3.3:latest` at 28/30 and
15.2s. Neither model is served any more.

Earlier single-question comparisons could not separate those two, and one of
them picked a different winner. If you are evaluating a model, use the suite
rather than a question you like: a model can be perfect on an aggregate and
still answer a different question than the one asked.

### Changing the prompt rather than the model

Two more harnesses exist for that, and they are worth knowing about before
you edit `internal/orchestrator/prompt.md`:

```bash
make eval-prompt-ab   # two prompts, same binary, on the questions that matter
make eval-lead        # one rule in isolation
```

The prompt has a hard budget. Every model on this gateway is capped at 32k
tokens whatever its native context, and the prompt travels alongside up to
64 KB of evidence on the same turn. There is currently about **8 KB of
headroom**, for prompt growth *or* evidence, not both. `make test` fails if
you exceed it.

Read `Cassandra-model-evaluation-results.md` in the Obsidian vault before
running one. It documents four ways these harnesses have already produced
confidently wrong numbers — stale ground truth, collapsed grading dimensions,
a baseline that could not express the thing being measured, and a grader that
could not parse the sentence it was grading. Three were committed by the person
who wrote the harness, on the day they wrote it; the fourth outlived their own
fixes and was found by someone else.

**Every new rule arrives with a measurement or an admission.** The prompt is
the one file in this project that grows by accretion, because each rule is
added on the day some answer was wrong and nothing ever forces a second look.
So a new rule needs one of two things before it lands: an eval case that
targets it, or a line in `Cassandra-prompt-change-log.md` saying it is unmeasured
and why it is being kept anyway. Both are acceptable. Silence is not, because a
prompt where proven guardrails and remembered folklore look identical cannot be
trimmed by anyone who was not there.

The lead rule is the worked example, and it cuts both ways. Over 72 asks,
`make eval-lead` moved the lead rate from 8/29 to 15/36 — p=0.30, which is not
a demonstrated effect. The same run moved answers that never found the number
at all from 7/36 to 0/36, p=0.011, which is significant and is *not what the
rule was written to do*. The rule stays, recorded as unmeasured-but-retained.
Do not let the second number be reported as evidence for the first: a
significant result that belongs to a different claim is the most convincing
way these harnesses lie.

## Adding an API

Read [adding-a-connector.md](adding-a-connector.md) first. It defines the
`Connector` interface, the five files a new source touches, and the
invariants each connector must uphold. Those invariants are not style
preferences; each one exists because something produced a wrong answer
during development.

Then:

```bash
git checkout -b feat/<source>-connector
```

Build in this order. Each step is independently reviewable and the early
ones surface disagreements before you have written much:

1. **Declare the source and intents** in `internal/broker/types.go`. Small
   and worth doing first, because it is also how you claim the name.
2. **Add planning** in `internal/broker/router.go`, with tests. At this
   point the intent can be authorized and denied but nothing executes.
3. **Implement the connector** in `internal/connector/<source>.go`, with
   tests against `httptest`. No network, no credentials.
4. **Wire configuration** into `cmd/cass-broker-exec` and
   `cmd/cass-chat`.
5. **Expose the intent** to the model in `internal/orchestrator/session.go`
   — the tool schema enum and the system prompt, including what the intent
   does *not* cover.
6. **Add evaluation cases** to `scripts/`.

Then open a pull request. Keep `main` reviewable: it is currently pinned to
the commit under independent review, and merges should be deliberate.

## Working in parallel

Two people can add sources at the same time. Connector implementations are
independent files and will never conflict. Four files are shared, and all
four are registration points:

| File | What you add | Conflict risk |
|---|---|---|
| `internal/broker/types.go` | a `Source` and `Intent` constant | low, adjacent lines |
| `internal/broker/router.go` | a `case` in `Plan()` | low, adjacent cases |
| `cmd/cass-broker-exec/main.go` | a block in `buildConnectors` | low |
| `internal/orchestrator/session.go` | an enum entry and prompt text | **moderate**, the prompt is prose |

The conflicts are mechanical rather than semantic — both sides are adding
to a list — so they resolve easily. Two habits keep it painless:

- **Claim the name first.** Land a small pull request adding just the
  `Source` and `Intent` constants before building the rest. It reserves the
  name, makes the intent visible early, and gives the other person
  something to rebase onto instead of discovering a collision at merge.
- **Rebase before opening a pull request**, so conflicts surface on your
  branch rather than in review.

The system prompt is the one place where two additions can genuinely
disagree rather than merely collide, because it is prose describing what
the model may and may not do. Treat prompt changes as requiring the same
review attention as code: a careless edit there can undo a safety property
without failing a test.

### The refactor that would remove this friction

Dispatch is currently a `switch` in `router.Plan()` and a chain of `if`
blocks in `buildConnectors`. Moving to an explicit registry, where a source
registers itself and the shared files carry only a loop, would reduce the
shared surface to almost nothing.

This is already recorded as a planned step in the project notes for the
endpoint operation catalog, for the same reason: the centralized `switch`
is fine while the surface is small and becomes a bottleneck as it grows. A
second contributor is exactly the pressure that makes it worth doing. It is
not a prerequisite for the first new connector, but if a third source is
coming, do it before rather than after.

## Worked example: Request Tracker

What has to be settled before writing code.

**Which REST API.** RT 5.x has REST2 at `/REST/2.0/`, JSON, with
`Authorization: token <token>`. RT 4.x has REST1 at `/REST/1.0/`, a bespoke
line-oriented format that needs its own parser. Confirm the version first;
it changes the amount of work substantially.

**A read-only token on a dedicated account.** Not a personal login. RT can
modify tickets, so the credential should not be able to.

**Which queues are in scope.** An allowlist in configuration, not a
parameter a plan can set.

**Whether ticket bodies are in scope.** This is the decision that most
needs making before rather than after. Zabbix and Wazuh return operational
telemetry. RT returns human correspondence, which routinely contains user
details and credentials pasted into logs by people asking for help. The
safe default is metadata only — subject, queue, status, owner, dates — with
body text excluded unless there is a specific decision to include it. Once
evidence flows to a model it has left the building; decide first.

**Which operations are reachable.** RT is write-capable. The connector's
action table is the control: if `ticket.comment` and `ticket.resolve` are
not compiled in, they cannot be reached regardless of what a plan or a
model asks for. Do not rely on the credential being read-only as the only
safeguard.

### Why it is worth adding

The loop can already report that a host has had a filesystem panic since a
given date. The obvious next question is whether anyone is already working
on it, and a ticketing system is the only thing that can answer it.

A `tickets.for_host` intent would also be the first to combine two sources
in a single plan: monitoring state and human response side by side. That is
a genuinely different capability from either system alone, and it is the
point at which the broker's multi-step route plan earns the shape it
already has.
