---
name: cassandra
description: Answer GWU RTS infrastructure questions via the askcass CLI.
version: 1.0.0
author: Glen Maclachlan
license: Internal
platforms: [linux, macos]
metadata:
  hermes:
    tags: [infrastructure, monitoring, ops, rts]
    category: devops
    related_skills: []
    config: {}
---

# Cassandra Skill

Routes GWU RTS infrastructure questions — Wazuh agent state, Zabbix problems,
Request Tracker tickets, Slurm/Pegasus job accounting, or a specific managed
host — through `askcass`, a read-only policy broker. It answers by calling
that CLI, never by inventing its own RT/Zabbix/Wazuh API calls or hunting the
system for a client (`rt`, `curl`, etc.). Going around `askcass` loses the
policy checks, the source allowlists, and the "an absence must never read as
a zero" guarantees the broker exists to provide.

## When to Use

The user asks about the state of GWU RTS-managed infrastructure: disconnected
Wazuh agents, firing Zabbix problems, open or aging RT tickets in allowlisted
queues, Slurm job accounting, or what's broken on a specific host.

Not for anything else. This skill has no reach beyond what `askcass` itself
can answer — five read-only sources, nothing more.

## Prerequisites

`askcass` wraps a broker with real credentials behind it. This skill is
useless without that already working — it does not replace any of the
following, only tells the agent the CLI exists once it does:

1. **Repo access and a working toolchain.** `git clone` the Cassandra repo,
   then `go test ./...` — no credentials or network required for this step.
2. **Your own credentials, never someone else's.** `~/.config/cass/env`,
   mode `0600`, with your own MindRouter API key and your own tokens for
   whichever sources you need. Do not copy another person's env file or
   share a login — see `docs/onboarding.md` in the repo, section "Use your
   own accounts," for why this matters (credential attribution, not trust).
3. **`make install`**, so `askcass` is on `PATH`.
4. **Confirm it works standalone, before trusting this skill at all:**
   `askcass "how many agents are disconnected right now?"` should return a
   real answer in a few seconds. If it doesn't, fix that first — see
   Verification below.

## How to Run

Use `terminal` to run:

```
askcass "<the question, in plain English>"
```

and relay its output. Add `-trace` if asked to explain how an answer was
reached. If `askcass` is not found on `PATH`, stop and say Prerequisites
aren't met — do not fall back to raw API calls, a guessed CLI, or hand-written
SQL. That fallback is the specific failure this skill exists to prevent: a
bare model asked an RT question with no broker underneath it will go looking
for an `rt` binary, find nothing, and give up having accomplished nothing
useful — observed directly, 2026-09-29, on an install that had this skill's
prose but not `askcass` itself.

## Quick Reference

| Source | Ask about | Example |
|---|---|---|
| Wazuh | agent connectivity | "how many agents are disconnected right now, and any in a critical group?" |
| Zabbix | firing problems | "what problems started since yesterday, by severity?" |
| Request Tracker | tickets | see Pitfalls — bound the age explicitly |
| Pegasus | Slurm job accounting | "how many jobs failed in the last 7 days?" |
| cassd | one host's state | "what is broken on dss01?" |

## Procedure

1. Take the infrastructure question as asked.
2. Run `askcass "<question>"` via `terminal`.
3. If it answers, relay the answer as given — don't round a stated
   truncation or scope note off the reply, that note is part of the answer.
4. If it refuses citing truncation, ordering, or ambiguity (see Pitfalls),
   rephrase with an explicit bound and try once more before giving up.
5. If it reports a source "unavailable" or "not covered," that's almost
   always a missing credential on your own account, not an outage. Don't
   tell the user the service is down — say the source isn't configured for
   you and point at Prerequisites.

## Pitfalls

- **Unbounded RT age questions return the wrong page, and `askcass`
  correctly refuses to guess past it.** Confirmed live, `askcass "What are
  the 5 oldest open tickets in RT?"` on 574 matching, open tickets: RT
  returns the 100 *newest* by default, and `askcass` reported it could not
  determine the oldest from a newest-first, truncated page — rather than
  answering from data it knew was the wrong slice. That refusal is correct
  behavior, not a bug to route around. Ask it the way that actually works
  instead: give an explicit age bound, e.g. *"which tickets are still open
  and were created more than 30 days ago? List the 5 oldest, with subject,
  owner, and days open."* Setting an explicit `until` bound with no `since`
  is what flips RT's sort to oldest-first.
- **Never try to find or invoke `rt`, `curl` against RT/Zabbix/Wazuh
  directly, or write SQL yourself.** `askcass`'s connectors already do this,
  read-only and policy-checked, with credentials this skill never sees.
  Working around them defeats the entire reason `askcass` exists instead of
  a general-purpose shell.
- **A stated refusal is information, not failure.** "Could not determine
  X because the evidence was truncated/ordered wrong/out of scope" is
  `askcass` telling you exactly what it does and doesn't know. Pass that
  through rather than smoothing it into a guess.
- **`host` takes exactly one hostname per call — never a list.** Asking about
  several nodes in one question (`"...for gpu039, gpu002, hmm001, and
  gpu004..."`) fails immediately with `host contains an unsupported
  character`. Confirmed live, 2026-09-29: an agent that didn't know this
  spent six sequential `askcass` calls bisecting a four-host question by
  trial and error — each paying the full rebuild-on-every-run cost `askcass`
  always pays — before landing on what was obvious from the start: one call
  per host. For N hosts, make N separate `askcass "<question about one
  host>"` calls directly. Don't try the combined phrasing first and don't
  retry by splitting the list in half; go straight to one call per host.

## Verification

```
askcass "how many agents are disconnected right now?"
```

should return a real number, with a source citation, in a few seconds. If it
errors or times out, that's a Prerequisites problem (credentials, PATH, or
toolchain) — fix that before assuming this skill or `askcass` itself is
broken.
