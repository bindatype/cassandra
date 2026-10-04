---
name: cassandra-mcp
description: "GW RTS infra questions: call cass_ask (Cassandra MCP)."
version: 1.0.0
author: Glen Maclachlan
license: Internal
platforms: [linux, macos]
metadata:
  hermes:
    tags: [infrastructure, monitoring, ops, rts]
    category: devops
    related_skills: [rt-ticket-analysis-mcp]
    config: {}
---

# Cassandra (MCP) Skill

For a Hermes that reaches Cassandra over MCP instead of running `askcass`,
e.g. on a laptop. Cassandra is GW RTS's read-only infrastructure evidence
service on sgtstubby. It answers questions about Wazuh agents, Zabbix
problems, Request Tracker tickets, Pegasus (Slurm) job accounting, and one
managed host's state. It holds the credentials and applies the policy checks;
this agent never does.

The tool is `mcp__cassandra__cass_ask`. "Ask cass" means call it.

## When to Use

Any question about the state of GW RTS infrastructure: disconnected Wazuh
agents, firing Zabbix problems, open or aging RT tickets, Slurm job
accounting, what is wrong on a specific host.

Not for anything else. Cassandra covers those five sources, read-only.

## Prerequisites

The `cassandra` MCP server configured in `~/.hermes/config.yaml`, with your
own MindRouter key in `~/.hermes/.env` as `CASS_MCP_KEY`, and your key on
Cassandra's allowlist. Check with `hermes mcp test cassandra`: it should
report "Connected" and one tool. Campus network or VPN only.

## How to Run

Call `mcp__cassandra__cass_ask` with one argument, `question`: the user's
whole question in plain English. Relay the answer as given, including its
Scope and Limitation lines. The result also carries the evidence as
structured data; quote figures from there, never retype or recompute them.

Never fall back to `askcass` (it is not installed here), `rt`, `curl`
against RT/Zabbix/Wazuh, or SQL you write yourself. Never ask the user for
RT, Zabbix or Wazuh credentials; Cassandra holds them.

## Quick Reference

| Source | Ask about | Example |
|---|---|---|
| Wazuh | agent connectivity | "how many agents are disconnected right now, and any in a critical group?" |
| Zabbix | firing problems | "what problems started since yesterday, by severity?" |
| Request Tracker | tickets | "which open tickets were created more than 30 days ago? list the 5 oldest" |
| Pegasus | Slurm job accounting | "how many jobs failed in the last 7 days?" |
| cassd | one host's state | "what is broken on dss01?" |

## Pitfalls

- **Give ticket-age questions a bound.** "The 5 oldest open tickets" with no
  bound sees the newest page; ask "created more than 30 days ago, list the 5
  oldest".
- **One host per question.** For several hosts, make one call per host.
- **A refusal or limitation is the answer, not a failure.** Pass it through
  rather than smoothing it into a guess.
- **"Source unavailable" usually means it isn't configured for this
  service, not an outage.** Wazuh questions currently fail through MCP for
  that reason.
- **Errors:** 401 means MindRouter rejected the key; 403 means the key is
  not on Cassandra's allowlist; a timeout means off campus and off VPN; "busy"
  means the four question slots are taken, so try again shortly.

## Verification

`hermes mcp test cassandra`, then ask "how many open tickets does each owner
have?" and expect counts per owner from RT.
