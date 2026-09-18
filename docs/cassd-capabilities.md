# cassd: capabilities, design, and what to add next

**Status:** deployed on two hosts, answering. **Date:** 2026-09-17.
**Audience:** external reviewers. Nothing here assumes prior context.

`cassd` is the endpoint agent for Cassandra, an infrastructure question-answering
system. A model is given a bounded tool; a policy broker decides what that tool
may actually ask for; connectors execute the approved request against Zabbix,
Wazuh, Request Tracker, a MariaDB accounting database, or `cassd`. `cassd` is
the only one of those that is ours, and the only one that can grow new
capabilities by decision rather than by what a vendor exposes.

This document exists to get one architectural question answered before it is
built: **whether `cassd` may execute programs.** Everything else here is
context for that.

---

## 1. What exists today

### Deployment

| | |
|---|---|
| Hosts | `sgtstubby` (also the broker), `winston` |
| Transport | loopback on each host; the broker reaches winston through an SSH forward |
| Identity | systemd `DynamicUser` — exists only while the service runs, owns nothing, no groups |
| Filesystem | `ProtectSystem=strict`; `@mount` denied by seccomp |
| Exposure | 1.1 "OK" per `systemd-analyze security`, both hosts |
| Unauthenticated request | `401` |

### Operations

Ten are implemented in the agent. Eight are routable through the broker. What
is enabled in a given deployment is separate again, and set per host. The three
sets are deliberately different.

| Operation | Implemented | Broker-routable | Enabled |
|---|---|---|---|
| `capabilities.describe` | yes | n/a | yes |
| `host.info` | yes | yes | yes |
| `host.uptime` | yes | yes | default on |
| `host.diskfree` | yes | yes | default on |
| `host.network` | yes | yes | default on |
| `filesystem.list` | yes | yes | yes |
| `filesystem.stat` | yes | yes | yes |
| `filesystem.tail` | yes | yes | yes |
| `filesystem.read` | yes | yes | **no** |
| `process.list` | yes | **no** | **no** |

A deployment that pins `CASS_ENABLED_OPERATIONS` explicitly does not pick up
the three new operations until their names are added to it.

Implementing an operation, exposing it through the broker, and enabling it on a
host are three separate decisions. `process.list` is implemented and
deliberately not routable; the unit also sets `ProtectProc=invisible`, so the
agent could only see its own processes even if it were.

### What a question can actually reach

`CASS_ALLOWED_ROOTS=/var/log,/tmp`, and within that, only these policy
resources:

| Resource | Operation | Target |
|---|---|---|
| `host-facts` | `host.info` | — |
| `log-dir` | `filesystem.list` | `/var/log` |
| `log-dir-metadata` | `filesystem.stat` | `/var/log` |
| `patch-history` | `filesystem.tail` | `/var/log/dnf.rpm.log` |

Two bounds apply, and they are independent. The **policy** decides which
resources a host may be asked for. **Unix permissions** decide what the
unprivileged agent can actually read. On these hosts `/var/log` is `0755` so it
lists, while `/var/log/messages` and `/var/log/secure` are `0600 root:root` and
do not open. That is the intended first posture: reading those would be a
deliberate privilege grant, argued on its own.

### What it answers that nothing else does

Zabbix knows thresholds, Wazuh knows agents, RT knows tickets, the accounting
database knows jobs. None of them knows what kernel a host runs, how long it
has been up, or when it was last patched. `cassd` does, and the first
cross-host question found real drift: `sgtstubby` on `5.14.0-687.26.1`,
`winston` on `687.31.1`.

---

## 2. The design constraint that shapes everything below

**`cassd` does not execute programs.** It reads structured sources — files,
`/proc`, `/sys` — and returns bounded JSON. There is no `exec` anywhere in it,
and its only write is its own audit log.

That is not incidental. It is what `DynamicUser`, `SystemCallFilter`,
`ProtectSystem=strict` and the empty `CapabilityBoundingSet` are protecting,
and it is why a compromised agent is a read-only window onto world-readable
files rather than a foothold.

The proposal below is framed as **"read what those tools read"** rather than
**"run those tools"**, for three reasons.

**Tool availability varies per host; kernel interfaces do not.** A
reconnaissance pass in August across the container and several hosts found `ss`
absent but `netstat` present in one place, `systemctl` absent entirely in
another, and `dmesg` present but returning `Operation not permitted`. An agent
that shells out has capabilities that depend on what someone installed.
`/proc/net/tcp` is there or the kernel is not Linux.

**Parsing human output is brittle.** `ss` and `systemctl` format for people and
change between releases. `/proc` and `/sys` are stable interfaces with
documented formats.

**Exec is the boundary.** Adding it is not an increment on the current design;
it is a different security posture, and it should be argued as one.

---

## 3. Proposed capabilities

Every "readable" below was measured on `winston` (Rocky 9.8) as an
unprivileged user on 2026-09-17, not inferred.

> [!note] Partly superseded, 2026-09-18
> Tier 1 below proposed reading network facts from `/proc` and `/sys` to avoid
> executing anything. That boundary has since been crossed deliberately for a
> bounded set: `host.uptime`, `host.diskfree` and `host.network` run programs.
> `host.network` runs `ip addr show` and `ip route show`, which answers the
> gap Tier 1 names below — IPv4 addresses are not in `/sys` and need netlink,
> which `ip` already speaks.
>
> The exec surface is drawn so that no caller input reaches a command line:
> every argument is a compile-time constant, which is why these operations take
> no target. `journalctl`, `dmesg`, `ps` and `ss` were requested at the same
> time and **deliberately not shipped** — each returns empty or partial output
> under the current unit (`ProtectKernelLogs=yes`, `ProtectProc=invisible`,
> empty `SupplementaryGroups`), and would do so with exit code 0. Each needs a
> named privilege grant first; see section 4.

### Tier 1 — no new boundary

**`network.listeners`** — which ports are open and to what.
Source: `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`. **Readable.**
This is what `ss` and `netstat` parse. Mapping a socket to an owning process
needs `/proc/*/fd`, which an unprivileged agent cannot traverse — so this
reports sockets and states without process attribution. That limit should be
stated in the evidence rather than left for the reader to discover.

**`network.interfaces`** — what links exist and whether they are up.
Source: `/sys/class/net/*/{operstate,address,mtu}`. **Readable.** Winston has
13 interfaces including VLANs and InfiniBand.
Gap: IPv4 addresses are not in `/sys`. `ip addr` gets them over **netlink**,
which would mean either a netlink implementation or a dependency. Interface
name, state, MAC and MTU need neither.

Both fit the existing shape exactly: no path, no parameters, bounded output,
same as `host.info`. Adding them requires no change to the security posture and
no new dependency.

### Tier 2 — needs a decision, not new architecture

**`kernel.messages`** — the ring buffer.
Source: `/dev/kmsg`. **Readable on winston**, because that host has
`kernel.dmesg_restrict=0`. On a host with it set to `1` — a common hardening
default — an unprivileged agent gets nothing. So this capability would work on
some hosts and silently return nothing on others unless it says so.

The ring buffer also carries more than diagnostics. Bounding it to recent
entries, or to matching severities, is a policy question rather than an
implementation one.

### Tier 3 — the architectural question

**`systemd.failed`** — which units are in `failed` state.

This is the capability with the clearest operational value. The probe that
tested it immediately found a real fault: `import-shared\x2dfiles.mount` is in
`failed` state on winston, and nothing in Cassandra can currently see it.

It is also the one that cannot be done by reading a file. There are two ways:

| Approach | Cost |
|---|---|
| Execute `systemctl --failed` | `cassd` gains the ability to run programs. The seccomp filter, `NoNewPrivileges` posture and "it never execs" argument all change. |
| Query systemd over D-Bus | No exec. A new dependency, more code, and a socket the agent must be allowed to reach — `RestrictAddressFamilies` currently permits only `AF_INET`/`AF_INET6`. |

Neither is obviously right. The first is a small change to the code and a large
change to the argument; the second is the reverse.

---

## 4. Questions for reviewers

1. **Should `cassd` ever execute a program?** If the answer is no on principle,
   `systemd.failed` must be D-Bus or must not exist, and that should be written
   down before someone reaches for `exec.Command` to add something small.

2. **Is D-Bus worth it for one capability?** It is a dependency, an unsafe-ish
   socket permission, and real code, for something `systemctl --failed` does in
   one line. The honest comparison is not exec-versus-D-Bus in the abstract but
   whether failed-unit reporting justifies either.

3. **Does a capability that works on some hosts and not others belong here at
   all?** `kernel.messages` depends on `dmesg_restrict`. A capability that
   silently returns nothing on hardened hosts is the failure shape this project
   keeps finding — something missing reported as something that does not exist.
   It can be made to say so, but should it exist?

4. **Is process attribution worth the privilege it costs?** `network.listeners`
   without `/proc/*/fd` traversal gives ports and states but not owners.
   "Port 8099 is listening" is less useful than "cassd is listening on 8099",
   and the difference is a privilege grant.

5. **What is missing from this list?** It came from operational instinct —
   listening ports, interfaces, kernel messages, failed units — rather than
   from an analysis of which questions go unanswered. A reviewer with no stake
   in that instinct may see a better first capability.

---

## 5. Things a reviewer should know are true

These are stated because they are easy to assume the other way.

- The agent has **no write path** outside its own audit log.
- Every request is **authorized by the broker against policy** before it
  reaches the agent, and the agent independently enforces its allowed roots and
  enabled operations. Neither trusts the other.
- The agent **reports its own hostname on every response**, and the connector
  refuses a reply from a host other than the one the plan addressed. This was
  added because the port map lives in two places and can drift.
- Evidence records **what was actually applied** — time bounds, filters,
  ordering — so a narrowed result cannot read as a complete one.
- A result too large for the context is **discarded whole, not truncated**, and
  says so.
- The audit log keeps **every question, its SQL, its refusals, and its
  failures**, and is never pruned.
