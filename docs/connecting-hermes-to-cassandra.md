# Connecting Hermes to Cassandra

How to ask Cassandra questions from your own Hermes, on a laptop or a
workstation, over MCP. When it works, "ask cass: what are the oldest open
tickets?" in Hermes comes back with an answer drawn from RT, Zabbix, Wazuh,
PegasusDB or a host. You never hold any of those systems' credentials.

Cassandra runs on sgtstubby as the `cass-mcp` service, at
`https://sgtstubby.arc.gwu.edu:8443/mcp`. Hermes sends your own MindRouter key
with every question. Cassandra checks the key against its allowlist, then
asks MindRouter whether the key is still valid, then answers on your key.

Expect about 15 minutes. Steps 1 and 2 need Glen; the rest you do yourself.

## What you need

- **Campus network or the VPN.** Port 8443 is not reachable from outside.
- **Hermes** installed and working with a model.
- **Your own MindRouter API key.** Never use someone else's: Cassandra records
  every question under the name your key maps to.
- **A checkout of this repository on the `glendev` branch**, for the skills
  in step 6.

## 1. Get your key onto the allowlist

Compute your key's hash. Only the hash is shared; the key never leaves your
machine. On Linux:

```sh
printf '%s' "$YOUR_MINDROUTER_KEY" | sha256sum
```

On macOS:

```sh
printf '%s' "$YOUR_MINDROUTER_KEY" | shasum -a 256
```

Send Glen the 64-character hex string, and the name you want to appear in
the audit log. He adds a line `sha256:<hash> <name>` to the allowlist, which
takes effect without a restart.

`printf '%s'` matters: `echo` adds a newline, which changes the hash. On a
machine with a Go toolchain, `go run ./cmd/cass-mcp -hash` from the checkout
reads the key on stdin and prints the finished line.

## 2. Get the certificate authority file

Until the university certificate is in place, `cass-mcp` uses a development
certificate signed by a small private CA, "Cassandra MCP development CA",
valid to October 2027. Get `ca.pem` from Glen. It is a public certificate,
not a secret. Save it as `~/.config/cass/cass-mcp-dev-ca.pem`
(`mkdir -p ~/.config/cass` first if that folder doesn't exist).

Never turn certificate verification off to get past this step.

## 3. Put the key where Hermes can read it

Add a line to `~/.hermes/.env`. Write it as `KEY=value`, with no `export`:

```sh
echo 'CASS_MCP_KEY=<your MindRouter key>' >> ~/.hermes/.env
chmod 600 ~/.hermes/.env
```

## 4. Configure the server

```sh
hermes config set mcp_servers.cassandra.url https://sgtstubby.arc.gwu.edu:8443/mcp
hermes config set mcp_servers.cassandra.headers.Authorization 'Bearer ${CASS_MCP_KEY}'
hermes config set mcp_servers.cassandra.ssl_verify ~/.config/cass/cass-mcp-dev-ca.pem
```

Keep the single quotes around `Bearer ${CASS_MCP_KEY}`. Hermes fills in the
variable from `.env` when it connects, so the key itself never goes into
`config.yaml`.

On sgtstubby itself, the URL can be `https://localhost:8443/mcp`.

## 5. Test the connection

```sh
hermes mcp test cassandra
```

You should see:

```
✓ Connected
✓ Tools discovered: 1
    cass_ask   Ask Cassandra, GW RTS's read-only infrastructure eviden...
```

If you don't, go to [When it doesn't work](#when-it-doesnt-work) before
continuing.

## 6. Tell Hermes when to use it

A working connection is not enough. In testing, a connected Hermes asked
about RT tickets replied that it had no access to RT. Asked to "ask cass", it
went looking for a skill with an unrelated name. Hermes needs to be told what
"cass" is.

**A memory entry.** Hermes's memory decides which tool it reaches for more
than its skills do. Add this entry to `~/.hermes/memories/MEMORY.md`. If the
file already has entries, put a line containing only `§` before it.

```
Cassandra ("cass") is GW RTS's read-only infrastructure evidence service. For any question about RT tickets, Zabbix alerts, Wazuh agents, Pegasus jobs (PegasusDB) or host state, call the MCP tool mcp__cassandra__cass_ask with the user's whole question in plain English. "Ask cass" means call that tool. Report its numbers and ticket IDs exactly as given. Don't ask for RT credentials or endpoints; Cassandra holds them. There is no askcass command on this machine.
```

If `askcass` does work on this machine, as it does on sgtstubby, drop the
last sentence.

**The two MCP skills.** Copy them in from your checkout:

```sh
mkdir -p ~/.hermes/skills/infrastructure
cp -R <checkout>/integrations/hermes-skill/cassandra-mcp ~/.hermes/skills/infrastructure/
cp -R <checkout>/integrations/hermes-skill/rt-ticket-analysis-mcp ~/.hermes/skills/infrastructure/
```

Install the `-mcp` skills, not `cassandra` and `rt-ticket-analysis`. Those
two tell Hermes to run the `askcass` command, which exists only on sgtstubby.
Copy rather than symlink: Hermes warns about skills that resolve outside
`~/.hermes/skills`. Copy them again after you pull an update.

`hermes skills list` should now show `cassandra-mcp` and
`rt-ticket-analysis-mcp` as enabled.

## 7. Small local models: offer the tool directly

By default Hermes keeps MCP tools behind a lookup step. The model has to call
`tool_search`, then `tool_call` with the exact tool name and an `arguments`
object. `gpt-oss:20b` fumbled that step every time in testing: it
abbreviated the tool name, put the question in the wrong field, and hit a
tool-call parse error from ollama. Turning the lookup off offers every tool
directly, and the call then worked first time:

```sh
hermes config set tools.tool_search.enabled off
```

The cost is a little more context per turn. With a handful of tools that is
small. A larger model may manage the lookup step, so try without this setting
first if you prefer.

## 8. First question

**Connect the VPN before you start Hermes.** Hermes connects to MCP servers
once, when a session starts. A session started before the network was ready
stays without Cassandra until you start a new one.

Then, in a new session:

```
ask cass: how many open tickets does each owner have?
```

Expect a short wait (15–30 seconds is normal), then counts per owner from
RT. Cassandra records the question under your name.

## When it doesn't work

Start with `hermes mcp test cassandra`, then look in
`~/.hermes/logs/agent.log` for lines mentioning `mcp` or `cassandra`.

| Symptom | Meaning | Fix |
|---|---|---|
| `Failed to connect to MCP server 'cassandra': CancelledError`, with no `HTTP Request` line before it | No reply from sgtstubby: you are off campus and off VPN, or the VPN was still coming up | Connect the VPN, then start a new Hermes session |
| `401` | No key was sent, or MindRouter rejected it | Check the `CASS_MCP_KEY` line in `~/.hermes/.env` and the quoted `Bearer ${CASS_MCP_KEY}` header |
| `403` | The key is valid but not on Cassandra's allowlist | Step 1. A new MindRouter key needs a new hash |
| Certificate or SSL error | Hermes doesn't trust the development CA | Step 2, and check the `ssl_verify` path |
| Connected, but Hermes says it has no access to RT, or asks what "cass" is | The memory entry is missing | Step 6 |
| `tool_call` errors, or a truncated tool name like `mcp__cassandra__cass_...` | The model is struggling with the lookup step | Step 7 |
| "Cassandra is answering 4 questions already" or "you already have 2 questions running" | All four question slots are in use, or you already have two questions running | Wait a minute and ask again; questions are refused rather than queued |
| Wazuh questions fail | Wazuh is not yet available through `cass-mcp` (a certificate decision is pending) | Use `askcass` on sgtstubby for Wazuh for now |

## What Cassandra will and won't tell you

- Read-only, and only what its sources hold. Ticket metadata, never ticket
  contents.
- RT answers cover the queues Cassandra is configured for: hpchelp, rtshelp,
  change, redcaphelp, alerts and lustrepurge. "Open" currently means status
  new, open or stalled. A search in the RT web interface with other queues,
  or with `Status = '__Active__'`, can give a different count. Say which
  queues you mean when comparing.
- Answers are internal GW IT data, subject to GW data policy. Cassandra and
  its model run locally. If you connect an agent whose model runs in the
  cloud, the answers leave GW, and that is your responsibility. The team
  standard is Hermes on local models.
