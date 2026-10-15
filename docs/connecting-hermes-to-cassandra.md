# Connecting Hermes to Cassandra

How to ask Cassandra questions from your own Hermes, on a laptop or a
workstation, over MCP. When it works, "ask cass: what are the oldest open
tickets?" in Hermes comes back with an answer drawn from RT, Zabbix, Wazuh,
PegasusDB or a host. You never hold any of those systems' credentials.

Cassandra serves MCP through the `cass-mcp` service, at an address your
administrator gives you, of the form `https://cassandra.example.edu:8443/mcp`.
Hermes sends your own MindRouter key with every question. Cassandra checks
the key against its allowlist, then asks MindRouter whether the key is still
valid, then answers on your key.

Expect about 15 minutes. Steps 1 and 2 need your Cassandra administrator; the
rest you do yourself.

## What you need

- **A network that can reach the `cass-mcp` port.** Deployments normally keep
  it off the public internet, so this usually means the site network or its
  VPN.
- **Hermes** installed and working with a model. Hermes Desktop and the
  `hermes` command share `~/.hermes`, so the commands below configure the
  desktop app too; restart it after step 6.
- **Your own MindRouter API key.** Never use someone else's: Cassandra records
  every question under the name your key maps to.
- **A terminal with `curl` and `tar`.** Both come with macOS and Linux; step 6
  uses them to download two small skill folders. No copy of this repository
  is needed.

## 1. Get your key onto the allowlist

Compute your key's hash. Only the hash is shared; the key never leaves your
machine. Paste the key at the silent prompt, so it stays out of your shell
history, and keep the terminal open for step 3. On macOS:

```sh
read -rs KEY && printf '%s' "$KEY" | shasum -a 256
```

On Linux, use `sha256sum` in place of `shasum -a 256`.

Send your administrator the 64-character hex string, and the name you want to
appear in the audit log. They add a line `sha256:<hash> <name>` to the
allowlist, which takes effect without a restart.

`printf '%s'` matters: `echo` adds a newline, which changes the hash. On a
machine with a Go toolchain, `go run ./cmd/cass-mcp -hash` from a checkout
reads the key on stdin and prints the finished line.

## 2. Save the certificate authority file

If your deployment's `cass-mcp` certificate is not signed by a CA your machine
already trusts, your administrator gives you the CA certificate, and its
SHA-256 fingerprint through a separate channel. It is a public certificate,
not a secret. Save it as `~/.config/cass/cass-mcp-ca.pem`, then check it:

```sh
mkdir -p ~/.config/cass
# save the file your administrator sent as ~/.config/cass/cass-mcp-ca.pem, then:
openssl x509 -in ~/.config/cass/cass-mcp-ca.pem -noout -fingerprint -sha256
```

The fingerprint must match the one your administrator gave you. If it
doesn't, stop. Never turn certificate verification off to get past this step.
If the certificate is publicly trusted, skip this step and the `ssl_verify`
line in step 4.

## 3. Put the key where Hermes can read it

Add a line to `~/.hermes/.env`, written as `KEY=value` with no `export`. In
the terminal from step 1, where `$KEY` is still set:

```sh
printf 'CASS_MCP_KEY=%s\n' "$KEY" >> ~/.hermes/.env && chmod 600 ~/.hermes/.env && unset KEY
```

## 4. Configure the server

Use the address your administrator gave you:

```sh
hermes config set mcp_servers.cassandra.url https://cassandra.example.edu:8443/mcp
hermes config set mcp_servers.cassandra.headers.Authorization 'Bearer ${CASS_MCP_KEY}'
hermes config set mcp_servers.cassandra.ssl_verify ~/.config/cass/cass-mcp-ca.pem
```

Keep the single quotes around `Bearer ${CASS_MCP_KEY}`. Hermes fills in the
variable from `.env` when it connects, so the key itself never goes into
`config.yaml`.

On the Cassandra host itself, the URL can be `https://localhost:8443/mcp`.

## 5. Test the connection

```sh
hermes mcp test cassandra
```

You should see:

```
✓ Connected
✓ Tools discovered: 1
    cass_ask   Ask Cassandra, ...
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
Cassandra ("cass") is our read-only infrastructure evidence service. For any question about RT tickets, Zabbix alerts, Wazuh agents, Pegasus jobs (PegasusDB) or host state, call the MCP tool mcp__cassandra__cass_ask with the user's whole question in plain English. "Ask cass" means call that tool. Report its numbers and ticket IDs exactly as given. Don't ask for RT credentials or endpoints; Cassandra holds them. There is no askcass command on this machine.
```

If `askcass` does work on this machine, as it does on the Cassandra host,
drop the last sentence.

**The two MCP skills.** These tell Hermes how to word questions for
Cassandra and how to report its answers. This downloads just the two skill
folders from `main` into Hermes's skills folder. The repository is public, so
no GitHub account or checkout is needed:

```sh
mkdir -p ~/.hermes/skills/infrastructure
curl -fsSL https://github.com/bindatype/cassandra/archive/refs/heads/main.tar.gz |
  tar -xz -C ~/.hermes/skills/infrastructure --strip-components=3 \
    cassandra-main/integrations/hermes-skill/cassandra-mcp \
    cassandra-main/integrations/hermes-skill/rt-ticket-analysis-mcp
ls ~/.hermes/skills/infrastructure
```

The last line should list `cassandra-mcp` and `rt-ticket-analysis-mcp`. Run
the command again to pick up an update; it overwrites both folders. Tested
with the `tar` that ships with macOS and with GNU tar on Linux.

Take only the `-mcp` skills. The repository's plain `cassandra` and
`rt-ticket-analysis` skills run the `askcass` command, which exists only on
the Cassandra host. If you do have a checkout, copy the folders rather than
symlinking them: Hermes warns about skills that resolve outside
`~/.hermes/skills`.

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

**Be on the right network before you start Hermes.** Hermes connects to MCP
servers once, when a session starts. A session started before the network or
VPN was ready stays without Cassandra until you start a new one.

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
| `Failed to connect to MCP server 'cassandra': CancelledError`, with no `HTTP Request` line before it | No reply from the Cassandra host: you are off the site network, or the VPN was still coming up | Connect, then start a new Hermes session |
| `401` | No key was sent, or MindRouter rejected it | Check the `CASS_MCP_KEY` line in `~/.hermes/.env` and the quoted `Bearer ${CASS_MCP_KEY}` header |
| `403` | The key is valid but not on Cassandra's allowlist | Step 1. A new MindRouter key needs a new hash |
| Certificate or SSL error | Hermes doesn't trust the `cass-mcp` certificate | Step 2, and check the `ssl_verify` path |
| Connected, but Hermes says it has no access to RT, or asks what "cass" is | The memory entry is missing | Step 6 |
| `tool_call` errors, or a truncated tool name like `mcp__cassandra__cass_...` | The model is struggling with the lookup step | Step 7 |
| "Cassandra is answering 4 questions already" or "you already have 2 questions running" | All question slots are in use, or you already have two questions running | Wait a minute and ask again; questions are refused rather than queued |
| A Wazuh answer says the API presented a certificate that is "not the pinned one" | The Wazuh manager's certificate changed; Cassandra refuses it rather than trusting it | Nothing to fix on your side: tell your administrator, who re-pins it (`CASS_WAZUH_CERT`) |

## What Cassandra will and won't tell you

- Read-only, and only what its sources hold. Ticket metadata, never ticket
  contents.
- RT answers cover the queues the deployment allows (`CASS_RT_QUEUES`). Name
  queues in the question to search only those. "Open" means status new, open
  or stalled; say "active" to get RT's `Status = '__Active__'`, which follows
  each queue's own lifecycle. Say which queues and which of the two you mean
  when comparing with a search in the RT web interface.
- Answers are internal data, subject to your organisation's data policy.
  Cassandra and its model are meant to run on your own infrastructure. If
  you connect an agent whose model runs in the cloud, the answers leave with
  it, and that is your responsibility.
