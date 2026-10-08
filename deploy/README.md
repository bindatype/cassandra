# Deploying cassd

`cassd` is the endpoint agent. It answers `live.evidence` for one host: list a
directory, stat a path, describe its own capabilities. It has no write path
outside its audit log, and the unit is written so the kernel enforces that
rather than the code promising it.

Until this runs somewhere, `live.evidence` is an intent the broker will route
and nothing will answer — the README has promised it since Phase One.

## What it can see, and why that is the point

The service runs as a `DynamicUser`: an identity that exists only while it
runs, owns nothing, and is in no group. So it reads exactly what is
world-readable.

On sgtstubby that means `/var/log` can be **listed and stat-ed** (the directory
is `0755`) while `/var/log/messages` and `/var/log/secure` **cannot be read**
(`0600 root:root`). That is the intended first posture, not a gap to close in
passing. Reading those is a deliberate privilege grant — a `SupplementaryGroups=`
line, or a permission change — and it should be argued for on its own rather
than arriving as a side effect of a deployment.

## Install

Two phases, because they run as different users. Build as yourself; install as
root.

Every path below is absolute, and deliberately so. The first version of this
runbook opened with `cd ~/dev/cassandra`, which is correct for the person who
has the checkout and wrong for root, whose `~` is `/root` -- pasted as one
block by a root shell it produced six consecutive "No such file or directory"
errors and installed nothing. A runbook that changes user halfway cannot use
`~` or relative paths anywhere.

```sh
# 1. Build, as the user who owns the checkout.
#    Building as root would leave root-owned files in dist/ and break the
#    owner's next make.
cd /home/glenamac/dev/cassandra && make build-linux-amd64
sha256sum dist/cassd-linux-amd64        # note this; check it after installing
```

```sh
# 2-5, as root. CASS is the checkout, not root's home.
CASS=/home/glenamac/dev/cassandra

install -o root -g root -m 0755 "$CASS/dist/cassd-linux-amd64" /usr/local/bin/cassd
mkdir -p /etc/cassd
install -o root -g root -m 0600 "$CASS/deploy/cassd.env.example" /etc/cassd/cassd.env
sed -i "s|^CASS_AUTH_TOKEN=.*|CASS_AUTH_TOKEN=$(openssl rand -hex 32)|" /etc/cassd/cassd.env
install -o root -g root -m 0644 "$CASS/deploy/cassd.service" /etc/systemd/system/cassd.service
systemctl daemon-reload
systemctl enable --now cassd
systemctl status cassd --no-pager
```

## Check it

```sh
systemd-analyze security cassd        # expect a low exposure score
systemctl show cassd -p MainPID       # running
ss -lntp | grep 8099                  # loopback only, never 0.0.0.0
```

The token never appears in the unit file. `systemctl cat` and
`systemd-analyze dump` print unit contents to any local user, so a credential
in `Environment=` is a credential published to everyone on the box. That shape
was recorded as a High finding against the sidecar in the August review; it is
why the token is in a `0600` file that only root can read.

## Point the broker at it

`cass-chat` reads a host map from `CASS_AGENT_CONFIG` — a JSON object of host
to endpoint and token. Each entry carries the one endpoint and bearer token
approved for that host; plans never carry either value.

```json
{"sgtstubby.arc.gwu.edu": {"endpoint": "http://127.0.0.1:8099", "token": "..."}}
```

Put it in `~/.config/cass/env` beside the other credentials, exported.

## Removing it

```sh
systemctl disable --now cassd
rm -f /etc/systemd/system/cassd.service /usr/local/bin/cassd
rm -rf /etc/cassd /var/lib/cassd
systemctl daemon-reload
```

## The tunnel to winston

`cassd` on a remote host binds its own loopback and is reached through an SSH
forward, so the connector still sees `http://127.0.0.1:<port>` and the
`https`-unless-loopback rule is satisfied by a transport SSH has already
encrypted and authenticated.

`deploy/cassd-tunnel-winston.user.service` is that forward. It is a **user**
unit, because a system unit cannot run it: SELinux denies `init_t` the right to
execute `ssh_exec_t`, and systemd reports that as `203/EXEC`, which reads as a
missing binary. The alternative was a policy module letting every unit on the
host exec ssh.

Install as the user who owns the key:

```sh
mkdir -p ~/.config/systemd/user
install -m 0644 ~/dev/cassandra/deploy/cassd-tunnel-winston.user.service \
  ~/.config/systemd/user/cassd-tunnel-winston.service
systemctl --user daemon-reload
systemctl --user enable --now cassd-tunnel-winston
```

Then once, as root, so the user manager survives logout and reboot:

```sh
loginctl enable-linger glenamac
```

Without lingering the forward dies when the last session ends, which is a
failure that looks like the network.

The key it uses must be restricted on the far host, in `~/.ssh/authorized_keys`:

```
restrict,port-forwarding,command="/bin/false",permitopen="127.0.0.1:8099" ssh-ed25519 AAAA...
```

All four options matter and one of them is easy to get wrong. `restrict` turns
everything off. **`permitopen` narrows forwarding; it does not enable it** — so
`restrict,permitopen=...` forwards nothing at all, and `port-forwarding` is
what restores the capability that `permitopen` then constrains.
`command="/bin/false"` closes the remaining gap, because `restrict` blocks PTY
allocation but not command execution; `ssh -N` requests no session, so the
forced command never runs and the forward is unaffected.

### One port map, kept in two places

The local port appears in this unit and again in `CASS_AGENT_CONFIG`. They can
drift, and a transposed port means one host's filesystem returned under another
host's name — an answer that parses, reads sensibly, and is false throughout.

That is survivable only because the agent reports its own hostname on every
response and the connector refuses a reply from anywhere but the host the plan
named. Verified deliberately: pointing sgtstubby's entry at winston's forward
produces a refusal naming both hosts, not an answer.

At a third host, replace this unit with a template plus a per-host environment
file rather than copying it again.

## The MCP service (cass-mcp)

`cass-mcp` serves Cassandra to MCP clients (Hermes, Claude Code) on `:8443`;
[docs/connecting-hermes-to-cassandra.md](../docs/connecting-hermes-to-cassandra.md)
is the client side. It runs on sgtstubby as a user unit, from its own copy of
the binaries, so an `askcass` rebuild never swaps `cass-chat` mid-question.

Deploy from the checkout on that host, as the user who owns the service:

```sh
cd ~/dev/cassandra && git pull
make install-cass-mcp      # test, build, swap in, restart, check
make rollback-cass-mcp     # put the previous build back; run again to undo
```

The install stops before changing anything if a test or the build fails.
After the restart it checks that an unauthenticated request gets `401`, which
proves TLS is served and the key gate is shut; if not, it puts the previous
build back and exits non-zero. It does not ask a question, so ask one after a
deploy that changed how questions are answered.

| What | Where | Managed by the install |
| --- | --- | --- |
| Binaries, policy snapshot, `BUILD` | `~/.local/share/cass-mcp/bin/`, each with a `.prev` | Yes |
| Unit | `~/.config/systemd/user/cass-mcp.service`, from `deploy/cass-mcp.user.service` | Yes; edit the repo copy |
| Host flags (`CASS_MCP_EXTRA_FLAGS`, e.g. `-wazuh-insecure`) | `~/.config/cass/cass-mcp.flags` | No |
| TLS | `~/.local/share/cass-mcp/tls/` (`ca.pem`, `cert.pem`, `key.pem`) | No; it warns 30 days before `cert.pem` expires |
| Source credentials | `~/.config/cass/env` | No |
| Allowlist | `~/.config/cass/mcp-allowlist` | No |

`cat ~/.local/share/cass-mcp/bin/BUILD` says which commit is running, and
whether the checkout had uncommitted changes when it was built.

**The policy is a snapshot.** `cass-chat` reads its policy on every question,
and the unit used to point into the checkout, so every `git pull` changed the
live policy with no deploy and no record. The install copies
`configs/broker-policy.example.json` (or `CASS_MCP_POLICY`) beside the
binaries, so a policy change goes live only through an install, and a rollback
takes it back too.

**Switching an intent off** is a policy change: add it to `disabled_intents`
in `configs/broker-policy.example.json`, commit, pull here, and
`make install-cass-mcp`. The model stops being offered it and the broker
refuses it. Removing it from the list and installing again turns it back on.

### Exports (`cass_export`)

`cass-mcp` also serves `cass_export` and `cass_export_status`: deterministic
exports of Pegasus job requests, for studies that need rows rather than an
answer. No model writes SQL or reads a column; `internal/export` does the
work, `cass-export` runs the same code from a shell, and every export ships
`verify_export.py` and `VERIFIER.md`, which says exactly what it checks.

Exports are **off** unless all of these exist; the service log says which is
missing, and questions are unaffected either way:

| What | Where | Notes |
| --- | --- | --- |
| Permissions | `~/.config/cass/export-allowlist` | `person export` or `person export,identify`, using the names in `mcp-allowlist`. Being able to ask questions is not permission to export. `identify` allows raw netids; without it identities are pseudonymous. Removing the file revokes everyone. |
| Salt | `~/.config/cass/export-salt` | At least 16 bytes, mode 0600. Pseudonymous keys are stable while it is unchanged; replacing it breaks comparison with earlier exports. Create once: `head -c 32 /dev/urandom > ~/.config/cass/export-salt && chmod 600 ~/.config/cass/export-salt` |
| The view | `runTBL2_jobs` on lucee | From `configs/pegasusdb/runTBL2_jobs.sql`. |
| Database login | `CASS_PEGASUS_DSN` in `~/.config/cass/env` | The same read-only login as questions. |

Exports are written under `~/.local/share/cass-mcp/exports/<id>/` (0700,
files 0600), kept 14 days (`-export-retention`), downloaded by their owner
only at `https://<host>:8443/exports/<id>/<file>` with the same key, and
audited to `~/.local/share/cass/export-audit.jsonl`. One export runs at a time
across everyone (`-export-max-running`), because a long window is a full pass
over `runTBL2` on lucee: for June-September 2026 the optimizer chose a scan
over the `SubmitTime` index (EXPLAIN, 2026-10-07; the table statistics look
stale), about 20 s. At most 2,000,000 rows (`-export-max-rows`) and 30 minutes
(`-export-timeout`).

Before turning exports on, run the live checks against the view:

```sh
set -a; . ~/.config/cass/env; set +a
make test-export-live
```

## vLLM (gemma4) service

`gemma4-31b-vllm`, the model Cassandra and the Xenolith testers use through
MindRouter (backend `ollama-sgtstubby`, `http://127.0.0.1:18080`), is served
by vLLM on sgtstubby's four RTX 6000 Ada GPUs. It is not part of Cassandra,
but Cassandra depends on it, so its service and recipe live here, in
`deploy/vllm/`. Chosen 2026-10-08: stability on this host first, portability
by recipe; containers when a second host needs the same serving stack.

| File | Installed as | What it is |
| --- | --- | --- |
| `vllm-gemma4.user.service` | `~/.config/systemd/user/vllm-gemma4.service` | glenamac user unit (linger is on, so it starts at boot); restarts on failure after 30 s, gives up after 3 failures in an hour; 90 s for the GPU workers to stop |
| `start-gemma4.sh` | `~/vllm/start-gemma4.sh` | Builds the `vllm serve` command from the settings; refuses to start if the chat template's sha256 or the pinned model revision does not match; `VLLM_DRY_RUN=1` prints the command instead |
| `gemma4.env.example` | `~/.config/vllm/gemma4.env` | Every setting: model, pinned revision, slots (`VLLM_MAX_NUM_SEQS`), context length, GPUs, `HF_HUB_OFFLINE=1` |
| `tool_chat_template_gemma4.jinja` | `~/vllm/tool_chat_template_gemma4.jinja` | sha256 `84af2a627a6e7489a9afe89e95dc6068d545999dd19fce89f34e9cedade71a35` |
| `requirements-vllm-cu128.lock` | — | `pip freeze` of `~/venvs/vllm-cu128` (vllm 0.21.0, torch 2.11.0+cu128, Python 3.11.13; driver 595.71.05) |

Log: `~/logs/vllm-gemma4.log`, the previous run's kept as `.1`.

**Changing a setting** (for example the slot count): edit
`~/.config/vllm/gemma4.env`, then `systemctl --user restart vllm-gemma4`. A
restart is a 2-4 minute outage of the model (a changed slot count also
recompiles, about 3 minutes more). Keep MindRouter's **Max Concurrent** for
`ollama-sgtstubby` equal to `VLLM_MAX_NUM_SEQS`.

**Install** (copies files; starts nothing):

```sh
cd /home/glenamac/dev/cassandra
mkdir -p ~/vllm ~/.config/vllm ~/logs
install -m 755 deploy/vllm/start-gemma4.sh ~/vllm/start-gemma4.sh
cmp deploy/vllm/tool_chat_template_gemma4.jinja ~/vllm/tool_chat_template_gemma4.jinja
[ -e ~/.config/vllm/gemma4.env ] || install -m 600 deploy/vllm/gemma4.env.example ~/.config/vllm/gemma4.env
install -m 644 deploy/vllm/vllm-gemma4.user.service ~/.config/systemd/user/vllm-gemma4.service
systemctl --user daemon-reload
VLLM_DRY_RUN=1 ~/vllm/start-gemma4.sh
```

**Switching over** from a hand-started vLLM (an outage of a few minutes):
stop the hand-started one (Ctrl-C in its tmux window, and wait until
`nvidia-smi` shows the GPUs empty), then

```sh
systemctl --user enable --now vllm-gemma4
until curl -sf -o /dev/null http://127.0.0.1:18080/health; do sleep 10; done; echo ready
```

Two vLLMs cannot share these GPUs: a second one fails at startup with "Free
memory on device ... is less than desired GPU memory utilization" and leaves
the first untouched (seen 2026-10-08, when a dry run was started without
`VLLM_DRY_RUN=1`).

**Rebuilding on another host:** a driver supporting CUDA 12.8, Python 3.11, then

```sh
python3.11 -m venv ~/venvs/vllm-cu128
~/venvs/vllm-cu128/bin/pip install -r deploy/vllm/requirements-vllm-cu128.lock --extra-index-url https://download.pytorch.org/whl/cu128
HF_HOME=<cache> ~/venvs/vllm-cu128/bin/hf download google/gemma-4-31B-it --revision 842da3794eaa0b77d5f08bae87a17459d91ff475
```

(Gemma needs a Hugging Face account that has accepted its licence), then
install as above with `HF_HOME`, `CUDA_VISIBLE_DEVICES` and `VLLM_TP` set for
that host.
