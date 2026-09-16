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
