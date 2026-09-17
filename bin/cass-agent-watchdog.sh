#!/bin/sh
# Notice when an endpoint agent, or the forward reaching it, stops working.
#
#   . ~/.config/cass/env
#   sh bin/cass-agent-watchdog.sh        # silent while every agent answers
#   sh bin/cass-agent-watchdog.sh -v     # say what it found either way
#
# From a systemd user timer every five minutes; see
# deploy/cass-agent-watchdog.user.{service,timer}.
#:usage-end
#
# WHY THIS EXISTS
#
# cassd restarts on failure and the tunnel restarts always, so both recover
# from most things on their own. What neither does is say when it has stopped
# recovering. The failure that follows is quiet: live.evidence keeps being
# offered to the model, because intents are derived from configured connectors
# rather than healthy ones, so every question routed to a dead agent spends a
# turn and returns an error. The first sign is somebody asking why answers got
# worse.
#
# WHAT IT CHECKS, AND WHY THAT PARTICULAR REQUEST
#
# One POST of capabilities.describe per configured agent proves three things at
# once, which is why it is preferred to a port check or a GET:
#
#   reachable      the forward is up and carrying traffic, not merely bound --
#                  a local listener exists whether or not the channel opens
#   authenticated  the agent accepted this host's own token
#   correct host   the reply reports the host the configuration expected
#
# The third is the one no other monitor would do. The port map lives in the
# tunnel unit and again in CASS_AGENT_CONFIG; if they drift, one host answers
# under another host's name. The connector refuses that mismatch when a
# question happens to be asked -- this notices it every five minutes whether
# anyone asks or not.
set -eu

VERBOSE=0
case ${1:-} in
-v | --verbose) VERBOSE=1 ;;
-h | --help)
	sed -n '2,/^#:usage-end$/{/^#:usage-end$/d;p;}' "$0" | sed 's/^# \{0,1\}//'
	exit 0
	;;
esac

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=bin/lib/config.sh
. "$ROOT/bin/lib/config.sh"

# Source the environment rather than expecting a caller to have done it.
#
# bin/lib/config.sh reads the environment; it does not populate it. A systemd
# timer starts with almost none, so the first run under one exited 2 with
# "CASS_AGENT_CONFIG is not set" against a host where it was perfectly well
# set -- in a file nobody had read. askcass sources its own environment for the
# same reason, and a monitor that only works when invoked by hand is not a
# monitor.
ENV_FILE=$(cass_config_path env CASS_ENV)
if [ -r "$ENV_FILE" ]; then
	set -a
	# shellcheck disable=SC1090
	. "$ENV_FILE"
	set +a
fi

STATE=${CASS_AGENT_WATCHDOG_STATE:-$(cass_state_path agent-watchdog.state)}

# Three consecutive failures, not one. cassd restarts in five seconds and the
# forward in ten, so a single failed probe usually means a restart was in
# flight. Alarming on that trains people to ignore the alarm, which costs more
# than the fifteen minutes of delay this buys.
THRESHOLD=${CASS_AGENT_WATCHDOG_THRESHOLD:-3}

CONFIG=$(cass_value CASS_AGENT_CONFIG)
if [ -z "$CONFIG" ]; then
	echo "cass-agent-watchdog: CASS_AGENT_CONFIG is not set; no agents to watch" >&2
	exit 2
fi

mkdir -p "$(dirname -- "$STATE")"
[ -f "$STATE" ] || : >"$STATE"

# The probe and the comparison live in python because the configuration is
# JSON and the reply is JSON. Parsing either with sed is how a monitor comes to
# report something other than what the service said.
REPORT=$(CASS_WATCHDOG_STATE="$STATE" CASS_WATCHDOG_THRESHOLD="$THRESHOLD" \
	CASS_WATCHDOG_CONFIG="$CONFIG" python3 - <<'PY'
import json, os, sys, urllib.error, urllib.request

agents = json.loads(os.environ["CASS_WATCHDOG_CONFIG"])
state_path = os.environ["CASS_WATCHDOG_STATE"]
threshold = int(os.environ["CASS_WATCHDOG_THRESHOLD"])

# host -> consecutive failures, carried between runs so a blip and a sustained
# outage are distinguishable.
streak = {}
try:
    with open(state_path) as handle:
        for line in handle:
            name, _, count = line.strip().partition("=")
            if name:
                streak[name] = int(count or 0)
except FileNotFoundError:
    pass


def probe(endpoint, token):
    """Return None when healthy, else why not."""
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/v1/operations",
        data=json.dumps({"operation": "capabilities.describe"}).encode(),
        method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + token},
    )
    try:
        payload = json.load(urllib.request.urlopen(request, timeout=10))
    except urllib.error.HTTPError as err:
        if err.code == 401:
            return "rejected this host's token (401); the agent's token was rotated or the config is stale"
        return f"HTTP {err.code}"
    except Exception as err:                       # noqa: BLE001 - report, don't raise
        return f"unreachable: {str(err)[:90]}"
    if payload.get("status") != "ok":
        return f"answered with status {payload.get('status')!r}"
    return payload.get("metadata", {}).get("host") or ""


def same_host(planned, reported):
    # First label, lowercased -- the rule the connector applies, kept identical
    # on purpose. A monitor stricter than the thing it monitors reports faults
    # that are not faults; one that is looser misses the faults that matter.
    return planned.strip().lower().split(".")[0] == reported.strip().lower().split(".")[0]


alarms, healthy = [], []
for host in sorted(agents):
    endpoint = agents[host].get("endpoint", "")
    result = probe(endpoint, agents[host].get("token", ""))

    if result and not result.startswith(("HTTP", "unreachable", "rejected", "answered")):
        if same_host(host, result):
            problem = None
        else:
            problem = (f"answered by {result!r}, not {host}. The endpoint {endpoint} "
                       f"points at the wrong host -- check the tunnel's local port "
                       f"against CASS_AGENT_CONFIG")
    elif result == "":
        problem = "did not report a hostname, so its answers cannot be attributed"
    else:
        problem = result

    if problem is None:
        streak[host] = 0
        healthy.append(f"{host} via {endpoint}")
        continue

    streak[host] = streak.get(host, 0) + 1
    if streak[host] >= threshold:
        alarms.append(f"{host}: {problem} ({streak[host]} consecutive checks)")

with open(state_path, "w") as handle:
    for host in sorted(streak):
        handle.write(f"{host}={streak[host]}\n")

print(json.dumps({"alarms": alarms, "healthy": healthy,
                  "pending": {h: c for h, c in streak.items() if 0 < c < threshold}}))
PY
)

ALARMS=$(printf '%s' "$REPORT" | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin)["alarms"]))')

if [ -z "$ALARMS" ]; then
	if [ "$VERBOSE" -eq 1 ]; then
		printf '%s' "$REPORT" | python3 -c 'import json,sys
d = json.load(sys.stdin)
print("cass-agent-watchdog: %d agent(s) healthy" % len(d["healthy"]))
for entry in d["healthy"]:
	print("  ok      " + entry)
for host, count in sorted(d["pending"].items()):
	print("  failing %s (%d check(s), alarms at threshold)" % (host, count))'
	fi
	exit 0
fi

# stderr first: this path needs nothing but the probe result, so it works when
# the gateway, Zoom and everything else are also unavailable.
echo "cass-agent-watchdog: endpoint agents are not answering:" >&2
printf '  %s\n' "$ALARMS" >&2

BIN=${CASS_BIN:-"$ROOT/runtime"}
if [ -n "$(cass_value CASS_ZOOM_WEBHOOK_URL)" ] &&
	[ -n "$(cass_value CASS_ZOOM_WEBHOOK_SECRET)$(cass_value CASS_ZOOM_WEBHOOK_TOKEN)" ]; then
	# cd into the module: go resolves go.mod from the working directory.
	if mkdir -p "$BIN" 2>/dev/null && (cd "$ROOT" && go build -o "$BIN/cass-notify" ./cmd/cass-notify) 2>/dev/null; then
		printf 'live.evidence is degraded:\n%s\n' "$ALARMS" |
			"$BIN/cass-notify" -title "Endpoint agent not answering" ||
			echo "cass-agent-watchdog: could not post the alarm to Zoom either" >&2
	else
		echo "cass-agent-watchdog: could not build cass-notify to post the alarm" >&2
	fi
else
	echo "cass-agent-watchdog: no Zoom credential in this environment; alarm not posted" >&2
fi

exit 1
