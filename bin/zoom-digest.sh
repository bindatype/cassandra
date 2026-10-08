#!/bin/sh
# Post a morning digest into a Zoom Team Chat channel.
#
#   . ~/.config/cass/env
#   sh bin/zoom-digest.sh            # ask, and post to Zoom
#   sh bin/zoom-digest.sh -n         # ask, print here, post nothing
#   sh bin/zoom-digest.sh -n Wazuh   # just that one section
#
# From cron, source the environment first; cron gets almost none of it:
#   45 4 * * * . $HOME/.config/cass/env && sh $HOME/dev/cassandra/bin/zoom-digest.sh
#:usage-end
#
# Give cron the FULL path to this script rather than `cd`-ing to the repo and
# using a relative one. That line used to read `cd $HOME/cass-src && sh
# bin/zoom-digest.sh`; the repository moved, the `cd` failed, `&&` swallowed
# the rest, and the digest stopped for six days without one word in the log --
# because the redirect that would have caught the error was attached to the
# command that never ran. Pair it with bin/zoom-watchdog.sh, which notices.
#
# The signature construction Zoom accepts was confirmed on 2026-08-30 and is
# the built-in default, so CASS_ZOOM_SIGNATURE_VARIANT need not be set. If
# posting starts returning 401, run  cass-notify -probe  before assuming
# the secret is wrong.
#
# Read-only throughout. Nothing here modifies any system.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# shellcheck source=bin/lib/config.sh
. "$ROOT/bin/lib/config.sh"

DRY=0
case ${1:-} in
-n | --dry-run)
	DRY=1
	shift
	;;
-h | --help)
	sed -n '2,/^#:usage-end$/{/^#:usage-end$/d;p;}' "$0" | sed 's/^# \{0,1\}//'
	exit 0
	;;
esac
# An optional substring selects one section, so testing a single question does
# not mean running all three.
ONLY=${1:-}

# Fail before asking anything. Without this the first missing variable surfaces
# from cass-notify at the end of a pipeline, after a question has already
# been answered, and reads as a Zoom problem rather than a missing source.
#
# ~/.config/cass/env is sourced explicitly and not from ~/.bashrc, so a
# fresh shell has none of these. That is the usual cause.
#
# It matters most under cron, which sources neither. A credential whose value
# lives in ~/.bashrc is simply absent at 04:45, and a question answered without
# one fails in a way that reads like a broken source rather than a missing
# secret. Every variable the digest needs is listed here so that failure is
# loud and names itself.
required="CASS_MINDROUTER_ENDPOINT MINDROUTER_API_KEY CASS_WAZUH_CRITICAL_GROUPS
	ZABBIX_RO_TOKEN CASS_ZABBIX_ENDPOINT
	WAZUH_API_USERNAME WAZUH_API_PASSWORD CASS_WAZUH_ENDPOINT
	CASS_PEGASUS_DSN"
[ "$DRY" -eq 1 ] || required="$required CASS_ZOOM_WEBHOOK_URL"
missing=
for var in $required; do
	value=$(cass_value "$var")
	[ -n "$value" ] || missing="$missing $var"
done
if [ "$DRY" -eq 0 ] && [ -z "$(cass_value CASS_ZOOM_WEBHOOK_SECRET)$(cass_value CASS_ZOOM_WEBHOOK_TOKEN)" ]; then
	missing="$missing CASS_ZOOM_WEBHOOK_SECRET"
fi
if [ -n "$missing" ]; then
	echo "zoom-digest: not set in this environment:$missing" >&2
	echo "zoom-digest: run  . ~/.config/cass/env  first" >&2
	echo "zoom-digest: (a variable set in ~/.bashrc without export is invisible here)" >&2
	exit 2
fi

POLICY=${CASS_POLICY:-"$ROOT/configs/broker-policy.example.json"}
BIN=${CASS_BIN:-"$ROOT/runtime"}

# The receipt records that a real post happened, and is what bin/zoom-watchdog.sh
# reads to decide the digest has gone quiet.
#
# It lives outside the repository on purpose. Putting it in runtime/ would tie
# the evidence-that-it-ran to the very directory whose disappearance is the
# thing most likely to stop it running -- the receipt would vanish along with
# the digest, and a watchdog cannot tell "never ran" from "never installed".
RECEIPT=${CASS_DIGEST_RECEIPT:-${CASS_DIGEST_RECEIPT:-$(cass_state_path zoom-digest.receipt)}}

mkdir -p "$BIN"
# The build must run INSIDE the module. Naming the package by absolute path is
# not enough: go resolves go.mod from the working directory. This script got
# away with it for as long as its cron line began `cd $HOME/cass-src`, which
# was doing the build's job by accident; the first run after that cd was
# removed failed with "go.mod file not found in current directory". bin/ask
# already carries this same subshell for the same reason.
(cd "$ROOT" && go build -o "$BIN/cass-chat" ./cmd/cass-chat)
[ "$DRY" -eq 1 ] || (cd "$ROOT" && go build -o "$BIN/cass-notify" ./cmd/cass-notify)

# A failed question must not post a cheerful empty message, and must not stop
# the questions after it. Each one stands or falls alone.
digest() {
	title=$1
	question=$2
	case $title in
	*"$ONLY"*) ;;
	*) return 0 ;;
	esac

	if answer=$("$BIN/cass-chat" -policy "$POLICY" -wazuh-insecure "$question" 2>&1); then
		body=$answer
	else
		title="$title (failed)"
		body=$(printf 'Could not answer "%s":\n%s' "$question" "$answer")
	fi

	if [ "$DRY" -eq 1 ]; then
		# Same text the channel would receive, marked so a dry run is never
		# mistaken for a real one in a scrollback.
		printf '\n--- %s --- (dry run, not posted)\n%s\n' "$title" "$body"
		return 0
	fi

	# A section that could not be answered still posts, saying so; what is
	# counted here is whether the message reached the channel, which is the
	# only thing the watchdog can act on.
	if printf '%s\n' "$body" | "$BIN/cass-notify" -title "$title"; then
		POSTED=$((POSTED + 1))
	else
		UNSENT=$((UNSENT + 1))
		echo "zoom-digest: could not post section: $title" >&2
	fi
}

POSTED=0
UNSENT=0

digest "Zabbix overnight" "what problems started since yesterday, and how many are there by severity? Give the severity breakdown as a short bulleted list."
# Critical groups are set by CASS_WAZUH_CRITICAL_GROUPS and marked in the
# evidence before the model sees it, so this asks for a report rather than a
# calculation.
digest "Wazuh agents" "how many agents are disconnected right now, and are any of them in a critical group? Name the critical ones as a short bulleted list."
# Not "the last 24 hours": runTBL2 lags ingestion by about a day, so that
# window holds only the leading edge and reads as an idle cluster every
# morning. A complete past day is the honest question.
#
# P95 alongside P50: this is the same PARTITION BY-per-partition shape that
# used to come back with P50 == P95 (GROUP BY collapsing each partition to
# one row before the window ran, fixed 2026-09-25). Asking for tail latency
# here is what that fix was for -- median alone hides a queue that is fine on
# average and terrible in the tail.
#
# Counts by workload class, wait times by partition (Glen, 2026-10-08). A GPU
# job is one that requested a GPU, on any partition (runTBL2_workload), which
# is not the same as a job on the partition named gpu; the labels say which is
# which so the two kinds of figure cannot be read as the same thing.
digest "Scheduler" "for the most recent complete day in runTBL2: how many jobs completed and how many failed, in total and broken out by the workload column of the runTBL2_workload view (gpu, cpu and excluded, naming any unclassified); and for the cpu partition and the gpu partition, what was the median (P50) and 95th percentile (P95) wait time? Say which day. List completed and failed as short bulleted lists, total first, then 'GPU jobs (requested a GPU, any partition)', 'CPU jobs' and 'Excluded (nano and staff partitions)'. Give wait times in seconds and minutes, listing each partition's P50 and P95 as a short bulleted list headed 'cpu partition' and 'gpu partition'."

# Longest-open tickets, not new ones: anyone can see what's new by logging
# into RT itself, so that told the channel nothing it couldn't already see.
# The oldest still-open tickets are the useful, non-obvious signal.
#
# "Which tickets have been open longest" with no age bound leaves both since
# and until empty, and tickets.open then defaults to newest-first (see
# ticketOrder in internal/connector/rt.go) -- combined with the page
# truncating at 100 of several hundred, that made the true oldest
# unreachable. Confirmed live: asked that way, the model correctly refused
# to guess rather than answer from the wrong page.
#
# Setting until with since empty is what flips the sort to oldest-first, per
# the same convention documented in prompt.md for "tickets older than N
# days". The 30-day floor barely matters -- ascending order surfaces the true
# oldest first regardless of where it sits -- it mainly gives the disclosed
# total a meaning: "N tickets older than a month" is its own backlog signal.
#
# RT still returns up to 100 rows (ticketSearchLimit in router.go, fixed
# rather than caller-tunable) and the model narrows to five in its own
# prose; asking RT itself for a page of five was considered and deliberately
# skipped -- see the discussion this replaced.
#
# "Active", not "open": the word sets status: active, which searches RT's own
# __Active__ statuses. "Open" searches new, open and stalled, which misses
# active tickets in queues whose lifecycle uses other statuses.
digest "Longest-open tickets" "which tickets are still active and were created more than 30 days ago? State the total number matching, then list only the 5 oldest, each as a bulleted line with its subject, owner, and how many days it has been open."


# A dry run deliberately writes no receipt. If it did, testing by hand would
# reset the watchdog's clock and hide a cron that has not fired in a week --
# which is exactly the state this whole mechanism exists to surface, and
# exactly what the log looked like when it was in it: the last thing written
# was a hand-run dry run, reading like a success.
if [ "$DRY" -eq 0 ]; then
	mkdir -p "$(dirname -- "$RECEIPT")"
	# Written whole and moved into place, so the watchdog never reads a
	# half-written receipt and alarms about a digest that is running fine.
	tmp=$(mktemp "$RECEIPT.XXXXXX")
	{
		echo "last_run=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "last_run_epoch=$(date +%s)"
		echo "posted=$POSTED"
		echo "unsent=$UNSENT"
		echo "root=$ROOT"
	} >"$tmp"
	mv -- "$tmp" "$RECEIPT"
fi

# Non-zero if nothing reached the channel, so cron mails on a total failure
# even before the watchdog next runs.
#
# Not on a dry run: it posts nothing by design, so counting zero posts as a
# failure would make the one command you use to test the digest by hand always
# report that the digest is broken.
if [ "$DRY" -eq 0 ] && [ "$POSTED" -eq 0 ]; then
	echo "zoom-digest: no section reached the channel" >&2
	exit 1
fi
