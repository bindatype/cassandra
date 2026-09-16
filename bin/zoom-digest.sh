#!/bin/sh
# Post a morning digest into a Zoom Team Chat channel.
#
#   . ~/.config/sroiaaa/env
#   sh bin/zoom-digest.sh            # ask, and post to Zoom
#   sh bin/zoom-digest.sh -n         # ask, print here, post nothing
#   sh bin/zoom-digest.sh -n Wazuh   # just that one section
#
# From cron, source the environment first; cron gets almost none of it:
#   45 4 * * * . $HOME/.config/sroiaaa/env && sh $HOME/dev/Cass/bin/zoom-digest.sh
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
# the built-in default, so SROIAAA_ZOOM_SIGNATURE_VARIANT need not be set. If
# posting starts returning 401, run  cass-notify -probe  before assuming
# the secret is wrong.
#
# Read-only throughout. Nothing here modifies any system.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

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
# ~/.config/sroiaaa/env is sourced explicitly and not from ~/.bashrc, so a
# fresh shell has none of these. That is the usual cause.
#
# It matters most under cron, which sources neither. A credential whose value
# lives in ~/.bashrc is simply absent at 04:45, and a question answered without
# one fails in a way that reads like a broken source rather than a missing
# secret. Every variable the digest needs is listed here so that failure is
# loud and names itself.
required="SROIAAA_MINDROUTER_ENDPOINT MINDROUTER_API_KEY SROIAAA_WAZUH_CRITICAL_GROUPS
	ZABBIX_RO_TOKEN SROIAAA_ZABBIX_ENDPOINT
	WAZUH_API_USERNAME WAZUH_API_PASSWORD SROIAAA_WAZUH_ENDPOINT
	SROIAAA_PEGASUS_DSN"
[ "$DRY" -eq 1 ] || required="$required SROIAAA_ZOOM_WEBHOOK_URL"
missing=
for var in $required; do
	eval "value=\${$var:-}"
	[ -n "$value" ] || missing="$missing $var"
done
if [ "$DRY" -eq 0 ] && [ -z "${SROIAAA_ZOOM_WEBHOOK_SECRET:-}${SROIAAA_ZOOM_WEBHOOK_TOKEN:-}" ]; then
	missing="$missing SROIAAA_ZOOM_WEBHOOK_SECRET"
fi
if [ -n "$missing" ]; then
	echo "zoom-digest: not set in this environment:$missing" >&2
	echo "zoom-digest: run  . ~/.config/sroiaaa/env  first" >&2
	echo "zoom-digest: (a variable set in ~/.bashrc without export is invisible here)" >&2
	exit 2
fi

POLICY=${SROIAAA_POLICY:-"$ROOT/configs/broker-policy.example.json"}
BIN=${SROIAAA_BIN:-"$ROOT/runtime"}

# The receipt records that a real post happened, and is what bin/zoom-watchdog.sh
# reads to decide the digest has gone quiet.
#
# It lives outside the repository on purpose. Putting it in runtime/ would tie
# the evidence-that-it-ran to the very directory whose disappearance is the
# thing most likely to stop it running -- the receipt would vanish along with
# the digest, and a watchdog cannot tell "never ran" from "never installed".
RECEIPT=${SROIAAA_DIGEST_RECEIPT:-"$HOME/.local/state/sroiaaa/zoom-digest.receipt"}

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

# The overnight ticket window, computed here rather than asked of the model.
#
# ParseSince accepts RFC 3339, a plain date, "24h"/"7d", and the words today
# and yesterday -- there is no form that says "5pm yesterday". The alternatives
# were to make the model author a timestamp, or to approximate with "12h".
# Neither is right: a relative window drifts with the run time (12h from a
# 04:45 start is 16:45, and a late or slow run moves it further), and asking a
# model to work out yesterday-17:00-in-Eastern-across-a-DST-boundary is asking
# it to do arithmetic the host can do exactly. If code can determine it, code
# must.
#
# The offset form, not -u. `date -u -d "yesterday 17:00"` parses the INPUT as
# UTC as well, yielding 17:00Z rather than 21:00Z, and would silently shift
# this window by four hours in EDT.
if since_5pm=$(date -d "yesterday 17:00" +%Y-%m-%dT%H:%M:%S%:z 2>/dev/null); then
	: # GNU date
elif since_5pm=$(date -v-1d -v17H -v0M -v0S +%Y-%m-%dT%H:%M:%S%z 2>/dev/null); then
	# BSD date, for a developer running this on a Mac. Its %z has no colon,
	# which RFC 3339 requires: -0400 becomes -04:00.
	since_5pm=$(printf '%s' "$since_5pm" | sed 's/\(..\)$/:\1/')
else
	echo "zoom-digest: could not compute the overnight ticket window" >&2
	exit 1
fi

digest "Zabbix overnight" "what problems started since yesterday, and how many are there by severity?"
# Critical groups are set by SROIAAA_WAZUH_CRITICAL_GROUPS and marked in the
# evidence before the model sees it, so this asks for a report rather than a
# calculation.
digest "Wazuh agents" "how many agents are disconnected right now, and are any of them in a critical group? Name the critical ones."
# Not "the last 24 hours": runTBL2 lags ingestion by about a day, so that
# window holds only the leading edge and reads as an idle cluster every
# morning. A complete past day is the honest question.
digest "Scheduler" "for the most recent complete day in runTBL2: how many jobs completed and how many failed, and what was the median wait time for the cpu partition and for the gpu partition? Say which day, and give wait times in seconds and minutes."

# Overnight tickets. "Still open" is not hedging: tickets.open selects
# Status in (new, open, stalled), so a ticket raised at 22:00 and resolved
# before this runs does not appear. Saying "new tickets" would overstate what
# the intent can see.
#
# The timestamp is interpolated rather than described, so the model transcribes
# a bound instead of deriving one.
digest "New tickets overnight" "which tickets were created since $since_5pm and are still open? Group them by owner and give the total. If there are none, say so plainly."


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
