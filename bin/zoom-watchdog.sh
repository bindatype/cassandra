#!/bin/sh
# Notice when the morning digest has stopped posting.
#
#   . ~/.config/sroiaaa/env
#   sh bin/zoom-watchdog.sh          # silent if the digest is current
#   sh bin/zoom-watchdog.sh -v       # say what it found either way
#
# From cron, at least 2h15m after the digest -- see MAX_AGE_HOURS below, the
# gap is load-bearing and 06:30 is too early to catch a same-day failure:
#   0 8 * * * . $HOME/.config/sroiaaa/env && sh $HOME/dev/Cass/bin/zoom-watchdog.sh
#:usage-end
#
# WHY THIS EXISTS
#
# The digest ran at 04:45 from a cron line that began `cd $HOME/cass-src`.
# The repository moved. `cd` failed, `&&` swallowed the rest, and because the
# `>> log` redirect was attached to the command that never ran, the log was not
# even touched. It stopped for six days. Nobody noticed, and the last thing in
# the log was a hand-run dry run reading "(dry run, not posted)", which looks
# like it worked.
#
# A daily job whose only failure mode is silence needs something that treats
# silence as the alarm.
#
# WHAT IT DOES NOT SHARE WITH THE THING IT WATCHES
#
# A watchdog that fails the same way as its subject is decoration. This one:
#
#   - reads a receipt kept OUTSIDE the repository, so a moved or deleted
#     working tree does not take the evidence with it;
#   - needs no repository at all to DETECT the fault -- only to report it;
#   - reports twice, on two independent paths. It posts to the same Zoom
#     channel the digest uses, and it also writes to stderr and exits non-zero
#     so cron mails. If Zoom is the broken part, the mail still arrives; if
#     mail is unread, the channel still gets it.
#
# Read-only throughout. Nothing here modifies any system.
set -eu

VERBOSE=0
case ${1:-} in
-v | --verbose)
	VERBOSE=1
	;;
-h | --help)
	sed -n '2,/^#:usage-end$/{/^#:usage-end$/d;p;}' "$0" | sed 's/^# \{0,1\}//'
	exit 0
	;;
esac

# Resolved up front so an alarm can name the tree this script actually lives
# in. A hint that hardcodes a path is how the original cron line went stale.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

RECEIPT=${SROIAAA_DIGEST_RECEIPT:-"$HOME/.local/state/sroiaaa/zoom-digest.receipt"}

# 26 hours, not 24: a daily job must be allowed to be an hour late without
# crying wolf, and an alarm that fires on ordinary jitter gets muted, which
# leaves you worse off than no alarm.
#
# THIS NUMBER IS COUPLED TO WHEN THIS SCRIPT RUNS. The age measured is against
# the last GOOD receipt, not against this morning -- a digest that failed at
# 04:45 today leaves yesterday's 04:45 receipt standing, so the age at check
# time is (check time - 04:45) + 24h. To catch a failure the same day, that
# has to clear 26h, which means running no earlier than 06:45:
#
#   06:00 -> 25.25h   silent; the failure waits until tomorrow
#   06:45 -> 26.00h   a coin flip on integer rounding
#   08:00 -> 27.25h   alarms today, with margin      <-- the installed time
#
# So moving the cron entry earlier, or raising this threshold, silently costs a
# day of detection. Move them together or not at all.
MAX_AGE_HOURS=${SROIAAA_DIGEST_MAX_AGE_HOURS:-26}

now=$(date +%s)

# Read the receipt without sourcing it. It is a file this host writes, but
# `.`-ing a data file to parse it is a habit that turns any future write into
# code execution.
last_epoch=
posted=
if [ -r "$RECEIPT" ]; then
	last_epoch=$(sed -n 's/^last_run_epoch=\([0-9][0-9]*\)$/\1/p' "$RECEIPT" | tail -1)
	posted=$(sed -n 's/^posted=\([0-9][0-9]*\)$/\1/p' "$RECEIPT" | tail -1)
fi

alarm=
if [ ! -r "$RECEIPT" ]; then
	# Distinguish "never installed" from "stopped". Alarming identically for
	# both sends someone hunting a broken cron that was never created.
	alarm="The morning digest has no receipt at $RECEIPT.
Either it has never completed a real run on this host, or the receipt was
removed. Check:  crontab -l  and  sh $ROOT/bin/zoom-digest.sh -n"
elif [ -z "$last_epoch" ]; then
	alarm="The digest receipt at $RECEIPT has no readable last_run_epoch.
It may be truncated or from an older format. Contents:
$(cat "$RECEIPT")"
else
	age_hours=$(((now - last_epoch) / 3600))
	if [ "$age_hours" -ge "$MAX_AGE_HOURS" ]; then
		alarm="The morning digest has not posted for ${age_hours}h (limit ${MAX_AGE_HOURS}h).
Last real run: $(sed -n 's/^last_run=//p' "$RECEIPT" | tail -1)
Most likely the cron line points at a path that no longer exists -- that is
how it failed before, silently. Check:  crontab -l"
	elif [ "${posted:-0}" -eq 0 ]; then
		alarm="The digest ran ${age_hours}h ago but no section reached the channel.
The questions may be failing, or the Zoom credential may have expired.
Try:  cass-notify -probe"
	fi
fi

if [ -z "$alarm" ]; then
	[ "$VERBOSE" -eq 0 ] || echo "zoom-watchdog: digest is current (${age_hours}h ago, $posted section(s) posted)"
	exit 0
fi

# Say it on stderr first. This path needs nothing but the receipt, so it works
# even when the repository, the gateway, and Zoom are all unavailable.
echo "zoom-watchdog: $alarm" >&2

# Then try the channel. Best effort: a failure here is itself informative and
# must not mask the stderr report above, so it is not fatal.
BIN=${SROIAAA_BIN:-"$ROOT/runtime"}
if [ -n "${SROIAAA_ZOOM_WEBHOOK_URL:-}" ] &&
	[ -n "${SROIAAA_ZOOM_WEBHOOK_SECRET:-}${SROIAAA_ZOOM_WEBHOOK_TOKEN:-}" ]; then
	# cd into the module: go resolves go.mod from the working directory, not
	# from the package path. See the same subshell in bin/zoom-digest.sh.
	if mkdir -p "$BIN" 2>/dev/null && (cd "$ROOT" && go build -o "$BIN/cass-notify" ./cmd/cass-notify) 2>/dev/null; then
		printf '%s\n' "$alarm" | "$BIN/cass-notify" -title "Morning digest is not running" ||
			echo "zoom-watchdog: could not post the alarm to Zoom either" >&2
	else
		echo "zoom-watchdog: could not build cass-notify from $ROOT to post the alarm" >&2
	fi
else
	echo "zoom-watchdog: no Zoom credential in this environment; alarm not posted" >&2
fi

# Non-zero so cron mails, and so a human running it by hand sees a failure.
exit 1
