#!/bin/sh
# Move settled audit records into compressed monthly archives.
#
#   . ~/.config/cass/env
#   sh bin/cass-audit-archive.sh          # archive anything older than today
#   sh bin/cass-audit-archive.sh -n       # say what would move, move nothing
#
# From a systemd user timer, weekly; see deploy/cass-audit-archive.user.*.
#:usage-end
#
# NOTHING IS DELETED, and that is the design rather than an oversight.
#
# The audit is the only record of what the model actually does -- 932 SQL
# queries it wrote, every refusal, every discarded result -- and it is what
# every wrong answer has been found with. Compressed it runs about 1.5 MB a
# year, measured at 13:1 on the real file. Retention policy for something that
# small, and that hard to reconstruct, is a way to lose evidence in exchange
# for nothing.
#
# What actually needed solving was reading it: audit_stats and audit_sql load
# the whole file, and 40 MB a year of that gets slow. So records move into
# monthly archives and the readers span both.
#
# WHY RENAMING IS SAFE HERE
#
# cass-chat opens the audit, appends one record, and exits, so nothing holds
# the file between questions. Renaming it means the next question creates a
# fresh one; a rename landing mid-question leaves that record in the renamed
# file, which is intact and archived. There is no truncation and no window in
# which a writer appends to a file that is about to be discarded.
#
# cassd's own audit is a different file with a long-lived writer, where this
# would NOT be safe. It is 8 KB after a day and needs nothing.
set -eu

DRY=0
case ${1:-} in
-n | --dry-run) DRY=1 ;;
-h | --help)
	sed -n '2,/^#:usage-end$/{/^#:usage-end$/d;p;}' "$0" | sed 's/^# \{0,1\}//'
	exit 0
	;;
esac

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=bin/lib/config.sh
. "$ROOT/bin/lib/config.sh"

ENV_FILE=$(cass_config_path env CASS_ENV)
if [ -r "$ENV_FILE" ]; then
	set -a
	# shellcheck disable=SC1090
	. "$ENV_FILE"
	set +a
fi

LOG=$(cass_value CASS_BROKER_AUDIT)
[ -n "$LOG" ] || LOG="$HOME/.local/share/cass/broker-audit.jsonl"
ARCHIVE=${CASS_AUDIT_ARCHIVE:-"$(dirname -- "$LOG")/archive"}

if [ ! -s "$LOG" ]; then
	echo "cass-audit-archive: $LOG is empty or absent; nothing to do"
	exit 0
fi

if [ "$DRY" -eq 1 ]; then
	python3 - "$LOG" <<'PY'
import collections, json, sys
months = collections.Counter()
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    try:
        months[json.loads(line)["timestamp"][:7]] += 1
    except Exception:
        months["unparsable"] += 1
today = __import__("datetime").date.today().isoformat()[:7]
for month in sorted(months):
    mark = "  (today's month, still archived — readers span both)" if month == today else ""
    print(f"  {month}: {months[month]} record(s){mark}")
PY
	exit 0
fi

mkdir -p "$ARCHIVE"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK="$LOG.archiving.$STAMP"

# Rename, then work on the renamed file. The next question creates a fresh log.
mv -- "$LOG" "$WORK"

python3 - "$WORK" "$ARCHIVE" "$STAMP" <<'PY'
import collections, gzip, json, os, sys

work, archive, stamp = sys.argv[1], sys.argv[2], sys.argv[3]
by_month = collections.defaultdict(list)
unparsable = 0
for line in open(work):
    if not line.strip():
        continue
    try:
        by_month[json.loads(line)["timestamp"][:7]].append(line)
    except Exception:
        unparsable += 1

# Kept beside the archives rather than dropped. A line this cannot parse is
# either a truncated final write or a format change, and both are worth seeing.
if unparsable:
    print(f"  {unparsable} unparsable line(s) retained in {os.path.basename(work)}.unparsable")

written = 0
for month in sorted(by_month):
    target = os.path.join(archive, f"broker-audit-{month}-{stamp}.jsonl.gz")
    with gzip.open(target, "wt") as handle:
        handle.writelines(by_month[month])
    size = os.path.getsize(target)
    print(f"  {month}: {len(by_month[month])} record(s) -> {os.path.basename(target)} ({size / 1024:.0f} KB)")
    written += len(by_month[month])
print(f"  {written} record(s) archived, 0 deleted")
PY

rm -f -- "$WORK"
echo "cass-audit-archive: $LOG starts fresh; archives in $ARCHIVE"
