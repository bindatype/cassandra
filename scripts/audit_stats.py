#!/usr/bin/env python3
"""Distributions from the broker audit log, for setting limits by measurement.

    python3 scripts/audit_stats.py
    python3 scripts/audit_stats.py --since 2026-09-01

Every bound in this system -- the connector timeout, the per-result byte cap,
the turn budget, each connector's row limit -- was chosen once and has been
carried since. This reports what the traffic actually does against them, so a
change to any of them can be argued from the record rather than from intuition.

Percentiles are nearest-rank on the sorted sample. The samples are small enough
that interpolation would imply a precision the data does not have.
"""
import argparse
import collections
import glob
import gzip
import json
import os
import sys

DEFAULT_LOG = "~/.local/share/cass/broker-audit.jsonl"


def percentile(values, fraction):
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def summarize(label, values, unit=""):
    if not values:
        print(f"  {label:<28} no samples")
        return
    print(f"  {label:<28} n={len(values):<6} p50={percentile(values,.5):<8} "
          f"p90={percentile(values,.9):<8} p99={percentile(values,.99):<8} max={max(values)}{unit}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default=DEFAULT_LOG)
    parser.add_argument("--since", help="ISO date; records before it are ignored")
    options = parser.parse_args()

    sources = audit_files(options.log)
    if not sources:
        sys.exit(f"no audit log or archives at {options.log}")
    records = [r for r in read_records(options.log)
               if not options.since or (r.get("timestamp") or "") >= options.since]

    if not records:
        sys.exit("no records matched")

    first = min(r.get("timestamp", "") for r in records)[:10]
    last = max(r.get("timestamp", "") for r in records)[:10]
    print(f"{len(records)} question(s), {first} to {last}\n")

    # --- end to end, which is what a person waits for --------------------
    print("QUESTION LATENCY (ms)")
    summarize("whole question", [r["duration_ms"] for r in records if r.get("duration_ms")])
    answered = [r for r in records if r.get("status") == "answered"]
    print(f"  answered {len(answered)}, failed {len(records) - len(answered)}"
          f"  ({100.0 * len(answered) / len(records):.1f}% answered)\n")

    # --- turns, against maxToolCalls -------------------------------------
    print("TURNS PER QUESTION (against maxToolCalls = 5)")
    turns = collections.Counter(len(r.get("calls") or []) for r in records)
    for count in sorted(turns):
        bar = "#" * min(40, turns[count] * 40 // max(turns.values()))
        print(f"  {count} call(s): {turns[count]:5d}  {bar}")
    spent = sum(n for c, n in turns.items() if c >= 5)
    print(f"  at or above the limit: {spent}\n")

    # --- per source, against its own timeout and row cap ------------------
    print("PER SOURCE")
    by_source = collections.defaultdict(list)
    failures = collections.Counter()
    truncations = collections.Counter()
    items = collections.defaultdict(list)
    for record in records:
        for call in record.get("calls") or []:
            key = f"{call.get('source')}/{call.get('action')}"
            if call.get("error"):
                failures[key] += 1
                continue
            by_source[key].append(call.get("duration_ms") or 0)
            if call.get("truncated"):
                truncations[key] += 1
            if call.get("item_count"):
                items[key].append(call["item_count"])

    # The union, not just the sources that succeeded. Failed attempts are
    # recorded against orchestrator/attempt_failed, which has no successes at
    # all -- so iterating by_source reported "0 failed" for everything while 39
    # questions had failed. A statistics script that cannot see failures is
    # worse than none, because it looks like evidence of health.
    for key in sorted(set(by_source) | set(failures), key=lambda k: -(len(by_source[k]) + failures[k])):
        total = len(by_source[key]) + failures[key]
        print(f"\n  {key}   {total} call(s), {failures[key]} failed, "
              f"{truncations[key]} truncated ({100.0 * truncations[key] / max(1, len(by_source[key])):.0f}%)")
        summarize("    duration", by_source[key], "ms")
        if items[key]:
            summarize("    items returned", items[key])

    # --- the log itself ---------------------------------------------------
    size = sum(os.path.getsize(name) for name in sources)
    days = max(1, len(set((r.get("timestamp") or "")[:10] for r in records)))
    print(f"\nAUDIT LOG\n  {size / 1048576:.1f} MB across {len(sources)} file(s) over {days} day(s)"
          f"  ~{size / days / 1024:.0f} KB/day on disk")


def audit_files(path):
    """The active log plus every archive beside it, newest content last.

    Archiving would otherwise make history disappear from these reports without
    saying so -- the file would still be there, still readable, and quietly
    describe only the days since the last archive run. A reader that silently
    narrows its own window is the same failure this project keeps finding
    elsewhere.
    """
    active = os.path.expanduser(path)
    archive = os.path.join(os.path.dirname(active), "archive")
    found = sorted(glob.glob(os.path.join(archive, "broker-audit-*.jsonl.gz")))
    if os.path.exists(active):
        found.append(active)
    return found


def read_records(path):
    """Every record from the active log and its archives, in timestamp order.

    Sorted rather than trusted to file order: archives are written per run, so
    two runs in one month produce two files, and nothing guarantees the names
    sort the way the contents do.
    """
    records = []
    for name in audit_files(path):
        opener = gzip.open if name.endswith(".gz") else open
        with opener(name, "rt") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
    records.sort(key=lambda r: r.get("timestamp") or "")
    return records

if __name__ == "__main__":
    main()
