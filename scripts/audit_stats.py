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

    try:
        handle = open(os.path.expanduser(options.log))
    except FileNotFoundError:
        sys.exit(f"no audit log at {options.log}")

    records = []
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if options.since and (record.get("timestamp") or "") < options.since:
                continue
            records.append(record)

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

    for key in sorted(by_source, key=lambda k: -len(by_source[k])):
        total = len(by_source[key]) + failures[key]
        print(f"\n  {key}   {total} call(s), {failures[key]} failed, "
              f"{truncations[key]} truncated ({100.0 * truncations[key] / max(1, len(by_source[key])):.0f}%)")
        summarize("    duration", by_source[key], "ms")
        if items[key]:
            summarize("    items returned", items[key])

    # --- the log itself ---------------------------------------------------
    size = os.path.getsize(os.path.expanduser(options.log))
    days = max(1, len(set((r.get("timestamp") or "")[:10] for r in records)))
    print(f"\nAUDIT LOG\n  {size / 1048576:.1f} MB over {days} day(s) with records"
          f"  ~{size / days / 1024:.0f} KB/day, no rotation configured")


if __name__ == "__main__":
    main()
