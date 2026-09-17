#!/usr/bin/env python3
"""Read the model-authored SQL out of the broker audit log.

    python3 scripts/audit_sql.py                 # what failed, grouped by cause
    python3 scripts/audit_sql.py --failed        # every failure, with its error
    python3 scripts/audit_sql.py --passed        # every query that ran
    python3 scripts/audit_sql.py --grep median   # either, filtered
    python3 scripts/audit_sql.py --record 3      # one question in full

Every question is recorded with the SQL the model wrote, so this is a corpus of
what the model actually does when asked for numbers, rather than a summary of
what it was supposed to do.

Failures are the more instructive half and were invisible until 2026-09-17: the
audit kept successful calls only, so a question that spent five turns failing
was recorded as the two that worked. Records older than that show passes with
no trace of what went wrong beside them.
"""
import argparse
import collections
import json
import os
import re
import sys

DEFAULT_LOG = "~/.local/share/cass/broker-audit.jsonl"


def load(path):
    """Yield (record, call) for every call that carries SQL.

    Bad lines are skipped rather than fatal. This is an append-only log written
    by a running service; a truncated final line means the service is mid-write,
    which is not a reason to refuse to read the other 1,600 records.
    """
    with open(os.path.expanduser(path)) as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            for call in record.get("calls") or []:
                query = call.get("query") or ""
                if "select" in query.lower():
                    yield record, call


def one_line(text, width=100):
    return re.sub(r"\s+", " ", (text or "").strip())[:width]


def cause(error):
    """Collapse an error to what is worth grouping on.

    MariaDB quotes the offending fragment back, which makes every message
    unique and every tally a count of one. The code and the shape of the
    complaint are what repeat.
    """
    error = one_line(error, 400)
    m = re.search(r"Error (\d+)", error)
    code = m.group(1) if m else "?"
    if "You have an error in your SQL syntax" in error:
        return f"{code} syntax error"
    if "Unknown column" in error:
        return f"{code} unknown column"
    if "doesn't exist" in error:
        return f"{code} no such table"
    if "denied" in error.lower():
        return f"{code} permission denied"
    if "timeout" in error.lower() or "max_statement_time" in error:
        return f"{code} exceeded the time limit"
    return f"{code} {one_line(error, 60)}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default=DEFAULT_LOG)
    parser.add_argument("--failed", action="store_true", help="only calls that errored")
    parser.add_argument("--passed", action="store_true", help="only calls that returned")
    parser.add_argument("--grep", help="substring, matched against question and SQL")
    parser.add_argument("--record", type=int, help="print the Nth listed item in full")
    parser.add_argument("--sql", action="store_true", help="print the SQL, not just the question")
    options = parser.parse_args()

    try:
        rows = list(load(options.log))
    except FileNotFoundError:
        sys.exit(f"no audit log at {options.log}; set CASS_BROKER_AUDIT and ask a question")

    if options.grep:
        needle = options.grep.lower()
        rows = [(r, c) for r, c in rows
                if needle in (r.get("question") or "").lower()
                or needle in (c.get("query") or "").lower()]
    if options.failed:
        rows = [(r, c) for r, c in rows if c.get("error")]
    if options.passed:
        rows = [(r, c) for r, c in rows if not c.get("error")]

    if options.record is not None:
        if not 1 <= options.record <= len(rows):
            sys.exit(f"--record must be between 1 and {len(rows)}")
        record, call = rows[options.record - 1]
        print("timestamp:", record.get("timestamp"))
        print("question: ", one_line(record.get("question"), 300))
        print("status:   ", record.get("status"), "|", record.get("error") or "no run-level error")
        print("\nSQL:\n" + (call.get("query") or "").strip())
        if call.get("error"):
            print("\nerror:\n  " + one_line(call["error"], 600))
        else:
            print("\nreturned:", call.get("item_count"), "row(s)",
                  "TRUNCATED" if call.get("truncated") else "")
        print("\nanswer:\n" + one_line(record.get("answer"), 900))
        return

    # No filter: the failures grouped by cause, which is the view worth having
    # first. A list of 932 successful queries tells you less than a tally of the
    # handful of ways the model gets it wrong.
    if not (options.failed or options.passed or options.grep):
        failures = [(r, c) for r, c in rows if c.get("error")]
        print(f"{len(rows)} SQL call(s): {len(rows) - len(failures)} returned, {len(failures)} failed\n")
        if failures:
            print("failures by cause:")
            for reason, count in collections.Counter(cause(c["error"]) for _, c in failures).most_common():
                print(f"  {count:4d}  {reason}")
            print("\n  --failed to see them, --record N for one in full")
        return

    for index, (record, call) in enumerate(rows, 1):
        mark = "FAIL" if call.get("error") else "ok  "
        print(f"{index:4d} {mark} {one_line(record.get('question'), 88)}")
        if options.sql or call.get("error"):
            print(f"        sql: {one_line(call.get('query'), 88)}")
        if call.get("error"):
            print(f"        err: {one_line(call['error'], 88)}")
    print(f"\n{len(rows)} shown. --record N for one in full.")


if __name__ == "__main__":
    main()
