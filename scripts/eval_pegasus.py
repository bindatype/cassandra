#!/usr/bin/env python3
"""Exercise the accounting database through the full chat loop.

Usage:
    source ~/.config/cass/env
    python3 scripts/eval_pegasus.py [model]
    python3 scripts/eval_pegasus.py --self-test    # grader only, no credentials

This suite is different in kind from the Zabbix one. There the model chooses
among four intents and the connector computes every figure; here the model
composes the SQL, so the failure mode is a query that runs cleanly and answers
a different question than the one asked. Each case therefore has an
independently computed ground truth, obtained by a query written here rather
than by the model.

The cases are drawn from mistakes actually observed: using DerivedExitCode as
though it were a number, leaving a reserved word unquoted, summarizing a result
that was capped, and a GROUP BY that collapsed each partition before
PERCENTILE_CONT ran, so P50 came back equal to P95.

Exits non-zero when any case fails, so a run can gate something.

Rewritten 2026-10-01 after a thinking on/off comparison showed two of six
"failures" were the harness's own:
- the median reference filtered `State <> 'CANCELLED'`, which the prompt's
  waittime-filters rule forbids (it keeps `CANCELLED by <uid>`): 11.09 h
  against a correct 11.65 h;
- "between 2026-08-25 and 2026-08-27" did not say whether the 27th counted.
Every window is now explicit whole days, in the past by more than the
ingestion lag, so the reference cannot move while the model is answering.
"""
import datetime, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_common import (ask, build_chat, default_model, normalize,
                         require_env, write_report)

# Resolved centrally, so this harness cannot drift from the model the
# deployment is actually running. See eval_common.default_model().
DEFAULT_MODEL = default_model()

# Same exclusions the prompt mandates for wait-time analysis (waittime-filters).
WAIT_FILTERS = "StartTime > 0 AND State NOT LIKE 'CANCELLED%'"


def truth(sql):
    """Run a verification query directly, bypassing the loop under test.

    Uses the mysql client and its ~/.my.cnf rather than a driver, so the script
    needs no dependency beyond what the host already has for ad hoc queries.
    """
    import subprocess
    out = subprocess.run(["mysql", "-N", "-B", "-e", sql],
                         capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError("ground-truth query failed: " + out.stderr.strip())
    return out.stdout.strip()


# --- grading -----------------------------------------------------------------

def _numbers(text):
    """Every number in the answer, with its position, separators removed."""
    flat = normalize(text)
    return [(float(m.group()), m.start(), m.end())
            for m in re.finditer(r"\d+(?:\.\d+)?", flat)], flat


def states_value(text, expected, rel=0.0, abs_tol=0.0):
    """Whether the answer states `expected` anywhere.

    Exact by default: a count is right or it is not. Pass a tolerance only for
    values that are legitimately rounded, such as a percentile in hours.
    """
    want = float(expected)
    for value, _, _ in _numbers(text)[0]:
        if abs(value - want) <= max(abs_tol, rel * abs(want)):
            return True
    return False


def states_labeled(text, expected, labels, rivals=(), window=60):
    """Whether `expected` appears with one of `labels` as its nearest label.

    Catches swapped figures: "24,963 failed and 2,053 completed" states both
    true numbers and passes a presence check, but here 2,053's nearest label
    is "completed", a rival, so it fails.
    """
    want = float(expected)
    numbers, flat = _numbers(text)
    spots = [(m.start(), m.end(), label in labels)
             for label in tuple(labels) + tuple(rivals)
             for m in re.finditer(re.escape(label), flat)]
    for value, start, end in numbers:
        if value != want:
            continue
        near = [(max(ls - end, start - le, 0), ours) for ls, le, ours in spots]
        near = [n for n in near if n[0] <= window]
        if near and min(near)[1]:
            return True
    return False


def self_test():
    """The grader is as likely to be wrong as the model; check it first."""
    checks = [
        # Exact counts: thousands separators fine, near misses not.
        (states_value("27,689 jobs were submitted.", 27689), True),
        (states_value("27,604 jobs were submitted.", 27689), False),
        # Rounded values within tolerance only.
        (states_value("median wait was 11.65 hours", 11.65, rel=0.005), True),
        (states_value("median wait was 11.7 hours", 11.65, rel=0.005), True),
        (states_value("median wait was 11.09 hours", 11.65, rel=0.005), False),
        # Labels: the real thinking-on answer from 2026-10-01 must pass...
        (states_labeled("In the last 7 days, 24,960 jobs completed and 2,186 failed. "
                        "The failure count includes: - FAILED: 2,053 - TIMEOUT: 104",
                        2053, ("fail",), ("complet",)), True),
        (states_labeled("In the last 7 days, 24,960 jobs completed and 2,186 failed.",
                        24960, ("complet",), ("fail",)), True),
        # ...and a swapped answer must not, even when the labels sit close by.
        (states_labeled("24,963 failed and 2,053 completed.", 2053, ("fail",), ("complet",)), False),
        (states_labeled("2,053 completed and 24,963 failed.", 2053, ("fail",), ("complet",)), False),
        (states_labeled("2,053 jobs failed and 24,963 completed.", 2053, ("fail",), ("complet",)), True),
    ]
    bad = [i for i, (got, want) in enumerate(checks) if got != want]
    if bad:
        print("grader self-test FAILED on check(s) %s" % bad)
        return 1
    print("grader self-test: %d checks pass" % len(checks))
    return 0


# --- cases -------------------------------------------------------------------

def day_window(days, end_offset=2):
    """`days` whole days ending `end_offset` days ago, clear of ingestion lag."""
    end = datetime.date.today() - datetime.timedelta(days=end_offset)
    start = end - datetime.timedelta(days=days - 1)
    return start, end


def between(start, end):
    """SQL for whole days start..end inclusive."""
    return ("SubmitTime >= UNIX_TIMESTAMP('%s') AND SubmitTime < UNIX_TIMESTAMP('%s')"
            % (start, end + datetime.timedelta(days=1)))


def build_cases():
    week_start, week_end = day_window(7)
    week = between(week_start, week_end)
    span = "submitted on the seven days %s through %s, inclusive" % (week_start, week_end)
    p3_start, p3_end = day_window(3)

    failed = truth("SELECT SUM(State='FAILED') FROM pegasusdb.runTBL2 WHERE " + week)
    completed = truth("SELECT SUM(State='COMPLETED') FROM pegasusdb.runTBL2 WHERE " + week)
    total = truth("SELECT COUNT(*) FROM pegasusdb.runTBL2 WHERE " + week)
    top = truth("SELECT netid FROM pegasusdb.runTBL2 WHERE " + week +
                " GROUP BY netid ORDER BY COUNT(*) DESC LIMIT 1")

    may = between(datetime.date(2026, 5, 1), datetime.date(2026, 5, 31))
    # Either table is a correct place to answer from: the prompt prefers runTBL2
    # for recent analysis and allows FY2026 when the period is inside it.
    median_run = truth("SELECT DISTINCT ROUND(MEDIAN(StartTime - SubmitTime) OVER ()/3600, 2) "
                       "FROM pegasusdb.runTBL2 WHERE `partition`='cpu' AND " + may +
                       " AND " + WAIT_FILTERS)
    median_fy = truth("SELECT DISTINCT ROUND(MEDIAN(WaitTime) OVER ()/3600, 2) "
                      "FROM pegasusdb.FY2026 WHERE `partition`='cpu' AND " + may +
                      " AND " + WAIT_FILTERS)

    two_start, two_end = datetime.date(2026, 8, 25), datetime.date(2026, 8, 26)
    two_days = truth("SELECT COUNT(*) FROM pegasusdb.runTBL2 WHERE " + between(two_start, two_end))

    # Per-partition percentiles over raw rows, the shape the GROUP BY collision
    # broke. P50 and P95 must both be stated and must differ.
    pct = {}
    for line in truth(
            "SELECT DISTINCT `partition`, "
            "ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY StartTime - SubmitTime) "
            "OVER (PARTITION BY `partition`)/60, 2), "
            "ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY StartTime - SubmitTime) "
            "OVER (PARTITION BY `partition`)/60, 2) "
            "FROM pegasusdb.runTBL2 WHERE `partition` IN ('cpu','gpu') AND " + week +
            " AND " + WAIT_FILTERS).splitlines():
        part, p50, p95 = line.split("\t")
        pct[part] = (float(p50), float(p95))

    ground = ("failed=%s completed=%s total=%s top=%s median_hr=%s|%s two_days=%s pct=%s"
              % (failed, completed, total, top, median_run, median_fy, two_days, pct))

    cases = [
        {"id": "job_total",
         "q": "how many jobs were %s?" % span,
         "checks": [("total", lambda a: states_value(a, total))]},
        # DerivedExitCode is a Slurm 'exit:signal' string; comparing it to zero
        # silently miscounts. Labels catch an answer that swaps the two figures.
        {"id": "failure_count",
         "q": "of the jobs %s, how many failed and how many completed?" % span,
         "checks": [("failed", lambda a: states_labeled(a, failed, ("fail",), ("complet", "succe"))),
                    ("completed", lambda a: states_labeled(a, completed, ("complet", "succe"), ("fail",)))]},
        {"id": "top_submitter",
         "q": "who submitted the most jobs on the seven days %s through %s, inclusive?"
              % (week_start, week_end),
         "checks": [("top", lambda a: top.lower() in a.lower())]},
        {"id": "median_wait",
         "q": "what was the median wait time in hours on the cpu partition for jobs "
              "submitted in May 2026?",
         "checks": [("median", lambda a: states_value(a, median_run, rel=0.005)
                     or states_value(a, median_fy, rel=0.005))]},
        # A reserved word the model must quote; previously a hard failure.
        {"id": "reserved_word",
         "q": "which partitions ran the most jobs submitted on %s through %s, inclusive?"
              % (p3_start, p3_end),
         "checks": [("cpu", lambda a: "cpu" in a.lower())]},
        # A listing must not produce a total counted from the capped page.
        {"id": "capped_result",
         "q": ("list the jobs submitted on 2026-08-25 and 2026-08-26 (those two whole "
               "days only) and tell me exactly how many there were"),
         "checks": [("count", lambda a: states_value(a, two_days))]},
        {"id": "partition_percentiles",
         "q": "for jobs %s, what were the median (P50) and 95th percentile (P95) wait "
              "times in minutes on the cpu partition and on the gpu partition?" % span,
         "checks": [("%s_%s" % (part, name), (lambda v: lambda a: states_value(a, v, rel=0.01, abs_tol=0.01))(value))
                    for part in ("cpu", "gpu") if part in pct
                    for name, value in zip(("p50", "p95"), pct[part])]},
    ]
    return cases, ground


def main():
    if "--self-test" in sys.argv:
        return self_test()
    if self_test() != 0:
        return 1
    require_env("mindrouter", "pegasus")
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    model = args[0] if args else DEFAULT_MODEL
    binary = build_chat()
    print("model: %s" % model, flush=True)

    cases, ground = build_cases()
    print("ground truth: " + ground, flush=True)

    rows = []
    for case in cases:
        answer, intent, _, seconds = ask(binary, model, case["q"])
        faults = []
        if intent != "database.query":
            faults.append("intent=%s" % (intent or "none"))
        if not answer.strip():
            faults.append("empty answer")
        for name, check in case["checks"]:
            if not check(answer):
                faults.append("missing:%s" % name)
        rows.append({"case": case["id"], "seconds": seconds, "faults": faults,
                     "answer": answer})
        print("  %-22s %6.1fs  %s" % (
            case["id"], seconds,
            "PASS" if not faults else "FAIL " + "; ".join(faults)), flush=True)
        print("      %s" % answer[:150].replace("\n", " "), flush=True)

    passed = sum(1 for r in rows if not r["faults"])
    avg = sum(r["seconds"] for r in rows) / max(len(rows), 1)
    print("\n===== %s: %d/%d passed, avg %.1fs =====" % (model, passed, len(rows), avg))

    lines = ["Generated %s" % datetime.datetime.now().isoformat(timespec="seconds"),
             "", "Model `%s`: **%d/%d passed**, average %.1fs." % (model, passed, len(rows), avg),
             "", "Ground truth computed independently at run time: %s" % ground,
             "", "| case | seconds | result |", "|---|---|---|"]
    for row in rows:
        lines.append("| `%s` | %.1f | %s |" % (
            row["case"], row["seconds"],
            "pass" if not row["faults"] else "FAIL: " + "; ".join(row["faults"])))
    lines += ["", "## Answers", ""]
    for row in rows:
        lines += ["### `%s`" % row["case"], "", row["answer"].strip() or "(empty)", ""]
    write_report("eval-pegasus.md", "Cass accounting-database evaluation", lines)
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
