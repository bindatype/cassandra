#!/usr/bin/env python3
"""Exercise the accounting database through the full chat loop.

Usage:
    source ~/.config/cass/env
    python3 scripts/eval_pegasus.py [model]

This suite is different in kind from the Zabbix one. There the model chooses
among four intents and the connector computes every figure; here the model
composes the SQL, so the failure mode is a query that runs cleanly and answers
a different question than the one asked. Each case therefore has an
independently computed ground truth, obtained by a query written here rather
than by the model.

The cases are drawn from mistakes actually observed: using DerivedExitCode as
though it were a number, reaching for a timing column that exists only in the
fiscal year tables, leaving a reserved word unquoted, and summarizing a result
that was capped.
"""
import datetime, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_common import (ask, build_chat, default_model, normalize,
                         require_env, states_a_number, write_report)

# Resolved centrally, so this harness cannot drift from the model the
# deployment is actually running. It has drifted twice: these scripts once
# defaulted to qwen3.6:35b while the deployment used something else, so the
# step onboarding gives a newcomer to verify their setup exercised the wrong
# model; and then to gemma4:31b after the gateway had withdrawn it. See
# eval_common.default_model().
DEFAULT_MODEL = default_model()


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


def main():
    require_env("mindrouter", "pegasus")
    model = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL
    binary = build_chat()
    print("model: %s" % model, flush=True)

    # Ground truth, computed here so a wrong answer cannot agree with itself.
    week = ("SubmitTime >= UNIX_TIMESTAMP(NOW() - INTERVAL 7 DAY)")
    failed = truth("SELECT SUM(State='FAILED') FROM pegasusdb.runTBL2 WHERE " + week)
    completed = truth("SELECT SUM(State='COMPLETED') FROM pegasusdb.runTBL2 WHERE " + week)
    total = truth("SELECT COUNT(*) FROM pegasusdb.runTBL2 WHERE " + week)
    top = truth("SELECT netid FROM pegasusdb.runTBL2 WHERE " + week +
                " GROUP BY netid ORDER BY COUNT(*) DESC LIMIT 1")
    median = truth("SELECT DISTINCT ROUND(MEDIAN(WaitTime) OVER ()/3600,1) "
                   "FROM pegasusdb.FY2026 WHERE `partition`='cpu' "
                   "AND SubmitTime >= UNIX_TIMESTAMP('2026-05-01') "
                   "AND SubmitTime < UNIX_TIMESTAMP('2026-06-01') "
                   "AND StartTime > 0 AND State <> 'CANCELLED'")

    print("ground truth: failed=%s completed=%s total=%s top=%s median_hr=%s"
          % (failed, completed, total, top, median), flush=True)

    cases = [
        {"id": "job_total", "q": "how many jobs were submitted in the last 7 days?",
         "must": [total]},
        # The failure that motivated this suite: DerivedExitCode is a Slurm
        # 'exit:signal' string, and comparing it to zero silently miscounts.
        {"id": "failure_count",
         "q": "how many jobs failed in the last 7 days, and how many completed?",
         "must": [failed, completed]},
        {"id": "top_submitter",
         "q": "who submitted the most jobs in the last 7 days?",
         "must": [top]},
        # Requires noticing that WaitTime lives only in the fiscal year tables,
        # and that percentiles here are window functions.
        {"id": "median_wait",
         "q": "what was the median wait time in hours on the cpu partition in May 2026?",
         "must": [median]},
        # A reserved word the model must quote; previously a hard failure.
        {"id": "reserved_word",
         "q": "which partitions ran the most jobs in the last 3 days?",
         "must": ["cpu"]},
        # Asking for a listing must not produce a total counted from a capped
        # page. The window is given as explicit dates: "the last 2 days" is
        # ambiguous between NOW() and CURDATE(), which differ here by nine
        # hundred jobs, and an ambiguous question cannot grade an answer.
        {"id": "capped_result",
         "q": ("list the jobs submitted between 2026-08-25 and 2026-08-27 and "
               "tell me exactly how many there were"),
         "must": [truth("SELECT COUNT(*) FROM pegasusdb.runTBL2 WHERE "
                        "SubmitTime >= UNIX_TIMESTAMP('2026-08-25') AND "
                        "SubmitTime < UNIX_TIMESTAMP('2026-08-27')")]},
    ]

    rows = []
    for case in cases:
        answer, intent, _, seconds = ask(binary, model, case["q"])
        faults = []
        if intent != "database.query":
            faults.append("intent=%s" % (intent or "none"))
        if not answer.strip():
            faults.append("empty answer")
        for token in case.get("must", []):
            if not states_a_number(answer, token):
                faults.append("missing:%s" % token)
        rows.append({"case": case["id"], "seconds": seconds, "faults": faults,
                     "answer": answer})
        print("  %-15s %6.1fs  %s" % (
            case["id"], seconds,
            "PASS" if not faults else "FAIL " + "; ".join(faults)), flush=True)
        print("      %s" % answer[:150].replace("\n", " "), flush=True)

    passed = sum(1 for r in rows if not r["faults"])
    avg = sum(r["seconds"] for r in rows) / max(len(rows), 1)
    print("\n===== %s: %d/%d passed, avg %.1fs =====" % (model, passed, len(rows), avg))

    lines = ["Generated %s" % datetime.datetime.now().isoformat(timespec="seconds"),
             "", "Model `%s`: **%d/%d passed**, average %.1fs." % (model, passed, len(rows), avg),
             "", "Ground truth computed independently at run time: failed=%s, "
             "completed=%s, total=%s, top submitter=%s, median wait=%s hr."
             % (failed, completed, total, top, median),
             "", "| case | seconds | result |", "|---|---|---|"]
    for row in rows:
        lines.append("| `%s` | %.1f | %s |" % (
            row["case"], row["seconds"],
            "pass" if not row["faults"] else "FAIL: " + "; ".join(row["faults"])))
    write_report("eval-pegasus.md", "Cass accounting-database evaluation", lines)


if __name__ == "__main__":
    main()
