#!/usr/bin/env python3
"""Exercise the Zabbix monitoring plane through the full chat loop.

Usage:
    source ~/.config/cass/env
    python3 scripts/eval_zabbix.py [model]

Covers both shapes the broker's single Zabbix intent supports, scoped and
unscoped by host, plus the normalizations a reader depends on: resolved trigger
macros, rendered timestamps, and honest disclosure when evidence is truncated.
"""
import datetime, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_common import (ask, build_chat, default_model, normalize,
                         numbers_in, require_env, write_report, zabbix_count)

# Resolved centrally, so this harness cannot drift from the model the
# deployment is actually running. It has drifted twice: these scripts once
# defaulted to qwen3.6:35b while the deployment used something else, so the
# step onboarding gives a newcomer to verify their setup exercised the wrong
# model; and then to gemma4:31b after the gateway had withdrawn it. See
# eval_common.default_model().
DEFAULT_MODEL = default_model()
# A host known to carry several correlated problems. Change if it is remediated.
SUBJECT_HOST = os.environ.get("EVAL_HOST", "dss01")


def main():
    require_env("mindrouter", "zabbix")
    model = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL
    binary = build_chat()
    print("model: %s   subject host: %s" % (model, SUBJECT_HOST), flush=True)

    cases = [
        {"id": "total_problems", "intent": "monitoring.problems",
         "q": "how many active problems are there in total across all hosts?",
         "volatile": None},
        {"id": "host_scoped", "intent": "monitoring.problems",
         "q": "what problems are currently active on host %s?" % SUBJECT_HOST,
         "host": SUBJECT_HOST, "must": [SUBJECT_HOST]},
        {"id": "most_severe", "intent": "monitoring.problems",
         "q": "what is the single most severe problem right now, and on which host?"},
        {"id": "severity_split", "intent": "monitoring.problems",
         "q": "on host %s, how many problems are there at each severity level?" % SUBJECT_HOST,
         "host": SUBJECT_HOST, "must": [SUBJECT_HOST], "volatile": SUBJECT_HOST},
        {"id": "truncation", "intent": "monitoring.problems",
         "q": "list every active problem in the environment. did you see all of them?",
         "must": ["truncat"]},
        {"id": "macro_check", "intent": "monitoring.problems",
         "q": "describe the most severe problem on host %s in one sentence." % SUBJECT_HOST,
         "must": [SUBJECT_HOST], "forbid": ["{HOST.NAME}", "{$IB.PORT}"]},
    ]

    rows = []
    for case in cases:
        volatile = "volatile" in case
        before = zabbix_count(case.get("volatile")) if volatile else None
        answer, intent, host, seconds = ask(binary, model, case["q"])
        after = zabbix_count(case.get("volatile")) if volatile else None

        faults = []
        if intent != case["intent"]:
            faults.append("intent=%s" % (intent or "none"))
        if case.get("host") and host != case["host"]:
            faults.append("host=%s" % (host or "none"))
        text = normalize(answer)
        for token in case.get("must", []):
            if token.lower() not in text:
                faults.append("missing:%s" % token)
        for token in case.get("forbid", []):
            if token.lower() in text:
                faults.append("leaked:%s" % token)
        if before is not None:
            low, high = min(before, after), max(before, after)
            if not any(low <= n <= high for n in numbers_in(text)):
                faults.append("count outside [%d,%d]" % (low, high))

        rows.append({"case": case["id"], "seconds": seconds, "faults": faults,
                     "answer": answer})
        print("  %-16s %6.1fs  %s" % (
            case["id"], seconds,
            "PASS" if not faults else "FAIL " + "; ".join(faults)), flush=True)
        print("      %s" % answer[:160].replace("\n", " "), flush=True)

    passed = sum(1 for r in rows if not r["faults"])
    avg = sum(r["seconds"] for r in rows) / max(len(rows), 1)
    print("\n===== %s: %d/%d passed, avg %.1fs =====" % (model, passed, len(rows), avg))

    lines = ["Generated %s" % datetime.datetime.now().isoformat(timespec="seconds"),
             "", "Model `%s`, subject host `%s`: **%d/%d passed**, average %.1fs."
             % (model, SUBJECT_HOST, passed, len(rows), avg), "",
             "| case | seconds | result |", "|---|---|---|"]
    for row in rows:
        lines.append("| `%s` | %.1f | %s |" % (
            row["case"], row["seconds"],
            "pass" if not row["faults"] else "FAIL: " + "; ".join(row["faults"])))
    write_report("eval-zabbix.md", "Cass Zabbix evidence-loop evaluation", lines)


if __name__ == "__main__":
    main()
