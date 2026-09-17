#!/usr/bin/env python3
"""Compare two models across the question shapes that actually differ.

Usage:
    source ~/.config/cass/env
    python3 scripts/eval_headtohead.py gemma4-31b-vllm some-other-model

Every earlier comparison used one question, an aggregate returning a single
row. Two models scored perfectly on it and nothing separated them, because the
row cap, the context window and the multi-turn loop were all inert for that
shape. This runs the shapes that engage them:

  aggregate       one row, the baseline
  grouped         many groups, engages the row cap
  two_step        needs a schema lookup before the query
  no_source       must be refused, not answered from the nearest source
  concept         a term with no column; must be derived, not refused
  listing         genuinely more rows than the cap allows

Ground truth is computed here, per question, immediately before the run.
"""
import json, os, re, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_common import (config_path, build_chat, default_model, normalize, require_env,
                        states_a_number, write_report)

RUNS = int(os.environ.get("RUNS", "5"))


def truth(sql):
    out = subprocess.run(["mysql", "-N", "-B", "-e", sql], capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        raise RuntimeError("ground truth failed: " + out.stderr.strip())
    return out.stdout.strip()


def ask(binary, model, question):
    started = time.time()
    try:
        proc = subprocess.run(
            [binary, "-policy", config_path("policy.json"),
             "-wazuh-insecure", "-model", model, question],
            capture_output=True, text=True, timeout=420)
        answer = proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return "", "timeout", round(time.time() - started, 1)
    seconds = round(time.time() - started, 1)
    if not answer:
        return "", "empty", seconds
    low = answer.lower()
    if "cass_evidence" in low or "intent=" in low or "i will now" in low or "let's construct" in low:
        return answer, "narrated", seconds
    return answer, "", seconds


def grade(case, answer):
    """Return a list of faults; empty means the answer is right."""
    faults = []
    text = normalize(answer)
    for token in case.get("must", []):
        if not states_a_number(answer, token):
            faults.append("missing:%s" % token)
    for token in case.get("must_say", []):
        if token.lower() not in text:
            faults.append("missing:%s" % token)
    for token in case.get("must_not_say", []):
        if token.lower() in text:
            faults.append("said:%s" % token)
    # Name a known wrong reading rather than reporting a bare miss, so the
    # report says which question the model actually answered.
    if "wrong_reading" in case and faults:
        value, label = case["wrong_reading"]
        if states_a_number(answer, value, tolerance=0.05):
            faults = [label]
    return faults


def main():
    require_env("mindrouter", "zabbix", "wazuh", "pegasus")
    # No default pair. There used to be one, naming two models the gateway has
    # since stopped serving, so a bare run failed at the first call with a
    # model-not-found rather than saying what it needed. A comparison has to be
    # told what to compare.
    models = sys.argv[1:]
    if len(models) < 2:
        sys.exit("usage: eval_headtohead.py MODEL MODEL [MODEL...]\n"
                 "  a head-to-head needs at least two models to compare;\n"
                 "  the gateway's current default is %s" % default_model())
    binary = build_chat()

    day = "2025-08-05"
    med = truth("SELECT DISTINCT ROUND(MEDIAN(EndTime-StartTime) OVER ()/3600,2) FROM pegasusdb.runTBL2 "
                "WHERE `partition`='defq' AND DATE(FROM_UNIXTIME(SubmitTime))='%s' AND State='COMPLETED'" % day)
    njobs = truth("SELECT COUNT(*) FROM pegasusdb.runTBL2 WHERE `partition`='defq' "
                  "AND DATE(FROM_UNIXTIME(SubmitTime))='%s' AND State='COMPLETED'" % day)
    top = truth("SELECT `partition` FROM pegasusdb.runTBL2 WHERE DATE(FROM_UNIXTIME(SubmitTime))='%s' "
                "GROUP BY `partition` ORDER BY COUNT(*) DESC LIMIT 1" % day)
    ngroups = truth("SELECT COUNT(DISTINCT netid) FROM pegasusdb.runTBL2 "
                    "WHERE SubmitTime >= UNIX_TIMESTAMP(NOW() - INTERVAL 90 DAY) AND StartTime > 0")
    nsshare = truth("SELECT COUNT(*) FROM information_schema.columns "
                    "WHERE table_schema='pegasusdb' AND table_name='sshare_data'")
    # Fixed dates, not a rolling window. "Last week" moved the truth eighteen
    # percent in a single night, so a model whose window differed from the
    # grader's by a few hours failed a question it had answered correctly. A
    # volatile target cannot grade an answer.
    week = ("WHERE `partition`='cpu' AND SubmitTime >= UNIX_TIMESTAMP('2026-08-18') "
            "AND SubmitTime < UNIX_TIMESTAMP('2026-08-25') "
            "AND StartTime > 0 AND State NOT LIKE 'CANCELLED%'")
    # This must match the filter the prompt teaches. When it did not, the
    # model followed the prompt, the grader used a different rule, and the
    # five percent gap looked like a model failure for two days.
    qdelay = truth("SELECT ROUND(AVG(StartTime - SubmitTime),0) FROM pegasusdb.runTBL2 " + week)
    qruntime = truth("SELECT ROUND(AVG(EndTime - StartTime),0) FROM pegasusdb.runTBL2 " + week)

    cases = [
        {"id": "aggregate", "shape": "one row",
         "q": "what was the median runtime for defq on August 5th, 2025? How many jobs were used?",
         "must": [med, njobs]},
        {"id": "grouped", "shape": "many groups",
         "q": "how many distinct users submitted jobs in the last 90 days?",
         "must": [ngroups]},
        {"id": "two_step", "shape": "schema then query",
         "q": "how many columns does the sshare_data table have?",
         "must": [nsshare]},
        {"id": "no_source", "shape": "must refuse",
         "q": "which login nodes have unpatched critical CVEs?",
         "must_say": ["not"], "must_not_say": ["no critical cves are", "none were found"]},
        # Named for a column that does not exist. Refusing is the wrong answer:
        # queue delay is derivable as StartTime - SubmitTime, and a model that
        # says the data is unavailable has stopped one step short. The trap is
        # answering with runtime, EndTime - StartTime, which is a different
        # quantity roughly seventeen times larger and just as confidently
        # stated. Grading on the number distinguishes the two; grading on
        # refusal failed both.
        {"id": "concept", "shape": "derive, do not refuse",
         "q": ("what is the average queue_delay_seconds for the cpu partition "
               "between 2026-08-18 and 2026-08-25?"),
         "must": [qdelay], "wrong_reading": (qruntime, "answered runtime, not queue delay")},
        {"id": "listing", "shape": "exceeds the cap",
         "q": "which partition ran the most jobs on August 5th, 2025?",
         "must_say": [top]},
    ]

    print("ground truth: median=%s jobs=%s top_partition=%s users=%s sshare_cols=%s"
          % (med, njobs, top, ngroups, nsshare), flush=True)
    print("              queue_delay=%ss  (runtime, the wrong reading, is %ss)"
          % (qdelay, qruntime), flush=True)
    print("%d runs per case per model\n" % RUNS, flush=True)

    results = {}
    for model in models:
        print("  %s" % model, flush=True)
        results[model] = {}
        for case in cases:
            passes, times, notes = 0, [], []
            for _ in range(RUNS):
                answer, failure, seconds = ask(binary, model, case["q"])
                times.append(seconds)
                if failure:
                    notes.append(failure)
                    continue
                faults = grade(case, answer)
                if faults:
                    notes.append(faults[0])
                else:
                    passes += 1
            results[model][case["id"]] = (passes, sum(times) / len(times), notes)
            print("    %-11s %-18s %d/%d  %5.1fs  %s" % (
                case["id"], case["shape"], passes, RUNS, sum(times) / len(times),
                ", ".join(sorted(set(notes))[:3])), flush=True)
        print(flush=True)

    lines = ["| case | shape | " + " | ".join("`%s`" % m for m in models) + " |",
             "|---|---|" + "---|" * len(models)]
    for case in cases:
        row = "| `%s` | %s |" % (case["id"], case["shape"])
        for model in models:
            passes, _, _ = results[model][case["id"]]
            row += " %d/%d |" % (passes, RUNS)
        lines.append(row)

    print("===== totals =====")
    for model in models:
        total = sum(results[model][c["id"]][0] for c in cases)
        avg = sum(results[model][c["id"]][1] for c in cases) / len(cases)
        print("  %-20s %d/%d   avg %.1fs" % (model, total, RUNS * len(cases), avg))
        lines.append("")
        lines.append("`%s`: **%d/%d**, average %.1fs per question."
                     % (model, total, RUNS * len(cases), avg))

    write_report("eval-headtohead.md", "Cass head-to-head model comparison", lines)


if __name__ == "__main__":
    main()
