#!/usr/bin/env python3
"""Run the graded evaluation and save everything a grader needs.

Usage:
  make eval-graded                      # RUNS=3, model from CASS_MODEL
  RUNS=1 ONLY=P1,S1 make eval-graded    # a quick plumbing check
  LABEL=thinking-off make eval-graded   # free text recorded in run.json

This harness does not grade. It asks each question in the question set's
questions.json through cass-chat, exactly as askcass does, and writes the
answer, the evidence, the audit record and a run-time reference value for each
one. Grading is done afterwards against the set's rubric.md, which is fixed
before the run; its sha256 goes in run.json so a later edit is visible. The
set lives in ~/.config/cass/eval_graded/ (EVAL_GRADED_SET overrides it).

References are computed at run time, directly against pegasusdb (through the
mysql client and ~/.my.cnf), Zabbix and Wazuh, so a total that has grown since
the rubric was written is still compared with the truth at the moment of
asking. They are never passed to the model.

Output: ~/eval-runs/<UTC time>-<model>/
  answers.jsonl    one line per (case, run): answer, evidence, timing, error
  audit.jsonl      cass-chat's own audit records (-audit), plan and SQL
  reference.jsonl  one line per case, before the first and after the last run
  run.json         model, commit, label, rubric sha256, start and end
"""
import datetime, hashlib, json, os, statistics, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_common import (DEFAULT_POLICY, ROOT, build_chat, config_path,
                         default_model, require_env, wazuh_agent_counts,
                         zabbix_count)

# The question set names this site's hosts and is kept with the site's
# configuration, not in the repository: ~/.config/cass/eval_graded/, holding
# questions.json and rubric.md. EVAL_GRADED_SET points elsewhere.
DATA = os.environ.get("EVAL_GRADED_SET") or config_path("eval_graded")
RUNS = int(os.environ.get("RUNS", "3"))
ONLY = [c for c in os.environ.get("ONLY", "").split(",") if c]
LABEL = os.environ.get("LABEL", "")


def mysql(sql):
    proc = subprocess.run(["mysql", "-N", "-B", "-e", sql],
                          capture_output=True, text=True, timeout=300)
    if proc.returncode:
        return {"error": proc.stderr.strip()}
    return [line.split("\t") for line in proc.stdout.splitlines()]


def percentile(values, p):
    """Continuous percentile, the same definition as PERCENTILE_CONT."""
    values = sorted(values)
    if not values:
        return None
    k = (len(values) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def reference(ref):
    kind = ref["kind"]
    try:
        if kind == "sql":
            return [mysql(sql) for sql in ref["sql"]]
        if kind == "percentiles":
            out = {}
            for name, sql in ref["sql"].items():
                rows = mysql(sql)
                if isinstance(rows, dict):
                    out[name] = rows
                    continue
                waits = [float(r[0]) for r in rows]
                out[name] = {"n": len(waits),
                             "p50_h": round(percentile(waits, 0.5) / 3600, 3) if waits else None,
                             "p95_h": round(percentile(waits, 0.95) / 3600, 3) if waits else None,
                             "mean_h": round(statistics.mean(waits) / 3600, 3) if waits else None}
            return out
        if kind == "zabbix_count":
            return {"problems": zabbix_count()}
        if kind == "wazuh_counts":
            active, disconnected = wazuh_agent_counts()
            return {"active": active, "disconnected": disconnected}
    except Exception as exc:  # a failed reference must not stop the run
        return {"error": repr(exc)}
    return None


def policy_path():
    """The policy askcass would use: a personal copy, else the repository's."""
    path = config_path("policy.json")
    return path if os.path.exists(path) else DEFAULT_POLICY


def ask(binary, model, audit, question):
    started = time.time()
    try:
        proc = subprocess.run(
            [binary, "-policy", policy_path(),
             "-json", "-audit", audit, "-model", model, question],
            capture_output=True, text=True, timeout=420)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "seconds": round(time.time() - started, 1)}
    out = {"seconds": round(time.time() - started, 1), "exit": proc.returncode,
           "stderr": proc.stderr.strip()[-2000:]}
    try:
        out.update(json.loads(proc.stdout))
    except ValueError:
        out["raw_stdout"] = proc.stdout
    return out


def main():
    require_env("mindrouter", "zabbix", "wazuh", "pegasus", "rt")
    model = default_model()
    cases = json.load(open(os.path.join(DATA, "questions.json")))["cases"]
    if ONLY:
        cases = [c for c in cases if c["id"] in ONLY]
    rubric = open(os.path.join(DATA, "rubric.md"), "rb").read()
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                            capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                                capture_output=True, text=True).stdout.strip())

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = os.path.expanduser("~/eval-runs/%s-%s" % (stamp, model.replace("/", "_").replace(":", "_")))
    os.makedirs(outdir)
    audit = os.path.join(outdir, "audit.jsonl")
    run = {"model": model, "label": LABEL, "runs": RUNS, "cases": [c["id"] for c in cases],
           "commit": commit, "dirty_tree": dirty,
           "rubric_sha256": hashlib.sha256(rubric).hexdigest(),
           "policy": policy_path(),
           "started": stamp}
    json.dump(run, open(os.path.join(outdir, "run.json"), "w"), indent=1)
    print("writing to", outdir, flush=True)

    binary = build_chat()
    with open(os.path.join(outdir, "answers.jsonl"), "w") as answers, \
         open(os.path.join(outdir, "reference.jsonl"), "w") as refs:
        for case in cases:
            before = reference(case["ref"])
            for n in range(1, RUNS + 1):
                result = ask(binary, model, audit, case["q"])
                result.update({"case": case["id"], "run": n, "q": case["q"],
                               "at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
                answers.write(json.dumps(result) + "\n")
                answers.flush()
                print("%-3s run %d  %5.1fs  %s" % (case["id"], n, result.get("seconds", 0),
                      result.get("error") or ("exit %s" % result.get("exit"))), flush=True)
            after = reference(case["ref"]) if case["ref"]["kind"] in ("zabbix_count", "wazuh_counts") else before
            refs.write(json.dumps({"case": case["id"], "kind": case["ref"]["kind"],
                                   "before": before, "after": after}) + "\n")
            refs.flush()

    run["finished"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json.dump(run, open(os.path.join(outdir, "run.json"), "w"), indent=1)
    print("done:", outdir)


if __name__ == "__main__":
    main()
