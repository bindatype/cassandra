#!/usr/bin/env python3
"""Measure one rule: does leading with the failure actually change the lead?

Usage:
    source ~/.config/cass/env
    python3 scripts/eval_lead.py [model]
    RUNS=15 python3 scripts/eval_lead.py            # uses $CASS_MODEL
    RUNS=15 python3 scripts/eval_lead.py gemma4-31b-vllm

Why this is separate from eval_prompt_ab.py
-------------------------------------------
The A/B against the pre-Zabbix prompt cannot answer this. That prompt scores
0/3 on substance for these questions -- it never finds the current outage at
all -- so there is nothing for it to lead with and the comparison is vacuous.
Isolating a rule means removing exactly that rule and changing nothing else.

The block is removed here by its literal text rather than through the
`<!-- rule: -->` markers eval_ablate.py uses. Those markers are deliberately
absent from rules about not turning an absence into a reassurance, so that a
short run cannot recommend dropping one. Measuring such a rule on purpose is
fine; leaving it in the general ablation sweep is not.

What is graded
--------------
The FIRST SENTENCE only. Every one of these questions has a literally-true
negative answer -- nothing new failed in the window -- while machines are down
right now. An answer that opens with the negative and corrects itself two
sentences later is right in substance and still misleads a reader who stops,
which is how these are read in a chat channel.

Each run lands in one of three states, kept apart because averaging them hides
the thing being measured:

  lead-ok        the first sentence carries the current outage
  lead-buried    the outage is in the answer but not in the first sentence
  not-found      the outage is absent entirely; the lead question is moot,
                 and this run is excluded from the lead rate rather than
                 counted as a failure of sentence order
"""
import datetime, json, os, ssl, subprocess, sys, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_common import (config_path, build_chat, default_model, first_sentence, normalize,
                        require_env, write_report)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPT = os.path.join(ROOT, "internal", "orchestrator", "prompt.md")
RUNS = int(os.environ.get("RUNS", "10"))
DEFAULT_MODEL = default_model()

RULE_ANCHOR = '**Lead with the broken thing, not with the true "no".**'

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

QUESTIONS = [
    "Did any host lose its Zabbix agent since 5am today?",
    "Has anything gone wrong with Zabbix agents this morning?",
    "Any new Zabbix agent failures in the last 3 hours?",
]

# Openings that promise good news. A first sentence containing one of these and
# no count is the failure this rule exists to prevent.
REASSURING = ("no host", "no hosts", "no new", "nothing", "none", "no agent",
              "no zabbix agent", "there have been no", "no issues", "all clear")


def zabbix(method, params):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "id": 1,
                       "params": params}).encode()
    req = urllib.request.Request(
        os.environ["CASS_ZABBIX_ENDPOINT"], data=body, method="POST",
        headers={"Content-Type": "application/json-rpc",
                 "Authorization": "Bearer " + os.environ["ZABBIX_RO_TOKEN"]})
    return json.load(urllib.request.urlopen(req, context=_CTX, timeout=60))["result"]


def agents_down():
    """(triggers, hosts) currently firing for an unavailable Zabbix agent."""
    rows = zabbix("trigger.get", {
        "only_true": True, "monitored": True, "skipDependent": True,
        "search": {"description": "Zabbix agent is not available"},
        "output": ["triggerid"], "selectHosts": ["host"], "limit": 5000})
    hosts = {r["hosts"][0]["host"] for r in rows if r.get("hosts")}
    return len(rows), len(hosts)


def numbers_in(text):
    out = []
    for token in normalize(text).replace(",", " ").replace("*", " ").split():
        digits = "".join(c for c in token if c.isdigit())
        if digits:
            out.append(int(digits))
    return out


def classify(answer, wanted):
    """One of lead-ok, lead-buried, not-found."""
    if not answer:
        return "not-found"
    body = numbers_in(answer)
    if not any(n in wanted for n in body):
        return "not-found"
    lead = first_sentence(answer)
    if any(n in wanted for n in numbers_in(lead)):
        return "lead-ok"
    # A first sentence with no count is only a failure if it also promises good
    # news; "I checked two sources" leads nowhere and says nothing false.
    if any(p in lead for p in REASSURING):
        return "lead-buried"
    return "lead-ok"


def ask(binary, model, prompt_path, question):
    env = dict(os.environ, CASS_PROMPT=prompt_path)
    started = time.time()
    try:
        proc = subprocess.run(
            [binary, "-policy", policy_path(), "-wazuh-insecure", "-model", model, question],
            capture_output=True, text=True, timeout=420, env=env, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return "", round(time.time() - started, 1)
    return proc.stdout.strip(), round(time.time() - started, 1)


def policy_path():
    deployed = config_path("policy.json")
    return deployed if os.path.exists(deployed) else os.path.join(
        ROOT, "configs", "broker-policy.example.json")


def without_rule(text):
    """Remove the lead rule and nothing else."""
    start = text.index(RULE_ANCHOR)
    end = text.index("\n\n", start)
    return text[:start] + text[end + 2:]


def main():
    require_env("mindrouter", "wazuh")
    model = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL
    binary = build_chat()

    current = open(PROMPT).read()
    if RULE_ANCHOR not in current:
        sys.exit("the lead rule is not in the prompt; nothing to isolate")
    stripped = without_rule(current)

    runtime = os.path.join(ROOT, "runtime")
    os.makedirs(runtime, exist_ok=True)
    without_path = os.path.join(runtime, "prompt-no-lead-rule.md")
    with open(without_path, "w") as fh:
        fh.write(stripped)

    arms = [("without", without_path), ("with", PROMPT)]
    print("model: %s   %d runs per question per arm   %d questions"
          % (model, RUNS, len(QUESTIONS)))
    print("  rule is %d chars; prompt %d -> %d without it\n"
          % (len(current) - len(stripped), len(current), len(stripped)), flush=True)

    tally = {name: {"lead-ok": 0, "lead-buried": 0, "not-found": 0} for name, _ in arms}
    seconds = {name: [] for name, _ in arms}
    examples = {name: [] for name, _ in arms}

    for question in QUESTIONS:
        print("── %s" % question, flush=True)
        for name, path in arms:
            counts = {"lead-ok": 0, "lead-buried": 0, "not-found": 0}
            for _ in range(RUNS):
                # Sampled per ask: an agent recovering mid-run changes the
                # number the answer should contain.
                triggers, hosts = agents_down()
                wanted = {triggers, hosts}
                answer, took = ask(binary, model, path, question)
                verdict = classify(answer, wanted)
                counts[verdict] += 1
                tally[name][verdict] += 1
                seconds[name].append(took)
                if verdict == "lead-buried" and len(examples[name]) < 3:
                    examples[name].append(first_sentence(answer)[:110])
            print("     %-8s ok %2d   buried %2d   not-found %2d"
                  % (name, counts["lead-ok"], counts["lead-buried"],
                     counts["not-found"]), flush=True)
        print(flush=True)

    def rate(name):
        """Lead rate over the runs where a lead was possible at all."""
        t = tally[name]
        eligible = t["lead-ok"] + t["lead-buried"]
        return t["lead-ok"], eligible

    lines = ["Generated %s" % datetime.datetime.now().isoformat(timespec="seconds"), "",
             "Model `%s`, %d runs per question, %d questions, %d runs per arm."
             % (model, RUNS, len(QUESTIONS), RUNS * len(QUESTIONS)), "",
             "The rule under test is %d characters. Everything else in the prompt, and"
             " the binary, is identical between arms." % (len(current) - len(stripped)), "",
             "| arm | lead-ok | lead-buried | not-found | lead rate |", "|---|---|---|---|---|"]
    for name, _ in arms:
        ok, eligible = rate(name)
        t = tally[name]
        lines.append("| `%s` | %d | %d | %d | **%s** |" % (
            name, t["lead-ok"], t["lead-buried"], t["not-found"],
            "%d/%d" % (ok, eligible) if eligible else "n/a"))
    lines += ["", "`not-found` runs are excluded from the lead rate: an answer that never"
              " located the outage cannot be judged on whether it led with it.", ""]
    for name, _ in arms:
        if examples[name]:
            lines += ["Buried leads, `%s`:" % name] + \
                     ["- \"%s\"" % e for e in examples[name]] + [""]

    for name, _ in arms:
        ok, eligible = rate(name)
        print("%-8s lead rate %s   avg %.1fs"
              % (name, "%d/%d" % (ok, eligible) if eligible else "n/a",
                 sum(seconds[name]) / max(len(seconds[name]), 1)))
    write_report("eval-lead.md", "Does the lead-with-the-failure rule work?", lines)


if __name__ == "__main__":
    main()
