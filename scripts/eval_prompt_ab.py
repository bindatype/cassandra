#!/usr/bin/env python3
"""A/B the pre-Zabbix prompt against the current one, on the same code.

Usage:
    source ~/.config/sroiaaa/env
    python3 scripts/eval_prompt_ab.py [model]
    RUNS=5 python3 scripts/eval_prompt_ab.py             # uses $CASS_MODEL
    RUNS=5 python3 scripts/eval_prompt_ab.py gemma4-31b-vllm

What this does and does not measure
-----------------------------------
Both arms run the CURRENT binary. Only the prompt differs. That is deliberate
and it is also the only honest option: the new prompt names evidence fields
(`total_ignoring_time_bound`, `breakdown.events_by_host`, `hosts_affected`)
that the old code never emitted, so running the old prompt on the old code
would compare two changes at once and tell you nothing about either.

So the question here is narrow and worth asking: given that the connector now
computes the aggregates and warnings, does the prompt still earn its added
length, or does the richer evidence carry the model on its own?

The cases are the reassuring failures -- the ones where a wrong answer reads as
good news. A prompt rule that only helps on questions Cass already answered
well is not worth 24 lines of a budget with 9.7 KB of headroom.

Ground truth is computed live, immediately before each run, because these
counts move: the active problem total was observed at 1841, 1458, 1846, 1844
and 1850 across a single afternoon.
"""
import datetime, json, os, ssl, subprocess, sys, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_common import (build_chat, default_model, first_sentence, normalize,
                        require_env, write_report)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPT = os.path.join(ROOT, "internal", "orchestrator", "prompt.md")
# The commit before the Zabbix query-control work began.
BASELINE_REV = os.environ.get("BASELINE_REV", "e94a4dd")
RUNS = int(os.environ.get("RUNS", "3"))
DEFAULT_MODEL = default_model()

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

AGENT_MATCH = "Zabbix agent is not available"


def zabbix(method, params):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "id": 1,
                       "params": params}).encode()
    req = urllib.request.Request(
        os.environ["CASS_ZABBIX_ENDPOINT"], data=body, method="POST",
        headers={"Content-Type": "application/json-rpc",
                 "Authorization": "Bearer " + os.environ["ZABBIX_RO_TOKEN"]})
    return json.load(urllib.request.urlopen(req, context=_CTX, timeout=60))["result"]


FIRING = {"only_true": True, "monitored": True, "skipDependent": True}


def agents_down():
    """Triggers firing now for an unavailable agent, and the hosts under them."""
    rows = zabbix("trigger.get", dict(FIRING, search={"description": AGENT_MATCH},
                                      output=["triggerid"], selectHosts=["host"],
                                      limit=5000))
    hosts = {r["hosts"][0]["host"] for r in rows if r.get("hosts")}
    return len(rows), len(hosts)


def problems_now():
    return int(zabbix("trigger.get", dict(FIRING, countOutput=True)))


def worst_host():
    rows = zabbix("trigger.get", dict(FIRING, min_severity=4, output=["triggerid"],
                                      selectHosts=["host"], limit=5000))
    counts = {}
    for row in rows:
        if row.get("hosts"):
            counts[row["hosts"][0]["host"]] = counts.get(row["hosts"][0]["host"], 0) + 1
    return max(counts, key=counts.get) if counts else None


def opened_last_24h():
    """Problems that OPENED in the last 24 hours.

    value=[1] is the opening event. Without it an incident that opened and
    closed inside the window is counted twice, which is the fault this case
    exists to catch -- so the ground truth must not commit it either.
    """
    since = int((datetime.datetime.now() - datetime.timedelta(hours=24)).timestamp())
    return int(zabbix("event.get", {"source": 0, "object": 0, "time_from": since,
                                    "value": [1], "countOutput": True}))


def says(answer, number):
    """Whether the answer states this integer, tolerating 1,234 and 1234."""
    text = normalize(answer)
    return str(number) in text.replace(",", "") or "{:,}".format(number) in text


def policy_path():
    """The deployed policy where there is one, the example otherwise.

    The other eval scripts assume ~/.config/sroiaaa/policy.json exists. It does
    on sgtstubby and does not on a fresh clone, and failing over to the example
    keeps the suite runnable in both places rather than only where it was
    written.
    """
    deployed = os.path.expanduser("~/.config/sroiaaa/policy.json")
    if os.path.exists(deployed):
        return deployed
    return os.path.join(ROOT, "configs", "broker-policy.example.json")


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


# Each case carries a callable for its ground truth, sampled immediately before
# AND after every individual ask, with any value in that range accepted.
#
# The first version of this suite sampled once for the whole run and compared
# minutes later. On this Zabbix the event log gains thousands of rows an hour,
# so the `double_count` case scored 0/3 against a figure that had been correct
# when it was taken and was stale by the time it was used. The Zabbix guide
# says exactly this -- "counts move fast, sample before and after, accept a
# range" -- and the suite did not do it.
CASES = [
    {"id": "false_allclear",
     "q": "Did any host lose its Zabbix agent since 5am today?",
     "why": "The event log is empty because an ongoing outage writes nothing inside its own window.",
     "truth": lambda: agents_down()[1], "lead": True},
    {"id": "narrow",
     "q": "Which hosts have lost their Zabbix agent?",
     "why": "Needs match rather than reading down a general page.",
     "truth": lambda: agents_down()[0]},
    {"id": "rows_vs_hosts",
     "q": "How many machines currently have a Zabbix agent problem?",
     "why": "Several triggers fire on one host; the trigger count is not the machine count.",
     "truth": lambda: agents_down()[1]},
    {"id": "population",
     "q": "How many problems are active right now?",
     "why": "A page size reported as a population.",
     "truth": problems_now, "forbid": ["25 problems", "200 problems"]},
    {"id": "worst_hosts",
     "q": "Which systems are in the worst shape right now?",
     "why": "Needs the per-host breakdown, not whichever hosts landed in the page.",
     "truth_text": worst_host},
    {"id": "double_count",
     # "since yesterday" is ambiguous between "the last 24 hours" and "since
     # yesterday began", and the two differ by tens of thousands of rows here.
     # A case that punishes a model for choosing the other reading is measuring
     # the question, not the prompt.
     "q": "How many problems started in the last 24 hours?",
     "why": "Counting both the opening and closing event doubles the figure.",
     "truth": opened_last_24h},
]


def numbers_in(answer):
    out = []
    for token in normalize(answer).replace(",", " ").replace("*", " ").split():
        digits = "".join(c for c in token if c.isdigit())
        if digits:
            out.append(int(digits))
    return out


def grade(case, answer, low, high, expect_text):
    """Return (substance_faults, lead_faults).

    Substance and lead are graded apart because collapsing them hid the thing
    this A/B was built to see. On `false_allclear` the old prompt omitted the
    current outage entirely while the new prompt reported it and merely led
    with the wrong clause; scored as one bit, both read as 0/3 and the
    improvement was invisible.
    """
    if not answer:
        return ["empty"], []
    text = normalize(answer)
    substance, lead = [], []

    if low is not None:
        if not any(low <= n <= high for n in numbers_in(answer)):
            substance.append("missing:%d-%d" % (low, high))
    if expect_text and expect_text.lower() not in text:
        substance.append("missing:%s" % expect_text)
    for token in case.get("forbid", []):
        if token.lower() in text:
            substance.append("said:%s" % token)

    # A first sentence that carries BOTH the "no" and the current failure is a
    # good answer, not a bad one: "No host has lost its agent since 5am, but 14
    # hosts currently have it down" tells a reader who stops there the truth.
    # Only a first sentence that is reassuring AND silent about the outage
    # fails.
    if case.get("lead") and low is not None:
        first = first_sentence(answer)
        reassuring = any(p in first for p in ("no host", "no hosts", "none"))
        carries = any(low <= n <= high for n in numbers_in(first))
        if reassuring and not carries:
            lead.append("lead-omits-the-outage")
    return substance, lead


def main():
    require_env()
    model = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL
    binary = build_chat()

    baseline = subprocess.run(["git", "show", "%s:internal/orchestrator/prompt.md" % BASELINE_REV],
                              cwd=ROOT, capture_output=True, text=True)
    if baseline.returncode != 0:
        sys.exit("cannot read the baseline prompt at %s: %s" % (BASELINE_REV, baseline.stderr.strip()))
    old_path = os.path.join(ROOT, "runtime", "prompt-baseline.md")
    os.makedirs(os.path.dirname(old_path), exist_ok=True)
    with open(old_path, "w") as fh:
        fh.write(baseline.stdout)
    current = open(PROMPT).read()

    arms = [("old", old_path, len(baseline.stdout)), ("new", PROMPT, len(current))]
    print("model: %s   %d runs per case   same binary, prompt is the only variable" % (model, RUNS))
    print("  old prompt  %s  %d chars" % (BASELINE_REV, len(baseline.stdout)))
    print("  new prompt  working tree  %d chars  (+%d)\n"
          % (len(current), len(current) - len(baseline.stdout)), flush=True)

    tally = {name: {} for name, _, _ in arms}
    for case in CASES:
        print("── %s ─ %s" % (case["id"], case["why"]), flush=True)
        for name, path, _ in arms:
            subs_pass, lead_pass, seconds = 0, 0, []
            for _ in range(RUNS):
                # Sampled around the ask, not once for the suite: this event log
                # gains thousands of rows an hour.
                before = case["truth"]() if "truth" in case else None
                expect_text = case["truth_text"]() if "truth_text" in case else None
                answer, took = ask(binary, model, path, case["q"])
                after = case["truth"]() if "truth" in case else None
                seconds.append(took)

                low = high = None
                if before is not None:
                    low, high = min(before, after), max(before, after)
                substance, lead = grade(case, answer, low, high, expect_text)
                if not substance:
                    subs_pass += 1
                if not lead:
                    lead_pass += 1
                if substance or lead:
                    print("     %-3s %-26s %s" % (name, ";".join(substance + lead),
                                                  answer[:88].replace("\n", " ")), flush=True)
            tally[name][case["id"]] = (subs_pass, lead_pass)
            note = "" if not case.get("lead") else "  lead %d/%d" % (lead_pass, RUNS)
            print("     %-3s substance %d/%d%s  avg %.1fs"
                  % (name, subs_pass, RUNS, note, sum(seconds) / len(seconds)), flush=True)
        print(flush=True)

    def total(name):
        return sum(v[0] for v in tally[name].values())

    lines = ["Generated %s" % datetime.datetime.now().isoformat(timespec="seconds"), "",
             "Model `%s`, %d runs per case. **Both arms run the same binary**; the prompt"
             " is the only variable, because the new prompt names evidence fields the old"
             " code never emitted." % (model, RUNS), "",
             "Old prompt `%s`, %d chars. New prompt, %d chars (+%d)."
             % (BASELINE_REV, len(baseline.stdout), len(current), len(current) - len(baseline.stdout)), "",
             "Ground truth is sampled immediately before and after every ask and any value"
             " in that range is accepted; these counts move by thousands an hour.", "",
             "| case | old | new | what it catches |", "|---|---|---|---|"]
    for case in CASES:
        old_s, _ = tally["old"][case["id"]]
        new_s, _ = tally["new"][case["id"]]
        lines.append("| `%s` | %d/%d | %d/%d | %s |"
                     % (case["id"], old_s, RUNS, new_s, RUNS, case["why"]))
    lines += ["", "**Substance total: old %d/%d, new %d/%d.**"
              % (total("old"), len(CASES) * RUNS, total("new"), len(CASES) * RUNS)]
    for case in CASES:
        if case.get("lead"):
            lines += ["", "Lead-sentence check on `%s`: old %d/%d, new %d/%d."
                      % (case["id"], tally["old"][case["id"]][1], RUNS,
                         tally["new"][case["id"]][1], RUNS)]

    print("===== substance: old %d/%d   new %d/%d ====="
          % (total("old"), len(CASES) * RUNS, total("new"), len(CASES) * RUNS))
    write_report("eval-prompt-ab.md", "Prompt A/B: pre-Zabbix baseline vs current", lines)


if __name__ == "__main__":
    main()
