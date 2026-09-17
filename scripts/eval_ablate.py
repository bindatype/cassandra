#!/usr/bin/env python3
"""Find which prompt rules a given model actually needs.

Usage:
    source ~/.config/cass/env
    python3 scripts/eval_ablate.py [model]

The prompt grew by accretion: nearly every rule was added because some model
got something wrong, and the models changed underneath it. A rule added for one
model is not evidence that another needs it, and length is not free -- a longer
prompt measurably costs tool-call adherence.

This removes one marked rule at a time, reruns the head-to-head suite, and
reports whether the score held. A rule whose removal costs nothing is not
earning its place for this model.

Safety rules cannot be ablated here. Refusing to turn a missing data source
into a reassurance is not a performance optimisation, and five runs is not the
evidence on which to drop it.

That protection used to be the absence of a marker, which meant a rule was safe
only while nobody tagged it. On 2026-09-03 eleven rules were tagged so their
loss could be guarded, and four of them were safety rules -- the tagging was
right and the protection silently ended. Something that holds only while nobody
does the obvious thing is not a protection. It is now a named list, and this
refuses to run if any name on it has stopped existing.
"""
import os, re, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_common import default_model, require_env, write_report

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPT = os.path.join(ROOT, "internal", "orchestrator", "prompt.md")
SUITE = os.path.join(ROOT, "scripts", "eval_headtohead.py")
RUNS = int(os.environ.get("RUNS", "3"))

MARKER = re.compile(r"(?m)^<!-- rule:([a-z0-9-]+) -->\n")

# Rules whose removal could turn an absence of evidence into a reassurance.
# Each of these exists because a wrong answer read as good news, and none is a
# performance knob. They are excluded from ablation regardless of what a score
# would say -- and the suite here is a pegasusdb one, so for most of them it
# would say "costs nothing" while being structurally unable to see the failure.
SAFETY_RULES = {
    "grouped-truncation":       "half the groups vanish with every visible row correct",
    "unrun-check-not-allclear": "\"no critical agents are disconnected\" posted while five were",
    "ongoing-not-in-log":       "an empty event log during an ongoing outage reads as all-clear",
    "no-cve-source":            "a CVE question answered from trigger data, for a host that did not exist",
    "lead-with-broken":         "a reader who stops after one sentence gets the opposite impression",
    "counts-from-summary":      "275 records tallied as 55 against a true 52",
    "rt-metadata-only":         "ticket bodies carry user PII and pasted credentials",
    "oldruntbl-compressed":     "a LIKE that silently misses the jobs it was asked about",
    "ingestion-lag":            "a partial day reported as a total",
}


def rules(text):
    return [m.group(1) for m in MARKER.finditer(text)]


def ablatable(text):
    """Marked rules that may be removed, and a refusal if the safety list has
    gone stale.

    A protected name that no longer exists in the prompt protects nothing, and
    would do it quietly: the loop below would simply never skip it. That is the
    same shape as the failure this list replaces.
    """
    marked = set(rules(text))
    missing = sorted(SAFETY_RULES.keys() - marked)
    if missing:
        sys.exit("these safety rules are no longer marked in the prompt, so nothing here is "
                 "protecting them: %s\nEither restore the markers or remove the names, "
                 "deliberately." % ", ".join(missing))
    return [name for name in rules(text) if name not in SAFETY_RULES]


def without(text, name):
    """Remove one marked block.

    A block runs from its marker to an explicit end marker where it spans
    paragraphs, and otherwise to the next blank line. Getting this wrong is
    quiet: an earlier version cut only the first line of a forty-line block and
    reported it as removed, so the result said the block was unnecessary when
    it had never been taken out.
    """
    start = text.index("<!-- rule:%s -->" % name)
    closing = text.find("<!-- /rule -->", start)
    next_rule = text.find("<!-- rule:", start + 1)

    # A closing marker belongs to this block only if it comes before the next
    # block starts. Where it does, it wins outright: the paragraph break is
    # nearer but is inside the block, which is how a forty-line block was
    # previously trimmed to its heading.
    if closing != -1 and (next_rule == -1 or closing < next_rule):
        end = closing + len("<!-- /rule -->\n\n")
    else:
        # Consecutive bullets share a list with no blank line between them, so
        # the next marker is often nearer than the next paragraph break. Taking
        # the paragraph break alone swallowed every rule below it.
        paragraph = text.find("\n\n", start)
        candidates = [x for x in (next_rule, paragraph + 2 if paragraph != -1 else -1) if x != -1]
        end = min(candidates) if candidates else len(text)
    return text[:start] + text[end:]


def score(model, prompt_path):
    env = dict(os.environ, CASS_PROMPT=prompt_path, RUNS=str(RUNS))
    out = subprocess.run([sys.executable, SUITE, model], capture_output=True,
                         text=True, env=env, timeout=3600)
    got = re.search(r"^\s+%s\s+(\d+)/(\d+)\s+avg\s+([\d.]+)s" % re.escape(model),
                    out.stdout, re.M)
    if not got:
        return None, None
    return int(got.group(1)), float(got.group(3))


def main():
    require_env()
    model = sys.argv[1] if len(sys.argv) > 1 else default_model()
    original = open(PROMPT).read()
    names = ablatable(original)
    skipped = sorted(SAFETY_RULES)
    print("skipping %d safety rule(s); their removal is not a question a score can answer:"
          % len(skipped), file=sys.stderr)
    for name in skipped:
        print("  %-26s %s" % (name, SAFETY_RULES[name]), file=sys.stderr)

    print("model: %s   %d ablatable rules   %d runs per case\n" % (model, len(names), RUNS), flush=True)

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
        fh.write(original)
        baseline_path = fh.name
    base_score, base_time = score(model, baseline_path)
    if base_score is None:
        sys.exit("baseline run produced no score; check the suite")
    print("  baseline (all rules)          %d  %.1fs  %d chars\n" % (base_score, base_time, len(original)), flush=True)

    results = []
    for name in names:
        variant = without(original, name)
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
            fh.write(variant)
            path = fh.name
        got, seconds = score(model, path)
        os.unlink(path)
        saved = len(original) - len(variant)
        verdict = "unknown"
        if got is not None:
            verdict = "not needed" if got >= base_score else "NEEDED (-%d)" % (base_score - got)
        results.append((name, got, seconds, saved, verdict))
        print("  without %-22s %s  %.1fs  saves %4d chars  %s" % (
            name, str(got).rjust(2), seconds or 0, saved, verdict), flush=True)

    os.unlink(baseline_path)

    droppable = [r for r in results if r[4] == "not needed"]
    print("\n  %d of %d rules could be removed without loss, saving %d chars"
          % (len(droppable), len(names), sum(r[3] for r in droppable)))

    lines = ["Model `%s`, baseline **%d** at %.1fs, prompt %d chars.\n"
             % (model, base_score, base_time, len(original)),
             "| rule | score without it | verdict | chars saved |", "|---|---|---|---|"]
    for name, got, _, saved, verdict in results:
        lines.append("| `%s` | %s | %s | %d |" % (name, got, verdict, saved))
    write_report("eval-ablate.md", "Which prompt rules this model needs", lines)


if __name__ == "__main__":
    main()
