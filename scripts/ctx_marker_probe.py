#!/usr/bin/env python3
"""Find where a served model stops seeing the head of its context.

Run this after any gateway or model change, and put the result in
servedContextTokens in internal/orchestrator/session.go. The constant was
correct at 32768 for as long as the backend was ollama and wrong the moment it
became vLLM; nothing in the system notices that on its own.

The previous version of this probe was written in /tmp on one host, produced
the finding that the gateway discarded the head of an oversized prompt, and
was gone by the time the backend changed and the finding needed re-checking.
That is why it is in the repository now.

A model that is handed more context than the gateway will serve does not
usually fail: it answers, and the answer is wrong in a way nothing reports.
This probe makes that failure visible by planting three unique words in a
prompt -- ALPHA at the very top, BRAVO in the middle, CHARLIE at the very
bottom -- and asking which ones survived.  A run that reports CHARLIE alone
has had its head cut off, and the head is where the system prompt lives.

The prompt size on the x-axis is not estimated.  Each response carries
usage.prompt_tokens, which is what the server actually tokenised, so the
table reports the size the server saw rather than the size we hoped for.

  ctx_marker_probe.py -model gemma4-31b-vllm 8000 32000 40000 120000
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

MARKERS = ("ALPHA", "BRAVO", "CHARLIE")

# Filler has to be text the model will not compress into a summary and will
# not mistake for an instruction.  Numbered inventory lines read as data.
def filler(lines, start):
    return "\n".join(
        "record %06d  host node%04d  state nominal  checksum %08x"
        % (i, i % 4096, (i * 2654435761) & 0xFFFFFFFF)
        for i in range(start, start + lines)
    )


def build(target_tokens, tokens_per_line):
    """A system message holding ALPHA and BRAVO, a user message ending CHARLIE.

    Both markers that matter sit in the system message because that is where
    the real system prompt sits: ALPHA on its first line, BRAVO exactly
    halfway down the filler.  CHARLIE rides at the end of the user turn, the
    one position a tail-keeping truncation cannot touch -- it is the control.
    """
    lines = max(2, int(target_tokens / tokens_per_line))
    half = lines // 2
    system = "\n".join([
        "ALPHA is the first word of this document. Remember it.",
        filler(half, 0),
        "BRAVO is the middle word of this document. Remember it.",
        filler(lines - half, half),
    ])
    user = (
        "Above is a document. Which of the words ALPHA, BRAVO, CHARLIE appear "
        "in it or in this question? Answer with just those words, comma "
        "separated, and nothing else. Do not guess: name only the ones you "
        "can actually see.\nCHARLIE is the last word of this question."
    )
    return system, user


def call(base, key, model, system, user, timeout):
    body = {
        "model": model,
        "max_tokens": 40,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    req = urllib.request.Request(
        base.rstrip("/") + "/v1/chat/completions",
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + key},
    )
    try:
        d = json.load(urllib.request.urlopen(req, timeout=timeout))
    except urllib.error.HTTPError as e:
        return None, "HTTP %d %s" % (e.code, e.read()[:120].decode("utf8", "replace"))
    except Exception as e:                       # noqa: BLE001 - report, don't raise
        return None, str(e)[:120]
    if "error" in d:
        return None, str(d["error"])[:120]
    return d, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-model", required=True)
    ap.add_argument("-timeout", type=float, default=900)
    ap.add_argument("sizes", nargs="+", type=int)
    args = ap.parse_args()

    # The old spelling is still accepted, as everywhere else, so a probe run on
    # a host that has not migrated does not fail with "set CASS_..." against an
    # environment that is perfectly good.
    base = os.environ.get("CASS_MINDROUTER_ENDPOINT") or os.environ.get("SROIAAA_MINDROUTER_ENDPOINT")
    key = os.environ.get("MINDROUTER_API_KEY")
    if not base or not key:
        sys.exit("set CASS_MINDROUTER_ENDPOINT and MINDROUTER_API_KEY")

    # Calibrate chars-per-line against this model's own tokeniser once, so the
    # requested size and the served size stay close enough to read as a sweep.
    tokens_per_line = 16.0
    system, user = build(2000, tokens_per_line)
    d, err = call(base, key, args.model, system, user, args.timeout)
    if d:
        served = d["usage"]["prompt_tokens"]
        tokens_per_line *= served / 2000.0
        print("calibration: %.2f tokens per filler line\n" % tokens_per_line)
    else:
        print("calibration failed (%s); using default\n" % err)

    print("%9s %9s  %-22s %s" % ("asked", "served", "markers seen", "answer"))
    for target in args.sizes:
        system, user = build(target, tokens_per_line)
        d, err = call(base, key, args.model, system, user, args.timeout)
        if err:
            print("%9d %9s  %-22s %s" % (target, "-", "-", err))
            continue
        text = (d["choices"][0]["message"].get("content") or "").strip()
        seen = [m for m in MARKERS if m in text.upper()]
        print("%9d %9d  %-22s %s" % (
            target, d["usage"]["prompt_tokens"],
            ",".join(seen) or "none", text.replace("\n", " ")[:60]))


if __name__ == "__main__":
    main()
