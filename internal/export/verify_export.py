#!/usr/bin/env python3
"""Verify a Pegasus export directory against its manifest.

Usage: python3 verify_export.py [--json] <export-directory>

Exit codes:
  0  every check passed and the request was fulfilled
  3  every check passed, but the request was only partially fulfilled or not
     fulfilled (the manifest says why, truthfully)
  1  a check failed: the manifest's claims are not supported by the files
  2  usage error

This is an independent implementation, in Python, of the rules the exporter
applies in Go; it shares no code with it. VERIFIER.md lists every check and
what is deliberately not checked. Standard library only (Python 3.9+).
"""
import csv
import datetime
import gzip
import hashlib
import io
import json
import math
import os
import re
import sys
from fractions import Fraction

NULL = "\\N"
SUPPORTED_MANIFEST = 1
PLAIN_JOBID = re.compile(r"^[0-9]+$")
ARRAY_JOBID = re.compile(r"^([0-9]+)_([0-9]+)$")
MEM = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([MGT])$")
WHOLE = re.compile(r"^[0-9]+$")
MEM_SHIFT = {"M": 20, "G": 30, "T": 40}
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

csv.field_size_limit(10 * 1024 * 1024)


class Report:
    def __init__(self):
        self.results = []

    def check(self, check_id, name, passed, detail):
        self.results.append({"id": check_id, "name": name, "passed": bool(passed), "detail": detail})
        return passed

    @property
    def ok(self):
        return all(r["passed"] for r in self.results)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path, columns):
    """Yield data rows as lists, with NULL markers turned into None. Raises on
    a header mismatch, a short or long row, or a truncated gzip stream."""
    with gzip.open(path, "rt", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        if header != columns:
            raise ValueError("header %s is not %s" % (",".join(header), ",".join(columns)))
        for n, row in enumerate(reader, start=1):
            if len(row) != len(columns):
                raise ValueError("row %d has %d fields, expected %d" % (n, len(row), len(columns)))
            yield [None if v == NULL else v for v in row]


def epoch_for(date, zone):
    from zoneinfo import ZoneInfo
    y, m, d = (int(x) for x in date.split("-"))
    return int(datetime.datetime(y, m, d, tzinfo=ZoneInfo(zone)).timestamp())


def local_time(epoch, zone):
    from zoneinfo import ZoneInfo
    t = datetime.datetime.fromtimestamp(epoch, ZoneInfo(zone))
    text = t.isoformat()
    return text[:-6] + "Z" if text.endswith("+00:00") else text


def blank(v):
    return v is None or v.strip() == ""


def derive(raw, fields, identity_column, zone):
    """Re-derive every normalized field from one raw row (a dict of source
    column -> value or None). Returns (values, flags-by-field)."""
    values, flags = {}, {}

    def flag(field, *names):
        flags.setdefault(field, []).extend(names)

    job = raw.get("JobID")
    values["job_id"] = job
    if job is not None and PLAIN_JOBID.match(job):
        values["array_parent_id"] = values["array_task_index"] = None
    elif job is not None and ARRAY_JOBID.match(job):
        parent, index = ARRAY_JOBID.match(job).groups()
        values["array_parent_id"], values["array_task_index"] = parent, index
    else:
        values["array_parent_id"] = values["array_task_index"] = None
        flag("array_parent_id", "jobid_malformed")
        flag("array_task_index", "jobid_malformed")

    who = raw.get(identity_column)
    values["researcher_key"] = who if not blank(who) else None
    if blank(who):
        flag("researcher_key", "netid_missing")
    values["account"] = raw.get("groupName")

    epoch = int(raw["SubmitTime"]) if raw.get("SubmitTime") is not None else None
    if epoch is not None:
        values["submit_epoch"] = str(epoch)
        local = local_time(epoch, zone)
        values["submit_local"] = local
        values["submit_month"] = local[:7]

    part = raw.get("partition")
    values["partition_raw"] = part
    if part is None or part == "":
        flag("partition_raw", "partition_missing")
    elif "_" in part:
        flag("partition_raw", "partition_unresolved")
    values["state"] = raw.get("State")

    cpus = raw.get("ReqCPUS")
    values["req_cpus"] = cpus
    if cpus is None:
        flag("req_cpus", "cpus_missing")
    elif raw.get("TRESReq_cpu") not in (None, "") and raw.get("TRESReq_cpu") != cpus:
        flag("req_cpus", "cpu_tres_mismatch")

    recorded = not blank(raw.get("TRESReq_mem"))
    node = raw.get("TRESReq_node")
    if not recorded:
        values["req_nodes"] = None
        flag("req_nodes", "tres_unrecorded")
    elif node is None or node == "":
        values["req_nodes"] = None
        flag("req_nodes", "nodes_missing")
    elif WHOLE.match(node):
        values["req_nodes"] = str(int(node))
    else:
        values["req_nodes"] = None
        flag("req_nodes", "nodes_invalid")

    gpu = raw.get("TRESReq_gres_gpu")
    if not recorded:
        values["req_gpus"] = None
        flag("req_gpus", "tres_unrecorded")
    elif gpu is None or gpu == "":
        values["req_gpus"] = "0"
    elif WHOLE.match(gpu):
        values["req_gpus"] = str(int(gpu))
    else:
        values["req_gpus"] = None
        flag("req_gpus", "gpus_invalid")

    mem = raw.get("TRESReq_mem")
    values["req_mem_raw"] = mem
    if blank(mem):
        values["req_mem_bytes"] = None
        flag("req_mem_bytes", "mem_missing")
    elif not MEM.match(mem):
        values["req_mem_bytes"] = None
        flag("req_mem_bytes", "mem_invalid")
    else:
        number, unit = MEM.match(mem).groups()
        amount = Fraction(number)
        if amount == 0:
            values["req_mem_bytes"] = None
            flag("req_mem_bytes", "mem_special")
        else:
            values["req_mem_bytes"] = str(math.floor(amount * (1 << MEM_SHIFT[unit]) + Fraction(1, 2)))
            flag("req_mem_bytes", "mem_scope_assumed_job_total")

    limit = raw.get("TimelimitRaw")
    values["req_walltime_raw"] = limit
    if blank(limit):
        values["req_walltime_s"] = None
        flag("req_walltime_s", "walltime_missing")
    elif limit == "UNLIMITED":
        values["req_walltime_s"] = None
        flag("req_walltime_s", "walltime_unlimited")
    elif limit == "Partition":
        values["req_walltime_s"] = None
        flag("req_walltime_s", "walltime_partition_default")
    elif WHOLE.match(limit):
        values["req_walltime_s"] = str(int(limit) * 60)
    else:
        values["req_walltime_s"] = None
        flag("req_walltime_s", "walltime_invalid")

    delivered = set(fields)
    values["quality_flags"] = ";".join(sorted({f for name, fs in flags.items() if name in delivered for f in fs}))
    return values


def expected_fulfillment(deliver, raw_state, norm_state, unavailable):
    if raw_state != "complete":
        return "not_fulfilled"
    if deliver == "normalized" and norm_state != "validated":
        return "not_fulfilled"
    if unavailable > 0:
        return "partially_fulfilled"
    return "fulfilled"


def verify(directory):
    r = Report()
    path = lambda name: os.path.join(directory, name)

    # V1: the manifest exists and is a version this verifier understands.
    try:
        with open(path("manifest.json"), encoding="utf-8") as f:
            m = json.load(f)
    except (OSError, ValueError) as e:
        r.check("V1", "manifest_readable", False, "cannot read manifest.json: %s" % e)
        return r, None
    if not r.check("V1", "manifest_readable", m.get("manifest_version") == SUPPORTED_MANIFEST,
                   "manifest_version %r (this verifier reads %d)" % (m.get("manifest_version"), SUPPORTED_MANIFEST)):
        return r, m

    # V2: every listed file is present, with the recorded size and sha256.
    listed = {f["name"]: f for f in m.get("files", [])}
    bad = []
    for name, info in listed.items():
        if os.path.basename(name) != name:
            bad.append("%s is not a plain file name" % name)
            continue
        if not os.path.isfile(path(name)):
            bad.append("%s is missing" % name)
            continue
        size, digest = os.path.getsize(path(name)), sha256_file(path(name))
        if size != info.get("bytes") or digest != info.get("sha256"):
            bad.append("%s: %d bytes, sha256 %s; manifest says %s bytes, %s" % (name, size, digest[:12], info.get("bytes"), str(info.get("sha256"))[:12]))
    r.check("V2", "listed_files_intact", not bad, "; ".join(bad) or "%d files match size and sha256" % len(listed))

    # V3: nothing else is in the directory, so no unlisted file can be mistaken for data.
    extra = sorted(n for n in os.listdir(directory) if not n.startswith(".") and n != "manifest.json" and n not in listed)
    r.check("V3", "no_unlisted_files", not extra, "unlisted: " + ", ".join(extra) if extra else "only listed files and manifest.json")

    # V4: the definitions and query are the ones the manifest names.
    defs_ok = "fields.json" in listed and listed["fields.json"]["sha256"] == m.get("field_definitions", {}).get("sha256")
    query_name = m.get("query_file", "query.sql")
    query_ok = query_name in listed and listed[query_name]["sha256"] == m.get("query_sha256")
    r.check("V4", "definitions_and_query_identified", defs_ok and query_ok,
            "fields.json %s, %s %s" % ("matches" if defs_ok else "does not match", query_name, "matches" if query_ok else "does not match"))
    try:
        with open(path("fields.json"), encoding="utf-8") as f:
            definitions = json.load(f)
        status = {fd["name"]: fd["status"] for fd in definitions["fields"]}
    except (OSError, ValueError, KeyError) as e:
        r.check("V4", "definitions_readable", False, str(e))
        return r, m

    req = m.get("request", {})
    window, zone = m.get("window", {}), req.get("window", {}).get("timezone")

    # V5: the window's epochs are what its dates mean in its time zone.
    try:
        start = epoch_for(req["window"]["start"], zone)
        end = epoch_for(req["window"]["end"], zone)
        ok = (DATE.match(req["window"]["start"]) and DATE.match(req["window"]["end"])
              and start == window.get("start_epoch") and end == window.get("end_epoch") and end > start)
        r.check("V5", "window_epochs_recomputed", ok,
                "%s to %s in %s is [%d, %d); manifest has [%s, %s)" % (req["window"]["start"], req["window"]["end"], zone, start, end,
                                                                     window.get("start_epoch"), window.get("end_epoch")))
    except Exception as e:  # unknown zone, missing tz database, bad date
        r.check("V5", "window_epochs_recomputed", False, "could not recompute the window: %s" % e)

    # V6: the raw extraction is what the manifest claims.
    raw = m.get("raw", {})
    raw_rows = None
    if raw.get("state") == "complete":
        problems = []
        if not all(c.get("passed") for c in raw.get("checks", [])):
            problems.append("a raw check in the manifest did not pass")
        if raw.get("file") not in listed:
            problems.append("raw file not listed")
        else:
            try:
                raw_rows = sum(1 for _ in read_csv(path(raw["file"]), raw.get("columns")))
            except Exception as e:
                problems.append("raw file unreadable: %s" % e)
        if raw_rows is not None:
            counts = {"rows in file": raw_rows, "rows_written": raw.get("rows_written"),
                      "rows_expected": raw.get("rows_expected"), "count_after": raw.get("count_after"),
                      "listed rows": listed.get(raw.get("file"), {}).get("rows")}
            if len(set(counts.values())) != 1:
                problems.append("counts disagree: " + ", ".join("%s %s" % kv for kv in counts.items()))
        r.check("V6", "raw_complete_supported", not problems,
                "; ".join(problems) or "%d rows, header and every count agree" % raw_rows)
    else:
        consistent = raw.get("state") == "incomplete" and (
            raw.get("rows_written") != raw.get("rows_expected") or raw.get("count_after") != raw.get("rows_expected")
            or not all(c.get("passed") for c in raw.get("checks", [])))
        r.check("V6", "raw_incomplete_reported", consistent,
                "raw is %r: %s" % (raw.get("state"), raw.get("reason", "")))

    # V7: the normalization outcome is what the manifest claims, and every
    # normalized value re-derives from its raw row.
    norm = m.get("normalization", {})
    state = norm.get("state")
    files_present = {"normalized.csv.gz": "normalized.csv.gz" in listed, "validation.json": "validation.json" in listed}
    if state == "not_requested":
        r.check("V7", "normalization_not_requested", req.get("deliver") == "raw" and not files_present["normalized.csv.gz"],
                "deliver is %r; normalized file %s" % (req.get("deliver"), "present" if files_present["normalized.csv.gz"] else "absent"))
    elif state == "not_run":
        r.check("V7", "normalization_not_run", raw.get("state") != "complete" and not files_present["normalized.csv.gz"],
                "raw is %r; normalized file %s" % (raw.get("state"), "present" if files_present["normalized.csv.gz"] else "absent"))
    elif state == "failed_validation":
        failed = []
        if files_present["validation.json"]:
            with open(path("validation.json"), encoding="utf-8") as f:
                failed = [c for c in json.load(f).get("checks", []) if not c.get("passed")]
        r.check("V7", "normalization_failure_reported", failed and not files_present["normalized.csv.gz"],
                "%d failed checks recorded; normalized file %s" % (len(failed), "present" if files_present["normalized.csv.gz"] else "withheld"))
    elif state == "validated":
        problems = []
        if not all(c.get("passed") for c in norm.get("checks", [])):
            problems.append("a normalization check in the manifest did not pass")
        if not files_present["validation.json"]:
            problems.append("validation.json not listed")
        if norm.get("file") not in listed:
            problems.append("normalized file not listed")
        columns = norm.get("columns") or []
        if not problems:
            try:
                identity = "netid" if req.get("identity") == "netid" else "researcher_key"
                raw_iter = read_csv(path(raw["file"]), raw.get("columns"))
                n = 0
                for normalized in read_csv(path(norm["file"]), columns):
                    try:
                        source = next(raw_iter)
                    except StopIteration:
                        problems.append("normalized file has more rows than the raw file")
                        break
                    n += 1
                    expected = derive(dict(zip(raw.get("columns"), source)), columns, identity, zone)
                    for name, value in zip(columns, normalized):
                        if expected.get(name) != value:
                            problems.append("row %d (job %s): %s is %r, re-derived %r" % (n, source[0], name, value, expected.get(name)))
                            break
                    if len(problems) >= 5:
                        break
                else:
                    if next(raw_iter, None) is not None:
                        problems.append("raw file has more rows than the normalized file")
                if not problems and n != raw_rows:
                    problems.append("%d normalized rows, %s raw" % (n, raw_rows))
            except Exception as e:
                problems.append("could not re-derive: %s" % e)
        r.check("V7", "normalized_values_rederived", not problems,
                "; ".join(problems) or "every value in %d rows re-derived from its raw row" % (raw_rows or 0))
    else:
        r.check("V7", "normalization_state_known", False, "unknown normalization state %r" % state)

    # V8: fulfillment follows from the request and the two outcomes, and the
    # omitted fields are exactly the requested ones that are not recorded.
    requested = req.get("fields", [])
    unavailable = [f for f in requested if status.get(f) == "not_recorded"]
    listed_unavailable = [u.get("field") for u in m.get("unavailable_fields", [])]
    want = expected_fulfillment(req.get("deliver"), raw.get("state"), state, len(unavailable))
    claimed = m.get("fulfillment", {}).get("state")
    headers = set(raw.get("columns") or []) | set(norm.get("columns") or [])
    leaked = [f for f in unavailable if f in headers]
    r.check("V8", "fulfillment_consistent", claimed == want and sorted(unavailable) == sorted(listed_unavailable) and not leaked,
            "claimed %r, recomputed %r; unavailable %s, listed %s%s" % (claimed, want, unavailable, listed_unavailable,
                                                                      "; unavailable columns present: %s" % leaked if leaked else ""))
    return r, m


def main(argv):
    as_json = "--json" in argv
    args = [a for a in argv if a != "--json"]
    if len(args) != 1 or not os.path.isdir(args[0]):
        print(__doc__, file=sys.stderr)
        return 2
    report, m = verify(args[0])
    m = m or {}
    verdict = {
        "verified": report.ok,
        "raw": m.get("raw", {}).get("state"),
        "normalization": m.get("normalization", {}).get("state"),
        "fulfillment": m.get("fulfillment", {}).get("state"),
        "export_id": m.get("export_id"),
        "as_of": m.get("as_of"),
    }
    code = 1 if not report.ok else (0 if verdict["fulfillment"] == "fulfilled" else 3)
    verdict["exit"] = code
    if as_json:
        print(json.dumps({"checks": report.results, "verdict": verdict}, indent=2))
    else:
        for c in report.results:
            print("%s %s %s: %s" % ("PASS" if c["passed"] else "FAIL", c["id"], c["name"], c["detail"]))
        print("VERDICT " + json.dumps(verdict))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
