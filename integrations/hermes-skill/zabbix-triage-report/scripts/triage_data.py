#!/usr/bin/env python3
"""Collect exact Zabbix alert figures for a triage report, through Cassandra's broker.

    triage_data.py --since 2026-09-23 --until 2026-09-30 --out ~/reports/zabbix-triage-2026-09-30

Writes <out>.json (every figure, with provenance) and <out>-detail.md (the
detail report's tables, with one marked place per category for recommended
actions). No language model is involved: route requests go to
cass-broker-plan and cass-broker-exec, which return Cassandra's evidence as
JSON, and every count below is Zabbix's or the accounting database's own.

Why not askcass: askcass answers in prose, and a model retyping a large table
is where a one-letter slip became a wrong ticket owner (2026-10-01). Counts
taken from JSON cannot be mistyped.
"""
import argparse, collections, datetime as dt, json, os, re, shutil, subprocess, sys

UTC = dt.timezone.utc
EXACT_HOST_ROWS = 5000   # Cassandra's host census is exact up to this many rows per window
MAX_NAMED_HOSTS = 25     # ...and names at most this many hosts
MIN_WINDOW = dt.timedelta(hours=1)

DEFAULT_CATEGORIES = [
    # label, Zabbix name substring (case-insensitive), check jobs on affected hosts
    ("IB spine link down", "IB spine link", False),
    ("IB link gone", "link gone", False),
    ("Interface link down", "Link down", False),
    ("Interface high bandwidth", "High bandwidth usage", False),
    ("GPU utilization", "GPU utilization", True),
    ("ollama.service not running", "ollama.service", False),
    ("Disk request latency", "request responses are too high", False),
    ("System Board Inlet Temp", "System Board Inlet Temp", False),
]


class Cass:
    """Runs route requests through the broker binaries with the user's own environment."""

    def __init__(self, repo, env_file, policy):
        self.repo, self.env_file, self.policy = repo, env_file, policy
        self.calls = 0
        for tool in ("cass-broker-plan", "cass-broker-exec"):
            subprocess.run(["go", "build", "-o", os.path.join(repo, "runtime", tool), "./cmd/" + tool],
                           cwd=repo, check=True)

    def _run(self, tool, stdin, extra=()):
        script = 'set -a; . "$1"; set +a; shift; exec "$@"'
        cmd = ["bash", "-c", script, "_", self.env_file, os.path.join(self.repo, "runtime", tool),
               "-policy", self.policy, *extra]
        return subprocess.run(cmd, input=stdin, capture_output=True, text=True)

    def evidence(self, request):
        self.calls += 1
        plan = self._run("cass-broker-plan", json.dumps(request))
        if plan.returncode != 0:
            raise RuntimeError("plan refused: " + plan.stderr.strip())
        out = self._run("cass-broker-exec", plan.stdout, ("-timeout", "240s"))
        if out.returncode != 0:
            raise RuntimeError(out.stderr.strip())
        return json.loads(out.stdout)["evidence"][0]


def iso(t):
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def day_windows(since, until):
    t = since
    while t < until:
        end = min(until, (t + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0))
        yield t, end
        t = end


def history(cass, since, until, match=None, limit=1):
    request = {"intent": "monitoring.history", "state": "problem", "since": iso(since), "until": iso(until),
               "limit": limit}
    if match:
        request["match"] = match
    return cass.evidence(request)


def exact_window(cass, since, until, match, log):
    """Total and per-host counts for one window, split until the host census is exact.

    Returns (total, {host: count}, host_counts_exact). Totals are always exact;
    per-host counts are exact only when each final window held at most
    EXACT_HOST_ROWS rows and MAX_NAMED_HOSTS hosts.
    """
    try:
        e = history(cass, since, until, match)
    except RuntimeError as err:
        if "deadline" not in str(err) and "Timeout" not in str(err):
            raise
        if until - since <= MIN_WINDOW:
            raise RuntimeError("window %s..%s still times out at %s: %s" % (iso(since), iso(until), MIN_WINDOW, err))
        log("timeout on %s..%s, splitting" % (iso(since), iso(until)))
        return merge(cass, since, until, match, log)
    total = e["summary"].get("total_matching", 0)
    hosts = (e.get("breakdown") or {}).get("events_by_host", {}) or {}
    warnings = " ".join(e.get("warnings") or [])
    rows_capped = "cover the most recent" in warnings   # splitting fixes this
    names_capped = "names only" in warnings             # splitting may not; mark it instead
    if rows_capped and until - since > MIN_WINDOW:
        return merge(cass, since, until, match, log)
    return total, dict(hosts), not (rows_capped or names_capped)


def window_total(cass, since, until, match=None):
    """Exact count only, splitting on timeouts but never for the host census."""
    try:
        return history(cass, since, until, match)["summary"].get("total_matching", 0)
    except RuntimeError as err:
        if ("deadline" not in str(err) and "Timeout" not in str(err)) or until - since <= MIN_WINDOW:
            raise
        mid = since + (until - since) / 2
        return window_total(cass, since, mid, match) + window_total(cass, mid, until, match)


def merge(cass, since, until, match, log):
    mid = since + (until - since) / 2
    t1, h1, x1 = exact_window(cass, since, mid, match, log)
    t2, h2, x2 = exact_window(cass, mid, until, match, log)
    hosts = collections.Counter(h1)
    hosts.update(h2)
    return t1 + t2, dict(hosts), x1 and x2


def is_timeout(err):
    return "deadline" in str(err) or "Timeout" in str(err)


def sample_items(cass, windows, match=None):
    """Newest 200 events from the newest window that answers in time."""
    for since, until in reversed(windows):
        try:
            return history(cass, since, until, match, limit=200).get("items", [])
        except RuntimeError as err:
            if not is_timeout(err):
                raise
    return []


def readable(name):
    """One trigger pattern per line: drop per-device ids and the measured value, keep the threshold."""
    name = re.sub(r"\[GPU-[0-9a-f-]+\]", "[GPU]", name)
    name = re.sub(r"\((\d+(\.\d+)?) ?%\) exceeded", "(N %) exceeded", name)
    return name


def jobs_on_hosts(cass, hosts, since, until):
    """Accounting jobs that were running on each host at any point in the window.

    Overlap, not start time: a multi-day job that started before the window and
    ran through it is running during it. The 2026-09-29 report missed every
    GH200 job by asking which jobs had started inside 00:00-06:00.
    """
    s, u = int(since.timestamp()), int(until.timestamp())
    result = {}
    for host in hosts:
        short = host.split(".")[0]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", short):
            continue
        query = ("SELECT JobID, netid, `partition`, StartTime, EndTime, State FROM runTBL2 "
                 "WHERE NodeList LIKE '%%%s%%' AND StartTime > 0 AND StartTime < %d "
                 "AND (EndTime = 0 OR EndTime > %d) ORDER BY StartTime" % (short, u, s))
        e = cass.evidence({"intent": "database.query", "query": query})
        rows = [i.get("fields", {}) for i in e.get("items", [])]
        result[host] = {"jobs": len(rows), "truncated": bool(e.get("truncated")),
                        "users": sorted({r.get("netid", "") for r in rows} - {""}),
                        "partitions": sorted({r.get("partition", "") for r in rows} - {""}),
                        "rows": rows}
    return result


def overnight_coverage(rows, since, until, start_hour, end_hour):
    """Per night: was any job running during start_hour..end_hour UTC on that host."""
    nights = {}
    day = since.replace(hour=0, minute=0, second=0)
    while day < until:
        a, b = day + dt.timedelta(hours=start_hour), day + dt.timedelta(hours=end_hour)
        running = [r for r in rows if int(r.get("StartTime") or 0) < b.timestamp()
                   and (int(r.get("EndTime") or 0) == 0 or int(r.get("EndTime")) > a.timestamp())]
        nights[day.strftime("%Y-%m-%d")] = len(running)
        day += dt.timedelta(days=1)
    return nights


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", required=True, help="UTC date or RFC 3339, inclusive")
    ap.add_argument("--until", required=True, help="UTC date or RFC 3339, exclusive")
    ap.add_argument("--out", required=True, help="output path prefix, e.g. ~/reports/zabbix-triage-2026-09-30")
    ap.add_argument("--category", action="append", default=[],
                    help='extra category "Label=match" or "Label=match:jobs"; repeatable')
    ap.add_argument("--overnight", default="0-6", help="overnight hours UTC, e.g. 0-6")
    ap.add_argument("--repo", default=os.environ.get("CASS_REPO", ""))
    args = ap.parse_args()

    def when(text):
        t = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=UTC)

    since, until = when(args.since), when(args.until)
    o_start, o_end = (int(x) for x in args.overnight.split("-"))
    repo = args.repo
    if not repo:
        askcass = shutil.which("askcass")
        repo = os.path.dirname(os.path.dirname(os.path.realpath(askcass))) if askcass else ""
    if not repo or not os.path.isdir(os.path.join(repo, "cmd")):
        sys.exit("cannot find the Cassandra checkout: put askcass on PATH or pass --repo")
    env_file = os.path.expanduser("~/.config/cass/env")
    policy = os.path.expanduser("~/.config/cass/policy.json")
    if not os.path.exists(policy):
        policy = os.path.join(repo, "configs", "broker-policy.example.json")

    categories = list(DEFAULT_CATEGORIES)
    for spec in args.category:
        label, _, rest = spec.partition("=")
        match, _, flag = rest.partition(":")
        categories.append((label, match, flag == "jobs"))

    log = lambda msg: print("  " + msg, file=sys.stderr, flush=True)
    cass = Cass(repo, env_file, policy)
    days = list(day_windows(since, until))

    print("total problem events...", file=sys.stderr, flush=True)
    grand_by_day = {d.strftime("%Y-%m-%d"): window_total(cass, d, e) for d, e in days}
    grand_total = sum(grand_by_day.values())

    data = {"window": {"since": iso(since), "until": iso(until), "overnight_utc": args.overnight},
            "generated": iso(dt.datetime.now(UTC)), "source": "Cassandra broker (cass-broker-plan | cass-broker-exec)",
            "total_problem_events": grand_total, "total_by_day": grand_by_day, "categories": []}

    for label, match, check_jobs in categories:
        print("category: %s" % label, file=sys.stderr, flush=True)
        total, hosts, exact = 0, collections.Counter(), True
        by_day, overnight = {}, {}
        for d, e in days:
            t, h, x = exact_window(cass, d, e, match, log)
            day = d.strftime("%Y-%m-%d")
            by_day[day] = t
            total += t
            hosts.update(h)
            exact = exact and x
            a, b = d.replace(hour=o_start), d.replace(hour=0) + dt.timedelta(hours=o_end)
            if a < e:
                overnight[day] = window_total(cass, a, min(b, e), match)
        sample = sample_items(cass, days, match)
        names = collections.Counter(readable(i.get("description", "")) for i in sample)
        severities = collections.Counter(i.get("severity", "") for i in sample)
        entry = {"label": label, "match": match, "total": total,
                 "share_of_all": round(100.0 * total / grand_total, 1) if grand_total else 0.0,
                 "by_day": by_day, "overnight_by_day": overnight,
                 "hosts": dict(hosts.most_common()), "hosts_affected": len(hosts), "host_counts_exact": exact,
                 "example_names": names.most_common(5),
                 "severity_in_newest_200": dict(severities), "examples_from_newest_day_that_answered": True}
        if check_jobs and hosts:
            print("  jobs on %d hosts" % len(hosts), file=sys.stderr, flush=True)
            jobs = jobs_on_hosts(cass, list(hosts), since, until)
            for host, j in jobs.items():
                j["running_overnight_by_day"] = overnight_coverage(j["rows"], since, until, o_start, o_end)
                j["rows"] = j["rows"][:50]
            entry["jobs_on_hosts"] = jobs
        data["categories"].append(entry)

    covered = sum(c["total"] for c in data["categories"])
    data["uncategorized"] = {"total": grand_total - covered,
                             "share_of_all": round(100.0 * (grand_total - covered) / grand_total, 1) if grand_total else 0.0}
    print("sampling uncategorized names...", file=sys.stderr, flush=True)
    matches = [m.lower() for _, m, _ in categories]
    other = collections.Counter()
    sampled, skipped = 0, 0
    for d, e in days:
        for half in (d, d + (e - d) / 2):
            try:
                items = history(cass, half, min(half + (e - d) / 2, e), limit=200).get("items", [])
            except RuntimeError as err:
                if not is_timeout(err):
                    raise
                skipped += 1
                continue
            sampled += len(items)
            for i in items:
                name = i.get("description", "")
                if not any(m in name.lower() for m in matches):
                    other[readable(name)] += 1
    data["uncategorized"]["sampled_rows"] = sampled
    data["uncategorized"]["sample_windows_timed_out"] = skipped
    data["uncategorized"]["top_patterns_in_sample"] = other.most_common(15)
    data["broker_calls"] = cass.calls

    out = os.path.expanduser(args.out)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out + ".json", "w") as fh:
        json.dump(data, fh, indent=2)
    with open(out + "-detail.md", "w") as fh:
        fh.write(render_detail(data))
    print("wrote %s.json and %s-detail.md (%d broker calls)" % (out, out, cass.calls), file=sys.stderr)


def render_detail(d):
    w = d["window"]
    days = list(d["total_by_day"])
    lines = ["# Zabbix alert triage: detail report", "",
             "Window: %s to %s (UTC). Overnight means %s UTC. Generated %s from %s." % (
                 w["since"], w["until"], w["overnight_utc"].replace("-", ":00-") + ":00", d["generated"], d["source"]),
             "Every figure below is a count returned by Zabbix or the accounting database; none was typed by a model.", "",
             "## All problem events", "", "Total: **%s**" % format(d["total_problem_events"], ","), "",
             "| Day | " + " | ".join(days) + " |", "|---|" + "---|" * len(days),
             "| Events | " + " | ".join(format(v, ",") for v in d["total_by_day"].values()) + " |", "",
             "## By category", "", "| Category | Events | Share | Hosts affected |", "|---|---:|---:|---:|"]
    for c in d["categories"]:
        lines.append("| %s | %s | %.1f%% | %s%s |" % (c["label"], format(c["total"], ","), c["share_of_all"],
                                                    c["hosts_affected"], "" if c["host_counts_exact"] else " (at least)"))
    u = d["uncategorized"]
    lines += ["| Uncategorized | %s | %.1f%% | |" % (format(u["total"], ","), u["share_of_all"]), ""]
    for c in d["categories"]:
        if not c["total"]:
            continue
        lines += ["## %s" % c["label"], "",
                  "Zabbix event names containing \"%s\". **%s** events, %.1f%% of all." % (
                      c["match"], format(c["total"], ","), c["share_of_all"]), "",
                  "| Day | " + " | ".join(c["by_day"]) + " |", "|---|" + "---|" * len(c["by_day"]),
                  "| All day | " + " | ".join(format(v, ",") for v in c["by_day"].values()) + " |",
                  "| Overnight | " + " | ".join(format(c["overnight_by_day"].get(k, 0), ",") for k in c["by_day"]) + " |", "",
                  "Hosts" + ("" if c["host_counts_exact"] else " (counts are lower bounds: some windows exceeded the census limit)") + ":", "",
                  "| Host | Events |", "|---|---:|"]
        lines += ["| %s | %s |" % (h, format(n, ",")) for h, n in list(c["hosts"].items())[:30]]
        if len(c["hosts"]) > 30:
            lines.append("| (%d more hosts) | |" % (len(c["hosts"]) - 30))
        lines += ["", "Event names seen (newest 200, per-device ids and measured values removed):", ""]
        lines += ["- `%s` (%d)" % (n, k) for n, k in c["example_names"]]
        jobs = c.get("jobs_on_hosts")
        if jobs:
            lines += ["", "Accounting jobs running on these hosts during the window (overlap, not start time):", "",
                      "| Host | Jobs | Users | Partitions | Nights with a job running overnight |", "|---|---:|---|---|---|"]
            for h, j in jobs.items():
                nights = j["running_overnight_by_day"]
                lines.append("| %s | %d%s | %s | %s | %d of %d |" % (
                    h, j["jobs"], "+" if j["truncated"] else "", ", ".join(j["users"]) or "-",
                    ", ".join(j["partitions"]) or "-", sum(1 for v in nights.values() if v), len(nights)))
        lines += ["", "### Recommended actions", "", "<!-- ACTIONS: %s -->" % c["label"], ""]
    lines += ["## Uncategorized", "", "**%s** events (%.1f%%) match none of the categories above. "
              "Most common names among %d sampled rows (sample counts, not totals; give a pattern a "
              "category to count it exactly):" % (format(u["total"], ","), u["share_of_all"], u["sampled_rows"]), ""]
    lines += ["- `%s` (%d in sample)" % (n, k) for n, k in u["top_patterns_in_sample"]]
    lines += ["", "### Recommended actions", "", "<!-- ACTIONS: Uncategorized -->", ""]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
