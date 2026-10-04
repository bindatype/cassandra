---
name: zabbix-triage-report
description: "Zabbix alert triage: summary + detail report via Cassandra."
version: 1.0.0
author: Glen Maclachlan + Hermes Agent
platforms: [linux]
metadata:
  hermes:
    tags: [zabbix, alerts, triage, monitoring, report]
    category: infrastructure
    related_skills: [askcass-infrastructure-analysis]
---

# Zabbix Triage Report Skill

Writes a two-part Zabbix alert triage report for a time window:
- **an executive summary**, for reading in a minute;
- **a linked detail report** the team can act on: alerts grouped by
  category, per-host and per-day counts, the thresholds from event names,
  whether accounting jobs were running on the alerting hosts, and
  recommended actions per category.

All figures come from a helper script that queries Cassandra's broker
directly and gets JSON back. You write the words; you never type a number
yourself.

## When to Use

"Triage the Zabbix alerts", "why so many alerts overnight", "alert noise
report", "what should we do about these alerts", or a weekly alert review.

## Prerequisites

- `askcass` works for this account (`askcass "how many agents are disconnected right now?"`).
- `go` on PATH: the script builds `cass-broker-plan` and `cass-broker-exec`
  from the same checkout `askcass` uses.

## How to Run

1. Pick the window in **UTC**, whole days. The default is the last 7 complete
   days, ending yesterday.
2. Run the helper through `terminal`. It takes several minutes and makes
   hundreds of broker calls; let it finish.
   ```
   python3 ~/.hermes/skills/infrastructure/zabbix-triage-report/scripts/triage_data.py \
     --since 2026-09-23 --until 2026-09-30 --out ~/reports/zabbix-triage-2026-09-30
   ```
   To give a recurring pattern its own category, add
   `--category "Label=name substring"`. Add `:jobs` (as in
   `"Label=name substring:jobs"`) to check accounting jobs on its hosts too.
3. `read_file` `<out>.json`. It holds every figure, with per-day,
   overnight, per-host and job-overlap detail.

## Procedure

**A. Finish the detail report** (`<out>-detail.md`). The script has already
written its tables. Under each category there is a marker line,
`<!-- ACTIONS: <category> -->`. Replace **only the marker** with `patch`,
writing 2–5 concrete actions. Never edit a table. Each action should:
- name the hosts, using bracket ranges where it reads well (`gh200-[02,03,05-07]`);
- quote the threshold from the event names, e.g. "warning at 90 %, critical at 98 %";
- say when, using the overnight and per-day rows;
- use the job-overlap table. If jobs were running on the alerting hosts, the
  alerts may be expected load; say which users and partitions. Recommend
  re-tuning only if they weren't;
- name what Cassandra cannot see and who should check it: node logs and
  `nvidia-smi` process lists on GPU nodes, the subnet manager or switch logs
  for IB, sensor history for temperature probes.

**B. Write the summary** (`<out>-summary.md`), with these four sections:
1. **Alert Volume & Distribution.** The total and the category table, with
   figures copied exactly from the JSON.
2. **Observations & Hypotheses.** For each large category: what happened,
   on which hosts, and a hypothesis consistent with the detail data.
3. **Recommended Follow-up Investigation.** The key actions in brief, plus
   the link `[Detailed report](zabbix-triage-<date>-detail.md)`.
4. **Operational Impact.**

**C.** Tell the user both file paths.

## Pitfalls

- **Don't type a figure the JSON doesn't contain, and don't compute one.**
  Copy it exactly. Model-written tables and totals have produced wrong owner
  names and wrong job counts here.
- **"No jobs were running" is a claim, so check it.** Say it only if
  `jobs_on_hosts` shows 0 for that host. The 2026-09-29 report said no jobs
  ran overnight on the GH200 nodes, because its query asked which jobs
  *started* between 00:00 and 06:00. Multi-day jobs were running through
  every one of those nights. The script checks overlap, which is the right
  test.
- **Host counts can be lower bounds.** When `host_counts_exact` is false,
  write "at least".
- **Uncategorized patterns come from a sample.** Their counts are sample
  frequencies, not totals. To count a pattern exactly, rerun with a
  `--category` for it, rather than estimating.
- **Name every alerting host.** The 2026-09-29 report listed three GH200
  nodes and missed gh200-05, the second busiest. Take hosts from the table.
- **A flat rate is a schedule, not an event.** If a category's count is
  almost the same every day, and overnight is about a quarter of each day, a
  check is firing on a timer. Look at the monitoring configuration, not for an
  overnight cause. On 2026-09-23 to 2026-09-30, "IB link gone" was 10,032 a
  day, every day, split evenly between master1 and master2, which suggests
  both report the same fabric.
- **Times are UTC.** Say so whenever you mention a time.
- **Don't use `askcass` for this report's figures.** It answers in prose. It
  is fine for follow-up questions, such as about one host.

## Verification

For 2026-09-23 to 2026-09-30, the GPU utilization category held 3,491 events
on 8 hosts: gh200-07 1,021, gh200-05 913, 01-junghunc 504, gh200-03 378,
gh200-06 326, gh200-02 306, viz002 34, rtsgh02 9. Jobs in `superChip` were
running on every GH200 node with alerts.
