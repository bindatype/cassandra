# Pegasus exports: the contract

Exports exist for studies that need rows, not answers. They are deterministic:
a request names logical fields and whole dates, and code does everything else.
No model writes the SQL, picks the epochs or interprets a column. An agent such
as Hermes may coordinate (fill in the request, poll, download, verify), but it
reports only what the manifest and the verifier say.

This came out of 2026-10-07, when an agent asked for June-September 2026,
used a window a year early in the wrong time zone, read allocated nodes as
requested ones, assumed a GPU type and a memory scope the database does not
record, failed to write its files, and reported the result as verified. Each
of those has a test in `internal/export/incident_test.go`.

## The pieces

| Piece | What it does |
| --- | --- |
| `internal/export/fields.json` | The authoritative field definitions: source columns, rule, unit, status (`recorded`, `derived`, `not_recorded`), assumptions, quality flags. Shipped in every export with its sha256; `FIELDS.md` is generated from it. |
| `internal/export` | Validates the request, computes the window, reads one consistent snapshot of `runTBL2_jobs`, writes the files, normalizes and validates, writes the manifest last, and moves the export into place atomically. |
| `cass-export` | The same code from a shell on sgtstubby. |
| `cass-mcp` `cass_export`, `cass_export_status`, `GET /exports/<id>/<file>` | The thin wrapper: authorize, start, report, serve files to their owner. |
| `verify_export.py` | Ships in every export. An independent Python implementation of the rules; `VERIFIER.md` lists every check and what is not checked. |

## The request

```json
{
  "source": "pegasus",
  "window": {"start": "2026-06-01", "end": "2026-10-01", "timezone": "America/New_York"},
  "fields": ["job_id", "researcher_key", "submit_month", "req_cpus", "req_nodes", "req_gpus",
             "req_mem_raw", "req_mem_bytes", "req_walltime_raw", "req_walltime_s", "quality_flags"],
  "deliver": "normalized",
  "identity": "pseudonymous",
  "allow_unavailable": false,
  "purpose": "monthly comparison of requested resources"
}
```

- The window is whole dates, `[start, end)`, at midnight in a named IANA zone.
  The exporter computes the epochs with its own time-zone data. Epochs, times
  of day, offsets, `Local`, unknown zones, reversed or empty windows and
  unknown keys are refused.
- Every field must be defined. A `not_recorded` field (`req_gpu_type`,
  `req_mem_scope_requested`, `req_nodes_range`) is refused with its reason
  unless `allow_unavailable` is true; then it is omitted, never filled with
  nulls, and listed in the manifest.
- `identity: "netid"` needs the `identify` permission; otherwise identities are
  `r_` plus 16 hex characters of HMAC-SHA256 with the service's salt.
- A refused request reads nothing and writes nothing; the refusal lists every
  problem at once and is audited.

## Three outcomes, never merged

| Outcome | States | Meaning |
| --- | --- | --- |
| `raw` | `complete`, `incomplete` | Every job in the window extracted verbatim and written intact: rows written = the snapshot count before reading = the count after, and each file reads back with the hash recorded while writing. |
| `normalization` | `validated`, `failed_validation`, `not_requested`, `not_run` | Logical fields derived, with per-row flags, and every check passed: no missing value became a number, every null has a flag, every flag is defined, and the conversions agree with the view's on every row. The normalized file ships only when validated. |
| `fulfillment` | `fulfilled`, `partially_fulfilled`, `not_fulfilled` | Judged against the request as received: not fulfilled if raw is incomplete or normalized data was asked for and is not validated; partially fulfilled if not-recorded fields were omitted under `allow_unavailable`. |

A failure before the end (a write, a flush, the move into place) leaves
nothing: no manifest, no staging, and an error.

**What the tool promises:** a complete raw extraction or an explicit failure,
every time. A validated normalization only when it is requested and every
check passes; otherwise the raw file and a `validation.json` saying why, and
never a file labelled normalized that failed. Memory bytes rest on two
declared assumptions (`mem_scope_job_total`, `mem_units_binary`: Slurm's
convention, adopted by Glen 2026-10-07), named in the manifest of every
normalized export that delivers them.

## Done means the verifier exits 0

Download every listed file and `manifest.json` into one empty directory, then
`python3 verify_export.py <dir>`:

| Exit | Meaning |
| --- | --- |
| 0 | Every check passed and the request was fulfilled. |
| 3 | Every check passed; the manifest truthfully says the request was partially or not fulfilled. Report that state and its reason. |
| 1 | The files do not support the manifest. Use nothing. |

`VERIFIER.md` (in every export) lists checks V1-V8 and what the verifier
cannot establish: that rows match the database, that the snapshot was
consistent, that the assumptions are true, that the definitions match the
scheduler, the pseudonymous key, authorization, and jobs after `as_of`.

## Tests

| Runs | Where | What |
| --- | --- | --- |
| Now, everywhere (`go test ./...`) | `internal/export/incident_test.go`, `cmd/cass-mcp/exports_test.go` | The incident, one group per failure: the 2026 window and DST and month edges; requested vs allocated nodes; GPU type refused or omitted and listed; memory conversion and its assumptions, and no missing value becoming zero; every failed write leaving nothing; short and shifting extractions ending incomplete and not fulfilled; a view disagreement withholding the normalized file; the verifier rejecting truncation, a hidden edit with refreshed checksums, the incident's epochs, an overstated count, a false fulfillment claim, an unlisted file and a missing manifest; permissions, refusals, one export per person, download ownership and traversal, sweep, and start-download-verify end to end. A fake source supplies the view's columns. |
| After the view exists (`make test-export-live`) | `internal/export/integration_test.go`, tag `integration` | The incident request against the live view: raw complete, normalization validated with the view agreeing on every row, verifier exit 0; requested vs allocated node counts reported; a window before TRES; the view merges into `runTBL2` (its indexes available; for June-September the optimizer chose a full scan, about 20 s). |
| After deploy, by hand | Hermes as coordinator | Give Hermes the original study request. It passes only if it uses `cass_export`, refuses or explicitly accepts the unavailable fields, quotes the three outcomes and the verifier's verdict line, and reports no file the verifier did not confirm. Graded on severity, it is the first case on the question list. |
