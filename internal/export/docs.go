package export

import (
	"fmt"
	"strings"
)

// FieldsMarkdown renders the definitions for people. It is generated from
// fields.json, never edited, so the two cannot disagree.
func FieldsMarkdown(d *Definitions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Pegasus export fields (definitions %s)\n\n", d.Version)
	fmt.Fprintf(&b, "Generated from `%s` (sha256 `%s`). Source: `%s.%s`, defined by `%s`; rows are selected by `%s` "+
		"in `[start, end)`.\n\n", FieldsFile, d.SHA256(), d.Source.Database, d.Source.Relation, d.Source.Definition, d.Source.TimeColumn)
	fmt.Fprintf(&b, "In both CSV files, `%s` is SQL NULL and an empty field is an empty string. They mean different things here: "+
		"an empty `TRESReq_gres_gpu` on a recorded job is no GPU; a null one is unknown.\n\n", d.NullMarker)
	b.WriteString("## Fields\n\n| Field | Status | Sources | Unit | Rule |\n| --- | --- | --- | --- | --- |\n")
	for _, f := range d.Fields {
		rule := f.Rule
		if f.Status == StatusNotRecorded {
			rule = "**Not recorded.** " + f.Reason
		}
		if len(f.Assumptions) > 0 {
			rule += " Assumptions: " + strings.Join(f.Assumptions, ", ") + "."
		}
		sources := "`" + strings.Join(f.Sources, "`, `") + "`"
		if len(f.Sources) == 0 {
			sources = "—"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", f.Name, f.Status, sources, orDash(f.Unit), strings.ReplaceAll(rule, "|", "\\|"))
	}
	b.WriteString("\n## Assumptions\n\n")
	for _, a := range d.Assumptions {
		fmt.Fprintf(&b, "- **%s** (%s): %s\n", a.Name, strings.Join(a.Fields, ", "), a.Statement)
	}
	b.WriteString("\n## Quality flags\n\n")
	for _, name := range d.sortedFlags() {
		fmt.Fprintf(&b, "- `%s`: %s\n", name, d.Flags[name])
	}
	b.WriteString("\n## Raw file\n\n`" + RawFile + "` holds the source columns the requested fields come from, verbatim, " +
		"one row per job submitted in the window, ordered by `SubmitTime, JobID`. The one exception is identity: with " +
		"`identity: pseudonymous` the `netid` column is replaced by `researcher_key`, computed as described above.\n")
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// VerifierMarkdown states exactly what verify_export.py guarantees, and what
// it cannot. It ships in every export.
const VerifierMarkdown = `# What the verifier checks

Run ` + "`python3 verify_export.py <export-directory>`" + ` (Python 3.9 or later, standard library
only). It is a separate implementation, in Python, of the rules the exporter
applies in Go; it shares no code with the exporter.

## Three outcomes, reported separately

| Outcome | Values | Question it answers |
| --- | --- | --- |
| ` + "`raw`" + ` | complete, incomplete | Was every job submitted in the window extracted, verbatim, and written intact? |
| ` + "`normalization`" + ` | validated, failed_validation, not_requested, not_run | Were the logical fields derived and did every validation check pass? A normalized file is shipped only when validated. |
| ` + "`fulfillment`" + ` | fulfilled, partially_fulfilled, not_fulfilled | Do the delivered files answer the request as it was asked? |

Fulfillment follows from the other two and the request: not fulfilled if the
raw extraction is incomplete, or if normalized data was asked for and
normalization is not validated; partially fulfilled if every deliverable field
was delivered but requested fields that are not recorded were omitted (only
possible with ` + "`allow_unavailable: true`" + `); fulfilled otherwise.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every check passed **and** the request was fulfilled. The only code that means "done as asked". |
| 3 | Every check passed, and the manifest truthfully says the request was partially fulfilled or not fulfilled. Report the fulfillment state and its reason. |
| 1 | A check failed: the files do not support what the manifest claims. Nothing in the directory should be used. |
| 2 | Usage error. |

The last line of output is ` + "`VERDICT {...}`" + ` with ` + "`verified`" + `, the three outcomes, the export id,
the as-of time and the exit code. ` + "`--json`" + ` prints every check and the verdict as JSON.

## The checks

| ID | Check | Guarantee when it passes |
| --- | --- | --- |
| V1 | manifest_readable | manifest.json exists, parses, and has a manifest version this verifier understands. |
| V2 | listed_files_intact | Every file the manifest lists is present with exactly the recorded size and sha256. |
| V3 | no_unlisted_files | The directory holds nothing else (dotfiles aside), so no unlisted file can be taken for data. |
| V4 | definitions_and_query_identified | fields.json and query.sql are the exact files the manifest names by sha256. |
| V5 | window_epochs_recomputed | The window's epochs are what its dates mean at midnight in its time zone, recomputed here; end is after start. This is the check that catches a window a year or a time zone off. |
| V6 | raw_complete_supported | (raw complete) Every raw check in the manifest passed; the raw file decompresses fully; its header is the listed columns; every row has that many fields; and the rows in the file, rows_written, rows_expected, count_after and the listed row count are all equal. |
| V6 | raw_incomplete_reported | (raw incomplete) The manifest's own counts or checks show why. |
| V7 | normalized_values_rederived | (normalization validated) Every normalization check in the manifest passed; validation.json is present; and every value in every normalized row equals what this verifier re-derives from the matching raw row: array ids, identity, account, submit epoch, local time and month in the request's zone, partition, state, CPUs, nodes, GPUs, memory raw and bytes, wall time raw and seconds, and the quality flags. |
| V7 | normalization_failure_reported | (failed_validation) validation.json records at least one failed check, and no normalized file is shipped. |
| V7 | normalization_not_requested / not_run | No normalized file is shipped, and the reason (raw delivery requested, or raw incomplete) holds. |
| V8 | fulfillment_consistent | The claimed fulfillment equals the one recomputed from the request and the two outcomes; the omitted fields are exactly the requested fields fields.json marks not recorded; and no omitted field appears as a column. |

## What is not checked

The verifier reads only the directory. It cannot establish:

- **That the rows match the database.** It has no database access. Completeness
  rests on the exporter's counts, taken in the same snapshot before and after
  reading (V6 checks they agree; it cannot re-count).
- **That the snapshot was consistent.** The manifest's ` + "`source.snapshot`" + ` and
  ` + "`source.engine`" + ` say whether the database guaranteed it.
- **That the assumptions are true.** It checks that memory bytes follow the
  declared rule and that the manifest names the assumptions; whether Pegasus's
  Slurm records memory as the job's total in powers of 1024 is not something
  the files can show.
- **That the field definitions describe reality.** It checks the data against
  the definitions, not the definitions against the scheduler.
- **The pseudonymous key.** Without the salt it cannot recompute
  ` + "`researcher_key`" + `; it checks the normalized key equals the raw file's.
- **Who asked for the export, or whether they were allowed to.** That is in the
  server's audit log.
- **Jobs ingested after ` + "`as_of`" + `.** A later export of the same window can hold more.
`
