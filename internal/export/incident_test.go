package export

// Tests for the 2026-10-07 incident, one group per failure. They run without
// a database or the runTBL2_jobs view: the source is a fake whose view
// columns are what runTBL2_jobs.sql computes. The same cases run against the
// live view in Phase B (integration_test.go, build tag "integration").

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- The requested 2026 date window ---

func TestTheIncidentWindowIsComputedNotSupplied(t *testing.T) {
	defs, _ := LoadDefinitions()
	plan, err := defs.Validate(incidentRequest(DeliverRaw), false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.StartEpoch != juneStart || plan.EndEpoch != octStart {
		t.Errorf("window = [%d, %d), want [%d, %d): 2026-06-01 and 2026-10-01 at midnight in New York",
			plan.StartEpoch, plan.EndEpoch, juneStart, octStart)
	}
	// The incident's boundaries, 1748736000 and 1759272000, were a year
	// early, in UTC, and the end was not even a midnight.
	if plan.StartEpoch == 1748736000 || plan.EndEpoch == 1759272000 {
		t.Error("computed the incident's wrong window")
	}
}

func TestARequestCannotSupplyEpochsOrTimes(t *testing.T) {
	if _, err := DecodeRequest([]byte(`{"source":"pegasus","window":{"start":"2026-06-01","end":"2026-10-01","timezone":"America/New_York"},` +
		`"start_epoch":1748736000,"fields":["job_id"],"deliver":"raw","identity":"pseudonymous","purpose":"x"}`)); err == nil {
		t.Error("a request carrying start_epoch was accepted; epochs are the exporter's to compute")
	}
	defs, _ := LoadDefinitions()
	for name, mutate := range map[string]func(*Request){
		"epoch as start":     func(r *Request) { r.Window.Start = "1748736000" },
		"time of day":        func(r *Request) { r.Window.Start = "2026-06-01T00:00" },
		"offset":             func(r *Request) { r.Window.End = "2026-10-01T00:00:00-04:00" },
		"end before start":   func(r *Request) { r.Window.Start, r.Window.End = "2026-10-01", "2026-06-01" },
		"empty window":       func(r *Request) { r.Window.End = r.Window.Start },
		"no time zone":       func(r *Request) { r.Window.Timezone = "" },
		"machine-local zone": func(r *Request) { r.Window.Timezone = "Local" },
		"unknown zone":       func(r *Request) { r.Window.Timezone = "America/Gotham" },
		"impossible date":    func(r *Request) { r.Window.End = "2026-09-31" },
	} {
		req := incidentRequest(DeliverRaw)
		mutate(&req)
		var refused *RequestError
		if _, err := defs.Validate(req, false); !errors.As(err, &refused) {
			t.Errorf("%s: not refused (err %v)", name, err)
		}
	}
}

func TestDaylightSavingAndMonthBoundaries(t *testing.T) {
	defs, _ := LoadDefinitions()
	req := incidentRequest(DeliverRaw)
	req.Window.Start, req.Window.End = "2026-11-01", "2026-11-02" // clocks go back on 1 November
	plan, err := defs.Validate(req, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.EndEpoch - plan.StartEpoch; got != 25*3600 {
		t.Errorf("1 November 2026 in New York is %d hours long, want 25", got/3600)
	}

	eastern, _ := time.LoadLocation("America/New_York")
	n := Normalizer{Location: eastern, Identity: IdentityPseudonymous, Salt: []byte("salt-salt-salt-salt")}
	row := incidentRows()[7] // 2026-06-30 22:00 EDT, 02:00 UTC on 1 July
	got := n.Normalize(row).Values
	if got["submit_month"].Text != "2026-06" || got["submit_local"].Text != "2026-06-30T22:00:00-04:00" {
		t.Errorf("month %q, local %q: want June, in New York time", got["submit_month"].Text, got["submit_local"].Text)
	}
	n.Location = time.UTC
	if month := n.Normalize(row).Values["submit_month"].Text; month != "2026-07" {
		t.Errorf("in UTC the same job is %q, want 2026-07: the month must follow the request's zone", month)
	}
}

func TestTheWindowSelectsExactlyItsJobs(t *testing.T) {
	opts := testOptions(t, &fakeSource{rows: incidentRows()}, nil)
	m, _, err := Run(context.Background(), incidentRequest(DeliverRaw), opts)
	if err != nil {
		t.Fatal(err)
	}
	// 11 rows: the one at 2026-10-01 00:00 and the one in June 2025 are outside.
	if m.Raw.RowsWritten != 9 || m.Raw.RowsExpected != 9 {
		t.Errorf("wrote %d of %d, want 9 of 9", m.Raw.RowsWritten, m.Raw.RowsExpected)
	}
	if m.Window.StartEpoch != juneStart || m.Window.EndEpoch != octStart {
		t.Errorf("manifest window [%d, %d)", m.Window.StartEpoch, m.Window.EndEpoch)
	}
}

// --- Requested versus allocated nodes ---

func TestNoRequestedFieldReadsAnAllocatedColumn(t *testing.T) {
	defs, _ := LoadDefinitions()
	allocated := []string{"NNodes", "NCPUS", "NodeList", "CPUTimeRAW", "TRESalloc_"}
	for _, f := range defs.Fields {
		if !strings.HasPrefix(f.Name, "req_") {
			continue
		}
		for _, source := range f.Sources {
			for _, bad := range allocated {
				if strings.HasPrefix(source, bad) {
					t.Errorf("%s is a requested field sourced from %s, which is allocated", f.Name, source)
				}
			}
		}
	}
	nodes, _ := defs.Lookup("req_nodes")
	if nodes.Sources[0] != "TRESReq_node" || !strings.Contains(nodes.Rule, "Never NNodes") {
		t.Errorf("req_nodes must come from TRESReq_node and say it is never NNodes: %+v", nodes)
	}
	if strings.Contains(RowsQuery, "NNodes") {
		t.Error("the export query reads NNodes; requested nodes must never be replaced with allocated ones")
	}
}

func TestRequestedNodesCountWhatWasAskedFor(t *testing.T) {
	eastern, _ := time.LoadLocation("America/New_York")
	n := Normalizer{Location: eastern, Identity: IdentityPseudonymous, Salt: []byte("salt-salt-salt-salt")}
	row := incidentRows()[0]
	row.TRESReqNode = txt("2")
	got := n.Normalize(row)
	if got.Values["req_nodes"].Text != "2" {
		t.Errorf("req_nodes = %q, want 2 from TRESReq_node", got.Values["req_nodes"].Text)
	}
	row.TRESReqNode = Text{}
	if got := n.Normalize(row); got.Values["req_nodes"].Valid || got.Flags["req_nodes"][0] != "nodes_missing" {
		t.Errorf("a recorded job with no node request: %+v, want null with nodes_missing", got.Values["req_nodes"])
	}
	if got := n.Normalize(preTRESRows()[0]); got.Values["req_nodes"].Valid || got.Flags["req_nodes"][0] != "tres_unrecorded" {
		t.Errorf("a job from before TRES: %+v, want null with tres_unrecorded", got.Values["req_nodes"])
	}
}

// --- Unavailable GPU type ---

func TestGPUTypeIsRefusedUnlessTheOmissionIsAccepted(t *testing.T) {
	defs, _ := LoadDefinitions()
	req := incidentRequest(DeliverNormalized, "job_id", "req_gpus", "req_gpu_type")
	_, err := defs.Validate(req, false)
	var refused *RequestError
	if !errors.As(err, &refused) {
		t.Fatalf("req_gpu_type was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "count only") || !strings.Contains(err.Error(), "allow_unavailable") {
		t.Errorf("the refusal does not say why or how to proceed: %v", err)
	}

	req.AllowUnavailable = true
	opts := testOptions(t, &fakeSource{rows: incidentRows()}, nil)
	m, dir, err := Run(context.Background(), req, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Unavailable) != 1 || m.Unavailable[0].Field != "req_gpu_type" {
		t.Errorf("unavailable fields = %+v", m.Unavailable)
	}
	for _, c := range append(m.Raw.Columns, m.Normalization.Columns...) {
		if c == "req_gpu_type" {
			t.Error("an unavailable field appears as a column; it must be omitted, not filled with nulls")
		}
	}
	if m.Fulfillment.State != PartiallyFulfilled {
		t.Errorf("fulfillment = %s, want partially_fulfilled", m.Fulfillment.State)
	}
	if code, verdict, failed := runVerifier(t, dir); code != 3 || verdict["fulfillment"] != PartiallyFulfilled {
		t.Errorf("verifier exit %d, verdict %v, failures:\n%s\nwant exit 3 and partially_fulfilled", code, verdict, failed)
	}
}

// --- Unresolved memory semantics ---

func TestMemoryConversionKeepsItsAssumptionVisible(t *testing.T) {
	for raw, want := range map[string]struct {
		bytes string
		flag  string
	}{
		"512M": {"536870912", "mem_scope_assumed_job_total"},
		"16G":  {"17179869184", "mem_scope_assumed_job_total"},
		"1T":   {"1099511627776", "mem_scope_assumed_job_total"},
		"1.5G": {"1610612736", "mem_scope_assumed_job_total"},
		"0G":   {"", "mem_special"},
		"16GB": {"", "mem_invalid"},
		"16":   {"", "mem_invalid"},
		"":     {"", "mem_missing"},
	} {
		bytes, flags := memBytes(txt(raw))
		if bytes != want.bytes || len(flags) != 1 || flags[0] != want.flag {
			t.Errorf("%q -> %q %v, want %q %s", raw, bytes, flags, want.bytes, want.flag)
		}
	}
	if bytes, flags := memBytes(Text{}); bytes != "" || flags[0] != "mem_missing" {
		t.Errorf("null memory -> %q %v, want null with mem_missing", bytes, flags)
	}

	opts := testOptions(t, &fakeSource{rows: incidentRows()}, nil)
	m, _, err := Run(context.Background(), incidentRequest(DeliverNormalized), opts)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, a := range m.Assumptions {
		names[a.Name] = true
	}
	if !names["mem_scope_job_total"] || !names["mem_units_binary"] {
		t.Errorf("a normalized export with memory bytes must name both assumptions; got %+v", m.Assumptions)
	}
	if !strings.Contains(FieldsMarkdown(opts.Definitions), "req_mem_scope_requested") {
		t.Error("FIELDS.md does not say the requested memory scope is not recorded")
	}
	raw, _, _ := Run(context.Background(), incidentRequest(DeliverRaw), testOptions(t, &fakeSource{rows: incidentRows()}, nil))
	if len(raw.Assumptions) != 0 {
		t.Errorf("a raw export carries assumptions %+v; raw values are what the database holds", raw.Assumptions)
	}
}

func TestNoMissingValueBecomesZero(t *testing.T) {
	eastern, _ := time.LoadLocation("America/New_York")
	n := Normalizer{Location: eastern, Identity: IdentityPseudonymous, Salt: []byte("salt-salt-salt-salt")}
	before := n.Normalize(preTRESRows()[0])
	for _, field := range []string{"req_gpus", "req_nodes", "req_mem_bytes"} {
		if before.Values[field].Valid {
			t.Errorf("before TRES, %s = %q; unknown is null, not a number", field, before.Values[field].Text)
		}
		if len(before.Flags[field]) == 0 {
			t.Errorf("before TRES, %s is null with no flag saying why", field)
		}
	}
	cpuJob := n.Normalize(incidentRows()[1]) // recorded, empty GPU request
	if cpuJob.Values["req_gpus"].Text != "0" {
		t.Errorf("a recorded CPU-only request gave req_gpus %q, want 0", cpuJob.Values["req_gpus"].Text)
	}
}

// --- Failed file writes ---

func TestAFailedWriteLeavesNoExport(t *testing.T) {
	for name, fs := range map[string]faultFS{
		"raw file cannot be created":     {failCreate: RawFile},
		"raw file write fails":           {failWrite: RawFile},
		"raw file cannot be flushed":     {failSync: RawFile},
		"normalized file write fails":    {failWrite: NormalizedFile},
		"validation report cannot write": {failCreate: ValidationFile},
		"verifier cannot be written":     {failCreate: VerifierFile},
		"manifest cannot be written":     {failCreate: ManifestFile},
		"manifest cannot be flushed":     {failSync: ManifestFile},
		"export cannot be moved in":      {failRename: true},
	} {
		t.Run(name, func(t *testing.T) {
			opts := testOptions(t, &fakeSource{rows: incidentRows()}, fs)
			m, dir, err := Run(context.Background(), incidentRequest(DeliverNormalized), opts)
			var failed *FailedError
			if !errors.As(err, &failed) {
				t.Fatalf("got manifest %v, dir %q, err %v; want a FailedError", m != nil, dir, err)
			}
			if m != nil || dir != "" {
				t.Error("a failed export returned a manifest or a directory")
			}
			if left := rootEntries(t, opts.Root); len(left) != 0 {
				t.Errorf("left behind %v; a failed export must leave nothing, staging included", left)
			}
		})
	}
}

// --- Incomplete exports ---

func TestAShortExtractionIsIncompleteAndNotFulfilled(t *testing.T) {
	for name, source := range map[string]*fakeSource{
		"rows lost while reading":     {rows: incidentRows(), dropRows: 2},
		"rows arrived while reading":  {rows: incidentRows(), countAfterDelta: 3},
		"rows vanished while reading": {rows: incidentRows(), countAfterDelta: -1},
	} {
		t.Run(name, func(t *testing.T) {
			opts := testOptions(t, source, nil)
			m, dir, err := Run(context.Background(), incidentRequest(DeliverNormalized), opts)
			if err != nil {
				t.Fatal(err)
			}
			if m.Raw.State != RawIncomplete || m.Normalization.State != NormNotRun || m.Fulfillment.State != NotFulfilled {
				t.Errorf("raw %s, normalization %s, fulfillment %s; want incomplete, not_run, not_fulfilled",
					m.Raw.State, m.Normalization.State, m.Fulfillment.State)
			}
			if _, err := os.Stat(filepath.Join(dir, NormalizedFile)); !os.IsNotExist(err) {
				t.Error("a normalized file was shipped from an incomplete extraction")
			}
			code, verdict, failed := runVerifier(t, dir)
			if code == 0 {
				t.Errorf("verifier exit 0 for an incomplete export: %v", verdict)
			}
			if code != 3 || verdict["raw"] != RawIncomplete {
				t.Errorf("verifier exit %d, verdict %v, failures:\n%s\nwant 3 with raw incomplete reported", code, verdict, failed)
			}
		})
	}
}

// --- The happy path, and the verifier against tampering ---

func TestAValidatedExportVerifies(t *testing.T) {
	rows := append(incidentRows(), preTRESRows()...)
	opts := testOptions(t, &fakeSource{rows: rows}, nil)
	req := incidentRequest(DeliverNormalized)
	req.Window.Start = "2026-01-01" // takes in the job from before TRES
	m, dir, err := Run(context.Background(), req, opts)
	if err != nil {
		t.Fatal(err)
	}
	if m.Raw.State != RawComplete || m.Normalization.State != NormValidated || m.Fulfillment.State != Fulfilled {
		t.Fatalf("raw %s, normalization %s (%s), fulfillment %s", m.Raw.State, m.Normalization.State, m.Normalization.Reason, m.Fulfillment.State)
	}
	code, verdict, failed := runVerifier(t, dir)
	if code != 0 || verdict["verified"] != true {
		t.Errorf("verifier exit %d, verdict %v, failures:\n%s", code, verdict, failed)
	}
	if !containsWarning(m.Warnings, "before 22 January 2026") {
		t.Errorf("a window reaching before TRES carries no warning: %v", m.Warnings)
	}
}

func TestAViewDisagreementFailsValidationAndWithholdsTheFile(t *testing.T) {
	rows := incidentRows()
	rows[1].ViewMemReqGB = txt("512.000") // the old "512M is 512" mistake, in the other implementation
	opts := testOptions(t, &fakeSource{rows: rows}, nil)
	m, dir, err := Run(context.Background(), incidentRequest(DeliverNormalized), opts)
	if err != nil {
		t.Fatal(err)
	}
	if m.Raw.State != RawComplete || m.Normalization.State != NormFailedValidation || m.Fulfillment.State != NotFulfilled {
		t.Fatalf("raw %s, normalization %s, fulfillment %s", m.Raw.State, m.Normalization.State, m.Fulfillment.State)
	}
	if !strings.Contains(m.Normalization.Reason, "agrees_with_view") {
		t.Errorf("reason %q does not name the failed check", m.Normalization.Reason)
	}
	if _, err := os.Stat(filepath.Join(dir, NormalizedFile)); !os.IsNotExist(err) {
		t.Error("a normalized file that failed validation was shipped")
	}
	if code, verdict, failed := runVerifier(t, dir); code != 3 || verdict["normalization"] != NormFailedValidation {
		t.Errorf("verifier exit %d, verdict %v, failures:\n%s", code, verdict, failed)
	}
}

func TestTheVerifierRejectsAnExportThatDoesNotSupportItsManifest(t *testing.T) {
	fresh := func(t *testing.T) (*Manifest, string) {
		m, dir, err := Run(context.Background(), incidentRequest(DeliverNormalized), testOptions(t, &fakeSource{rows: incidentRows()}, nil))
		if err != nil {
			t.Fatal(err)
		}
		return m, dir
	}
	rewrite := func(t *testing.T, dir string, m *Manifest) {
		if err := os.WriteFile(filepath.Join(dir, ManifestFile), marshalManifest(m), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, tamper := range map[string]func(t *testing.T, m *Manifest, dir string){
		"truncated raw file": func(t *testing.T, m *Manifest, dir string) {
			path := filepath.Join(dir, RawFile)
			raw, _ := os.ReadFile(path)
			os.WriteFile(path, raw[:len(raw)/2], 0o600)
		},
		"edited value, checksums updated to hide it": func(t *testing.T, m *Manifest, dir string) {
			rewriteCSV(t, filepath.Join(dir, NormalizedFile), "536870912", "512")
			refreshChecksums(t, m, dir)
			rewrite(t, dir, m)
		},
		"the incident's window in the manifest": func(t *testing.T, m *Manifest, dir string) {
			m.Window.StartEpoch, m.Window.EndEpoch = 1748736000, 1759272000
			rewrite(t, dir, m)
		},
		"claims fulfilled with a field omitted": func(t *testing.T, m *Manifest, dir string) {
			m.Request.Fields = append(m.Request.Fields, "req_gpu_type")
			rewrite(t, dir, m)
		},
		"row count overstated": func(t *testing.T, m *Manifest, dir string) {
			m.Raw.RowsExpected++
			m.Raw.CountAfter++
			rewrite(t, dir, m)
		},
		"an unlisted file": func(t *testing.T, m *Manifest, dir string) {
			os.WriteFile(filepath.Join(dir, "extra.csv"), []byte("x"), 0o600)
		},
		"no manifest": func(t *testing.T, m *Manifest, dir string) {
			os.Remove(filepath.Join(dir, ManifestFile))
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, dir := fresh(t)
			tamper(t, m, dir)
			if code, verdict, _ := runVerifier(t, dir); code != 1 || verdict["verified"] != false {
				t.Errorf("verifier exit %d, verdict %v; want 1 (not verified)", code, verdict)
			}
		})
	}
}

// --- Identity ---

func TestIdentityIsPseudonymousUnlessPermitted(t *testing.T) {
	defs, _ := LoadDefinitions()
	req := incidentRequest(DeliverRaw)
	req.Identity = IdentityNetid
	if _, err := defs.Validate(req, false); err == nil || !strings.Contains(err.Error(), "identify permission") {
		t.Errorf("netid without the identify permission: %v", err)
	}
	if _, err := defs.Validate(req, true); err != nil {
		t.Errorf("netid with the permission: %v", err)
	}
	salt := []byte("0123456789abcdef")
	if a, b := ResearcherKey(salt, "alice"), ResearcherKey(salt, "alice"); a != b || a == "alice" || !strings.HasPrefix(a, "r_") {
		t.Errorf("keys %q %q: want stable, prefixed, and not the netid", a, b)
	}
	opts := testOptions(t, &fakeSource{rows: incidentRows()}, nil)
	opts.Salt = nil
	var failed *FailedError
	if _, _, err := Run(context.Background(), incidentRequest(DeliverRaw), opts); !errors.As(err, &failed) {
		t.Errorf("no salt: %v; want a failure, never an unsalted export", err)
	}
	m, dir, err := Run(context.Background(), incidentRequest(DeliverRaw), testOptions(t, &fakeSource{rows: incidentRows()}, nil))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, RawFile))
	if strings.Contains(string(gunzip(t, raw)), "alice") {
		t.Error("a pseudonymous export contains the netid")
	}
	if m.Raw.Columns[1] != "researcher_key" {
		t.Errorf("raw columns %v: the netid column must be replaced by researcher_key", m.Raw.Columns)
	}
}

// --- Definitions ---

func TestEveryDeliverableFieldIsImplemented(t *testing.T) {
	defs, err := LoadDefinitions()
	if err != nil {
		t.Fatal(err)
	}
	eastern, _ := time.LoadLocation("America/New_York")
	got := Normalizer{Location: eastern, Identity: IdentityPseudonymous, Salt: []byte("salt-salt-salt-salt")}.Normalize(incidentRows()[0])
	for _, f := range defs.Fields {
		_, implemented := got.Values[f.Name]
		switch {
		case f.Status == StatusNotRecorded && implemented:
			t.Errorf("%s is defined as not recorded but the normalizer produces it", f.Name)
		case f.Status != StatusNotRecorded && f.Name != "quality_flags" && !implemented:
			t.Errorf("%s is defined but the normalizer never produces it", f.Name)
		}
	}
	for field, flags := range got.Flags {
		for _, flag := range flags {
			if _, ok := defs.Flags[flag]; !ok {
				t.Errorf("%s raised %s, which fields.json does not define", field, flag)
			}
		}
	}
}

func containsWarning(warnings []string, part string) bool {
	for _, w := range warnings {
		if strings.Contains(w, part) {
			return true
		}
	}
	return false
}
