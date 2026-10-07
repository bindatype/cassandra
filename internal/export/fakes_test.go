package export

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSource serves rows from memory. dropRows and countAfterDelta simulate
// a source that loses rows or keeps ingesting during the export.
type fakeSource struct {
	rows            []SourceRow
	dropRows        int
	countAfterDelta int64
	counts          int
}

func (f *fakeSource) Snapshot(ctx context.Context) (Snapshot, error) { return f, nil }
func (f *fakeSource) AsOf() time.Time                                { return time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC) }
func (f *fakeSource) Describe() SourceInfo {
	return SourceInfo{Endpoint: "fake:3306", Database: "pegasusdb", Relation: "runTBL2_jobs", Engine: "InnoDB", Snapshot: "consistent (InnoDB)"}
}
func (f *fakeSource) Query() string { return RowsQuery }
func (f *fakeSource) Close() error  { return nil }

func (f *fakeSource) inWindow(start, end int64) []SourceRow {
	var out []SourceRow
	for _, r := range f.rows {
		if r.SubmitTime >= start && r.SubmitTime < end {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeSource) Count(ctx context.Context, start, end int64) (int64, error) {
	f.counts++
	n := int64(len(f.inWindow(start, end)))
	if f.counts > 1 {
		n += f.countAfterDelta
	}
	return n, nil
}

func (f *fakeSource) Rows(ctx context.Context, start, end int64, each func(SourceRow) error) error {
	rows := f.inWindow(start, end)
	rows = rows[:len(rows)-f.dropRows]
	for _, r := range rows {
		if err := each(r); err != nil {
			return err
		}
	}
	return nil
}

// faultFS writes to a real temporary directory and fails at a named step.
type faultFS struct {
	OSFS
	failCreate string // base name whose Create fails
	failWrite  string // base name whose writes fail after the first
	failSync   string // base name whose Sync fails
	failRename bool
}

var errInjected = errors.New("injected failure")

func (f faultFS) Create(path string) (File, error) {
	if filepath.Base(path) == f.failCreate {
		return nil, errInjected
	}
	file, err := f.OSFS.Create(path)
	if err != nil {
		return nil, err
	}
	return &faultFile{File: file, failWrite: filepath.Base(path) == f.failWrite, failSync: filepath.Base(path) == f.failSync}, nil
}

func (f faultFS) Rename(oldpath, newpath string) error {
	if f.failRename {
		return errInjected
	}
	return f.OSFS.Rename(oldpath, newpath)
}

type faultFile struct {
	File
	failWrite bool
	failSync  bool
	writes    int
}

func (f *faultFile) Write(p []byte) (int, error) {
	f.writes++
	if f.failWrite && f.writes > 1 {
		return 0, errInjected
	}
	return f.File.Write(p)
}

func (f *faultFile) Sync() error {
	if f.failSync {
		return errInjected
	}
	return f.File.Sync()
}

// The incident's window: June through September 2026, New York time.
const (
	juneStart  = int64(1780286400) // 2026-06-01 00:00 EDT
	octStart   = int64(1790827200) // 2026-10-01 00:00 EDT
	preTRESJob = int64(1767268800) // 2026-01-01 07:00 EST, before TRES was recorded
)

func txt(s string) Text { return Text{Value: s, Valid: true} }
func num(n int64) Int   { return Int{Value: n, Valid: true} }

// incidentRows covers every shape the incident needed handled: array and
// plain ids, recorded and unrecorded TRES, every memory and wall-time form,
// an unresolved partition and a CPU mismatch. View columns are what
// runTBL2_jobs.sql computes for each.
func incidentRows() []SourceRow {
	base := func(id string, at int64) SourceRow {
		return SourceRow{JobID: txt(id), Netid: txt("alice"), GroupName: txt("physgrp"), SubmitTime: at,
			Partition: txt("gpu"), State: txt("COMPLETED"), ReqCPUS: num(4), TRESReqCPU: txt("4"),
			TRESReqNode: txt("1"), TRESReqGresGPU: txt("1"), TRESReqMem: txt("16G"), TimelimitRaw: txt("30"),
			ViewMemReqGB: txt("16.000"), ViewTimelimitMin: num(30), ViewGpusReq: num(1), ViewNodesReq: num(1)}
	}
	rows := []SourceRow{}
	r := base("73299647_1", juneStart) // array task, at the very start of the window
	rows = append(rows, r)
	r = base("73299648", juneStart+3600) // plain id, CPU job, memory in M
	r.Partition, r.TRESReqGresGPU, r.TRESReqMem, r.ViewMemReqGB, r.ViewGpusReq = txt("cpu"), txt(""), txt("512M"), txt("0.500"), num(0)
	rows = append(rows, r)
	r = base("73299649", juneStart+7200) // terabytes and an unlimited wall time
	r.TRESReqMem, r.ViewMemReqGB, r.TimelimitRaw, r.ViewTimelimitMin = txt("1T"), txt("1024.000"), txt("UNLIMITED"), Int{}
	rows = append(rows, r)
	r = base("73299650", juneStart+10800) // partition default limit, fractional memory
	r.TRESReqMem, r.ViewMemReqGB, r.TimelimitRaw, r.ViewTimelimitMin = txt("1.5G"), txt("1.500"), txt("Partition"), Int{}
	rows = append(rows, r)
	r = base("73299651", juneStart+14400) // unresolved multi-partition request, CPU mismatch
	r.Partition, r.TRESReqCPU = txt("cpu_gpu"), txt("8")
	rows = append(rows, r)
	r = base("73299652", juneStart+18000) // all-memory request
	r.TRESReqMem, r.ViewMemReqGB = txt("0G"), txt("0.000")
	rows = append(rows, r)
	r = base("7329+bad", juneStart+21600) // malformed id, missing netid
	r.Netid = Text{}
	rows = append(rows, r)
	r = base("73299653", 1782871200) // 2026-06-30 22:00 EDT: June in New York, already July in UTC
	rows = append(rows, r)
	r = base("73299654", octStart-1) // the last second of the window
	rows = append(rows, r)
	r = base("73299655", octStart) // the first second after it: excluded
	rows = append(rows, r)
	r = base("1748736000", 1748736000) // the incident's wrong start, June 2025: excluded
	rows = append(rows, r)
	return rows
}

// preTRESRows are jobs from before TRES requests were recorded.
func preTRESRows() []SourceRow {
	return []SourceRow{{JobID: txt("60000001"), Netid: txt("bob"), GroupName: txt("chemgrp"), SubmitTime: preTRESJob,
		Partition: txt("cpu"), State: txt("FAILED"), ReqCPUS: num(16), TimelimitRaw: txt("120"), ViewTimelimitMin: num(120)}}
}

func incidentRequest(deliver string, fields ...string) Request {
	if len(fields) == 0 {
		fields = []string{"job_id", "array_parent_id", "array_task_index", "researcher_key", "account",
			"submit_epoch", "submit_local", "submit_month", "partition_raw", "state",
			"req_cpus", "req_nodes", "req_gpus", "req_mem_raw", "req_mem_bytes",
			"req_walltime_raw", "req_walltime_s", "quality_flags"}
	}
	return Request{Source: "pegasus", Window: Window{Start: "2026-06-01", End: "2026-10-01", Timezone: "America/New_York"},
		Fields: fields, Deliver: deliver, Identity: IdentityPseudonymous, Purpose: "test"}
}

func testOptions(t *testing.T, source Source, fs FS) Options {
	t.Helper()
	defs, err := LoadDefinitions()
	if err != nil {
		t.Fatal(err)
	}
	if fs == nil {
		fs = OSFS{}
	}
	return Options{Definitions: defs, Source: source, FS: fs, Root: filepath.Join(t.TempDir(), "exports"),
		Caller: "glen", Salt: []byte("0123456789abcdef-test-salt"), ToolVersion: "test",
		NewID: func() string { return "test-export" }}
}

// rootEntries lists what is left in the export root, staging included.
func rootEntries(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// runVerifier runs the shipped verifier on a directory and returns its exit
// code and verdict. Skipped where python3 is absent.
func runVerifier(t *testing.T, dir string) (int, map[string]any, string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	cmd := exec.Command(python, filepath.Join(dir, VerifierFile), "--json", dir)
	out, err := cmd.Output()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run verifier: %v", err)
	}
	var result struct {
		Checks  []map[string]any `json:"checks"`
		Verdict map[string]any   `json:"verdict"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("verifier output is not JSON: %v\n%s", err, out)
	}
	var failed []string
	for _, c := range result.Checks {
		if c["passed"] != true {
			failed = append(failed, c["id"].(string)+" "+c["name"].(string)+": "+c["detail"].(string))
		}
	}
	return code, result.Verdict, strings.Join(failed, "\n")
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func gunzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// rewriteCSV replaces the first occurrence of a cell value, as an edit by
// hand would, and recompresses.
func rewriteCSV(t *testing.T, path, old, replacement string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(gunzip(t, raw))
	if !strings.Contains(text, ","+old+",") {
		t.Fatalf("%s holds no cell %q", path, old)
	}
	text = strings.Replace(text, ","+old+",", ","+replacement+",", 1)
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(text))
	w.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// refreshChecksums makes the manifest's file list match the files, as a
// careful forger would.
func refreshChecksums(t *testing.T, m *Manifest, dir string) {
	t.Helper()
	for i, f := range m.Files {
		raw, err := os.ReadFile(filepath.Join(dir, f.Name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		m.Files[i].Bytes, m.Files[i].SHA256 = int64(len(raw)), hex.EncodeToString(sum[:])
	}
}
