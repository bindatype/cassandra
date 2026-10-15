package export

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed verify_export.py
var verifierScript []byte

// File names inside an export directory.
const (
	RawFile        = "raw.csv.gz"
	NormalizedFile = "normalized.csv.gz"
	ManifestFile   = "manifest.json"
	FieldsFile     = "fields.json"
	FieldsDoc      = "FIELDS.md"
	VerifierDoc    = "VERIFIER.md"
	QueryFile      = "query.sql"
	ValidationFile = "validation.json"
	VerifierFile   = "verify_export.py"
)

// NullMarker stands for SQL NULL in the CSV files, so a null is never read as
// an empty string; in this database the two mean different things.
const NullMarker = `\N`

// Options configures one export.
type Options struct {
	Definitions *Definitions
	Source      Source
	FS          FS
	Root        string // exports live in Root/<export_id>
	Caller      string
	CanIdentify bool
	Salt        []byte
	MaxRows     int64
	ToolVersion string
	Now         func() time.Time
	NewID       func() string
	Progress    func(rows int64)
}

// FailedError is an export that produced nothing usable: no manifest exists
// and its staging directory has been removed.
type FailedError struct {
	Step string
	Err  error
}

func (e *FailedError) Error() string { return "export failed at " + e.Step + ": " + e.Err.Error() }
func (e *FailedError) Unwrap() error { return e.Err }

// rawSourceOrder is the order of source columns in the raw file.
var rawSourceOrder = []string{"JobID", "netid", "groupName", "SubmitTime", "partition", "State", "ReqCPUS",
	"TRESReq_cpu", "TRESReq_node", "TRESReq_gres_gpu", "TRESReq_mem", "TimelimitRaw"}

// Run performs one export. It returns a *RequestError when the request is
// refused, a *FailedError when nothing usable was produced, and otherwise
// the manifest, whose three outcomes say what was achieved; a manifest with
// an incomplete raw extraction is still returned, so the reason is kept.
func Run(ctx context.Context, req Request, opts Options) (*Manifest, string, error) {
	defs := opts.Definitions
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	newID := opts.NewID
	if newID == nil {
		newID = NewExportID
	}
	plan, err := defs.Validate(req, opts.CanIdentify)
	if err != nil {
		return nil, "", err
	}
	if req.Identity == IdentityPseudonymous && len(opts.Salt) < 16 {
		return nil, "", &FailedError{Step: "configuration", Err: errors.New("no pseudonymization salt is configured (at least 16 bytes); refusing rather than exporting unsalted or raw identities")}
	}

	id := newID()
	if err := opts.FS.MkdirAll(opts.Root, 0o700); err != nil {
		return nil, "", &FailedError{Step: "create export root", Err: err}
	}
	staging, err := opts.FS.MkdirTemp(opts.Root, ".staging-"+id+"-")
	if err != nil {
		return nil, "", &FailedError{Step: "create staging directory", Err: err}
	}
	finished := false
	defer func() {
		if !finished {
			opts.FS.RemoveAll(staging)
		}
	}()
	fail := func(step string, err error) (*Manifest, string, error) {
		return nil, "", &FailedError{Step: step, Err: err}
	}

	snap, err := opts.Source.Snapshot(ctx)
	if err != nil {
		return fail("open snapshot", err)
	}
	defer snap.Close()
	expected, err := snap.Count(ctx, plan.StartEpoch, plan.EndEpoch)
	if err != nil {
		return fail("count rows", err)
	}
	if opts.MaxRows > 0 && expected > opts.MaxRows {
		return fail("size limit", fmt.Errorf("the window holds %d jobs, over the limit of %d; split it into shorter windows", expected, opts.MaxRows))
	}

	identityColumn := "researcher_key"
	if req.Identity == IdentityNetid {
		identityColumn = "netid"
	}
	rawColumns := rawColumnsFor(plan.Deliverable, identityColumn)
	normalize := req.Deliver == DeliverNormalized
	var normColumns []string
	for _, f := range plan.Deliverable {
		normColumns = append(normColumns, f.Name)
	}

	rawOut, err := newTable(opts.FS, filepath.Join(staging, RawFile), rawColumns)
	if err != nil {
		return fail("create "+RawFile, err)
	}
	var normOut *table
	if normalize {
		if normOut, err = newTable(opts.FS, filepath.Join(staging, NormalizedFile), normColumns); err != nil {
			rawOut.abort()
			return fail("create "+NormalizedFile, err)
		}
	}
	abort := func() {
		rawOut.abort()
		if normOut != nil {
			normOut.abort()
		}
	}

	normalizer := Normalizer{Location: plan.Location, Identity: req.Identity, Salt: opts.Salt}
	audit := newValidationAudit(defs)
	var written int64
	err = snap.Rows(ctx, plan.StartEpoch, plan.EndEpoch, func(row SourceRow) error {
		identity := row.Netid
		if identity.Valid && strings.TrimSpace(identity.Value) != "" {
			identity = Text{Value: normalizer.identity(identity.Value), Valid: true}
		}
		if err := rawOut.write(rawRecord(row, rawColumns, identity)); err != nil {
			return fmt.Errorf("write %s: %w", RawFile, err)
		}
		if normalize {
			n := normalizer.Normalize(row)
			record := make([]string, len(normColumns))
			for i, f := range plan.Deliverable {
				if f.Name == "quality_flags" {
					record[i] = n.QualityFlags(plan.Deliverable)
					continue
				}
				record[i] = cell(n.Values[f.Name])
			}
			if err := normOut.write(record); err != nil {
				return fmt.Errorf("write %s: %w", NormalizedFile, err)
			}
			audit.observe(row, n, plan.Deliverable)
		}
		written++
		if opts.Progress != nil && written%10000 == 0 {
			opts.Progress(written)
		}
		return nil
	})
	if err != nil {
		abort()
		return fail("read rows", err)
	}
	countAfter, err := snap.Count(ctx, plan.StartEpoch, plan.EndEpoch)
	if err != nil {
		abort()
		return fail("count rows after reading", err)
	}

	rawInfo, err := rawOut.finish()
	if err != nil {
		if normOut != nil {
			normOut.abort()
		}
		return fail("finish "+RawFile, err)
	}
	var normInfo FileInfo
	if normOut != nil {
		if normInfo, err = normOut.finish(); err != nil {
			return fail("finish "+NormalizedFile, err)
		}
	}

	m := &Manifest{
		ManifestVersion:  ManifestVersion,
		ExportID:         id,
		CreatedAt:        now().UTC(),
		Tool:             ToolInfo{Name: "cass-export", Version: opts.ToolVersion},
		Caller:           opts.Caller,
		Request:          req,
		RequestSHA256:    plan.RequestHash,
		FieldDefinitions: DefinitionsInfo{File: FieldsFile, Version: defs.Version, SHA256: defs.SHA256()},
		Source:           snap.Describe(),
		Window: WindowInfo{Start: req.Window.Start, End: req.Window.End, Timezone: req.Window.Timezone,
			StartEpoch: plan.StartEpoch, EndEpoch: plan.EndEpoch, Interval: "[start_epoch, end_epoch): start included, end excluded"},
		AsOf:      snap.AsOf().UTC(),
		QueryFile: QueryFile,
		Warnings:  []string{},
	}
	for _, f := range plan.Unavailable {
		m.Unavailable = append(m.Unavailable, UnavailableRef{Field: f.Name, Reason: f.Reason})
	}
	if m.Unavailable == nil {
		m.Unavailable = []UnavailableRef{}
	}
	m.Assumptions = assumptionsFor(defs, plan.Deliverable, normalize)
	m.Warnings = windowWarnings(plan, m.AsOf)

	// Raw outcome: every count must agree, and the file must read back intact.
	rawChecks := []Check{
		{Name: "rows_written_equal_count", Passed: written == expected,
			Detail: fmt.Sprintf("%d rows written, %d counted in the snapshot before reading", written, expected)},
		{Name: "count_unchanged_after_reading", Passed: countAfter == expected,
			Detail: fmt.Sprintf("%d counted before reading, %d after", expected, countAfter)},
		rereadCheck(opts.FS, filepath.Join(staging, RawFile), rawInfo, rawColumns),
	}
	m.Raw = RawOutcome{State: RawComplete, File: RawFile, Columns: rawColumns, RowsExpected: expected,
		RowsWritten: written, CountAfter: countAfter, Checks: rawChecks}
	for _, c := range rawChecks {
		if !c.Passed {
			m.Raw.State = RawIncomplete
			m.Raw.Reason = c.Name + ": " + c.Detail
			break
		}
	}
	m.Files = append(m.Files, rawInfo)

	// Normalization outcome.
	switch {
	case !normalize:
		m.Normalization = NormOutcome{State: NormNotRequested, Checks: []Check{}}
	case m.Raw.State != RawComplete:
		m.Normalization = NormOutcome{State: NormNotRun, Checks: []Check{}, Reason: "the raw extraction is incomplete"}
		opts.FS.RemoveAll(filepath.Join(staging, NormalizedFile))
	default:
		checks := audit.checks(written)
		checks = append(checks, rereadCheck(opts.FS, filepath.Join(staging, NormalizedFile), normInfo, normColumns))
		m.Normalization = NormOutcome{State: NormValidated, File: NormalizedFile, Columns: normColumns, Rows: audit.rows, Checks: checks}
		for _, c := range checks {
			if !c.Passed {
				m.Normalization.State = NormFailedValidation
				m.Normalization.Reason = c.Name + ": " + c.Detail
			}
		}
		if m.Normalization.State == NormValidated {
			m.Files = append(m.Files, normInfo)
		} else {
			// A file that failed validation is not shipped, so it cannot be
			// mistaken for one that passed.
			m.Normalization.File, m.Normalization.Columns = "", nil
			if err := opts.FS.RemoveAll(filepath.Join(staging, NormalizedFile)); err != nil {
				return fail("remove unvalidated "+NormalizedFile, err)
			}
		}
		validation, _ := json.MarshalIndent(map[string]any{
			"state": m.Normalization.State, "rows": audit.rows, "checks": checks, "examples": audit.examples,
		}, "", "  ")
		info, err := writeFile(opts.FS, filepath.Join(staging, ValidationFile), append(validation, '\n'))
		if err != nil {
			return fail("write "+ValidationFile, err)
		}
		m.Files = append(m.Files, info)
	}

	// Fulfillment, judged against the request as received.
	state, reason := Fulfillment(req, m.Raw.State, m.Normalization.State, len(plan.Unavailable))
	m.Fulfillment = FulfillOutcome{State: state, Deliver: req.Deliver, Reason: reason, Fields: fieldOutcomes(plan, m, identityColumn)}

	query := snap.Query() + "\n-- parameters: start_epoch = " + strconv.FormatInt(plan.StartEpoch, 10) +
		", end_epoch = " + strconv.FormatInt(plan.EndEpoch, 10) + "\n-- count: " + CountQuery + "\n"
	for _, extra := range []struct {
		name string
		body []byte
	}{
		{QueryFile, []byte(query)},
		{FieldsFile, defs.Raw()},
		{FieldsDoc, []byte(FieldsMarkdown(defs))},
		{VerifierDoc, []byte(VerifierMarkdown)},
		{VerifierFile, verifierScript},
	} {
		info, err := writeFile(opts.FS, filepath.Join(staging, extra.name), extra.body)
		if err != nil {
			return fail("write "+extra.name, err)
		}
		if extra.name == QueryFile {
			m.QuerySHA256 = info.SHA256
		}
		m.Files = append(m.Files, info)
	}

	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fail("encode manifest", err)
	}
	if _, err := writeFile(opts.FS, filepath.Join(staging, ManifestFile), append(manifest, '\n')); err != nil {
		return fail("write "+ManifestFile, err)
	}
	final := filepath.Join(opts.Root, id)
	if err := opts.FS.Rename(staging, final); err != nil {
		return fail("move export into place", err)
	}
	finished = true
	return m, final, nil
}

// NewExportID is sortable by time and unguessable.
func NewExportID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

func rawColumnsFor(fields []Field, identityColumn string) []string {
	need := map[string]bool{}
	for _, f := range fields {
		if f.Name == "quality_flags" {
			for _, s := range rawSourceOrder {
				need[s] = true
			}
		}
		for _, s := range f.Sources {
			need[s] = true
		}
	}
	var columns []string
	for _, s := range rawSourceOrder {
		if need[s] {
			if s == "netid" {
				s = identityColumn
			}
			columns = append(columns, s)
		}
	}
	return columns
}

func rawRecord(row SourceRow, columns []string, identity Text) []string {
	record := make([]string, len(columns))
	for i, c := range columns {
		var v Text
		switch c {
		case "JobID":
			v = row.JobID
		case "netid", "researcher_key":
			v = identity
		case "groupName":
			v = row.GroupName
		case "SubmitTime":
			v = Text{Value: strconv.FormatInt(row.SubmitTime, 10), Valid: true}
		case "partition":
			v = row.Partition
		case "State":
			v = row.State
		case "ReqCPUS":
			if row.ReqCPUS.Valid {
				v = Text{Value: strconv.FormatInt(row.ReqCPUS.Value, 10), Valid: true}
			}
		case "TRESReq_cpu":
			v = row.TRESReqCPU
		case "TRESReq_node":
			v = row.TRESReqNode
		case "TRESReq_gres_gpu":
			v = row.TRESReqGresGPU
		case "TRESReq_mem":
			v = row.TRESReqMem
		case "TimelimitRaw":
			v = row.TimelimitRaw
		}
		record[i] = cell(Value{Text: v.Value, Valid: v.Valid})
	}
	return record
}

func cell(v Value) string {
	if !v.Valid {
		return NullMarker
	}
	return v.Text
}

func fieldOutcomes(plan *Plan, m *Manifest, identityColumn string) []FieldOutcome {
	var out []FieldOutcome
	for _, name := range plan.Request.Fields {
		f, _ := m.lookupField(plan, name)
		switch {
		case f.Status == StatusNotRecorded:
			out = append(out, FieldOutcome{Field: name, DeliveredAs: "unavailable", Reason: f.Reason})
		case m.Raw.State != RawComplete:
			out = append(out, FieldOutcome{Field: name, DeliveredAs: "not_delivered", Reason: "the raw extraction is incomplete"})
		case plan.Request.Deliver == DeliverNormalized && m.Normalization.State == NormValidated:
			out = append(out, FieldOutcome{Field: name, DeliveredAs: "normalized_column", Columns: []string{name}})
		case plan.Request.Deliver == DeliverNormalized:
			out = append(out, FieldOutcome{Field: name, DeliveredAs: "not_delivered", Reason: "normalization is " + m.Normalization.State})
		default:
			cols := rawColumnsFor([]Field{f}, identityColumn)
			out = append(out, FieldOutcome{Field: name, DeliveredAs: "raw_source_columns", Columns: cols})
		}
	}
	return out
}

func (m *Manifest) lookupField(plan *Plan, name string) (Field, bool) {
	for _, f := range plan.Deliverable {
		if f.Name == name {
			return f, true
		}
	}
	for _, f := range plan.Unavailable {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

func assumptionsFor(defs *Definitions, fields []Field, normalized bool) []Assumption {
	used := map[string]bool{}
	for _, f := range fields {
		for _, a := range f.Assumptions {
			used[a] = true
		}
	}
	out := []Assumption{}
	if !normalized {
		return out // raw values carry no assumption; they are what the database holds
	}
	for _, a := range defs.Assumptions {
		if used[a.Name] {
			out = append(out, a)
		}
	}
	return out
}

func windowWarnings(plan *Plan, asOf time.Time) []string {
	warnings := []string{}
	if plan.EndEpoch > asOf.Unix() {
		warnings = append(warnings, "the window ends after the as-of time; jobs submitted later are not included")
	}
	if plan.StartEpoch < tresStartEpoch {
		warnings = append(warnings, "the window starts before 22 January 2026, when TRES requests began to be recorded; "+
			"GPU, node and memory requests for earlier jobs are null with tres_unrecorded, not zero")
	}
	warnings = append(warnings, "jobs keep arriving until they finish and are ingested, so a later export of the same window can hold more rows; quote as_of with any figure")
	return warnings
}

// tresStartEpoch is 2026-01-22 00:00 US Eastern, the first day TRESReq_mem
// is set (checked 2026-10-07 across all of runTBL2).
var tresStartEpoch = func() int64 {
	eastern, err := time.LoadLocation("America/New_York")
	if err != nil {
		panic(err) // tzdata is compiled in
	}
	return time.Date(2026, 1, 22, 0, 0, 0, 0, eastern).Unix()
}()

// table writes one gzip-compressed CSV and records what it wrote.
type table struct {
	fs      FS
	path    string
	file    File
	hash    hash.Hash
	bytes   *countWriter
	gz      *gzip.Writer
	csv     *csv.Writer
	rows    int64
	columns []string
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func newTable(fs FS, path string, columns []string) (*table, error) {
	file, err := fs.Create(path)
	if err != nil {
		return nil, err
	}
	t := &table{fs: fs, path: path, file: file, hash: sha256.New(), bytes: &countWriter{}, columns: columns}
	t.gz = gzip.NewWriter(io.MultiWriter(file, t.hash, t.bytes))
	t.csv = csv.NewWriter(t.gz)
	if err := t.csv.Write(columns); err != nil {
		file.Close()
		return nil, err
	}
	return t, nil
}

func (t *table) write(record []string) error {
	if err := t.csv.Write(record); err != nil {
		return err
	}
	t.rows++
	if t.rows%4096 == 0 {
		t.csv.Flush()
		return t.csv.Error()
	}
	return nil
}

// finish flushes, syncs and closes, failing on any error along the way: a
// file that could not be flushed is not a file.
func (t *table) finish() (FileInfo, error) {
	t.csv.Flush()
	if err := t.csv.Error(); err != nil {
		t.file.Close()
		return FileInfo{}, err
	}
	if err := t.gz.Close(); err != nil {
		t.file.Close()
		return FileInfo{}, err
	}
	if err := t.file.Sync(); err != nil {
		t.file.Close()
		return FileInfo{}, err
	}
	if err := t.file.Close(); err != nil {
		return FileInfo{}, err
	}
	rows := t.rows
	return FileInfo{Name: filepath.Base(t.path), Bytes: t.bytes.n, SHA256: hex.EncodeToString(t.hash.Sum(nil)), Rows: &rows}, nil
}

func (t *table) abort() { t.file.Close() }

// writeFile writes a small file whole and syncs it.
func writeFile(fs FS, path string, body []byte) (FileInfo, error) {
	file, err := fs.Create(path)
	if err != nil {
		return FileInfo{}, err
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return FileInfo{}, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return FileInfo{}, err
	}
	if err := file.Close(); err != nil {
		return FileInfo{}, err
	}
	sum := sha256.Sum256(body)
	return FileInfo{Name: filepath.Base(path), Bytes: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}, nil
}

// rereadCheck reads a written CSV back from disk: the bytes must hash to what
// was recorded while writing, decompress fully, carry the expected header and
// hold the recorded number of rows.
func rereadCheck(fs FS, path string, info FileInfo, columns []string) Check {
	name := "reread_" + strings.TrimSuffix(filepath.Base(path), ".csv.gz")
	file, err := fs.Open(path)
	if err != nil {
		return Check{Name: name, Detail: "cannot reopen: " + err.Error()}
	}
	defer file.Close()
	hasher := sha256.New()
	gz, err := gzip.NewReader(io.TeeReader(file, hasher))
	if err != nil {
		return Check{Name: name, Detail: "not gzip: " + err.Error()}
	}
	reader := csv.NewReader(gz)
	reader.FieldsPerRecord = len(columns)
	header, err := reader.Read()
	if err != nil {
		return Check{Name: name, Detail: "no header: " + err.Error()}
	}
	if strings.Join(header, ",") != strings.Join(columns, ",") {
		return Check{Name: name, Detail: "header " + strings.Join(header, ",") + " is not " + strings.Join(columns, ",")}
	}
	var rows int64
	for {
		if _, err := reader.Read(); err == io.EOF {
			break
		} else if err != nil {
			return Check{Name: name, Detail: fmt.Sprintf("unreadable after %d rows: %v", rows, err)}
		}
		rows++
	}
	io.Copy(io.Discard, file) // hash any trailing bytes too
	sum := hex.EncodeToString(hasher.Sum(nil))
	switch {
	case sum != info.SHA256:
		return Check{Name: name, Detail: "sha256 on disk " + sum + " differs from " + info.SHA256 + " recorded while writing"}
	case info.Rows == nil || rows != *info.Rows:
		return Check{Name: name, Detail: fmt.Sprintf("%d rows on disk, %v recorded while writing", rows, info.Rows)}
	}
	return Check{Name: name, Passed: true, Detail: fmt.Sprintf("%d rows and %s read back from disk", rows, sum[:12])}
}

// validationAudit accumulates the normalization checks row by row.
type validationAudit struct {
	defs          *Definitions
	rows          int64
	zeroViolation int64
	unflaggedNull int64
	unknownFlags  map[string]bool
	viewMismatch  map[string]int64
	viewMissing   int64
	examples      []string
}

func newValidationAudit(defs *Definitions) *validationAudit {
	return &validationAudit{defs: defs, unknownFlags: map[string]bool{}, viewMismatch: map[string]int64{}}
}

// nullNeedsFlag lists the fields whose null always has a reason to give.
var nullNeedsFlag = []string{"researcher_key", "req_cpus", "req_nodes", "req_gpus", "req_mem_bytes", "req_walltime_s"}

func (a *validationAudit) example(format string, args ...any) {
	if len(a.examples) < 20 {
		a.examples = append(a.examples, fmt.Sprintf(format, args...))
	}
}

func (a *validationAudit) observe(row SourceRow, n Normalized, fields []Field) {
	a.rows++
	// No missing value became zero: a zero GPU count must come from a
	// recorded request with no GPU in it.
	if v := n.Values["req_gpus"]; v.Valid && v.Text == "0" {
		if !tresRecorded(row) || (row.TRESReqGresGPU.Valid && row.TRESReqGresGPU.Value != "") {
			a.zeroViolation++
			a.example("job %s: req_gpus 0 without a recorded empty GPU request", row.JobID.Value)
		}
	}
	if v := n.Values["req_mem_bytes"]; v.Valid && !memValue.MatchString(row.TRESReqMem.Value) {
		a.zeroViolation++
		a.example("job %s: req_mem_bytes %s from unparseable %q", row.JobID.Value, v.Text, row.TRESReqMem.Value)
	}
	if v := n.Values["req_walltime_s"]; v.Valid && !wholeNum.MatchString(row.TimelimitRaw.Value) {
		a.zeroViolation++
		a.example("job %s: req_walltime_s %s from %q", row.JobID.Value, v.Text, row.TimelimitRaw.Value)
	}
	for _, name := range nullNeedsFlag {
		if v, ok := n.Values[name]; ok && !v.Valid && len(n.Flags[name]) == 0 {
			a.unflaggedNull++
			a.example("job %s: %s is null with no flag", row.JobID.Value, name)
		}
	}
	for _, flags := range n.Flags {
		for _, flag := range flags {
			if _, ok := a.defs.Flags[flag]; !ok {
				a.unknownFlags[flag] = true
			}
		}
	}
	a.compareWithView(row, n)
}

// compareWithView checks the exporter's conversions against the view's, an
// independent implementation in SQL.
func (a *validationAudit) compareWithView(row SourceRow, n Normalized) {
	mismatch := func(field, detail string) {
		a.viewMismatch[field]++
		a.example("job %s: %s %s", row.JobID.Value, field, detail)
	}
	// Memory: the view gives GB to three decimals.
	ours := n.Values["req_mem_bytes"]
	switch {
	case !row.ViewMemReqGB.Valid && ours.Valid:
		mismatch("req_mem_bytes", "has a value and the view's mem_req_gb is null")
	case row.ViewMemReqGB.Valid && !ours.Valid:
		if !(hasFlag(n, "req_mem_bytes", "mem_special") && isZeroDecimal(row.ViewMemReqGB.Value)) {
			mismatch("req_mem_bytes", "is null and the view's mem_req_gb is "+row.ViewMemReqGB.Value)
		}
	case row.ViewMemReqGB.Valid && ours.Valid:
		view, ok1 := new(big.Rat).SetString(row.ViewMemReqGB.Value)
		bytesRat, ok2 := new(big.Rat).SetString(ours.Text)
		if !ok1 || !ok2 {
			mismatch("req_mem_bytes", "could not be compared with "+row.ViewMemReqGB.Value)
			break
		}
		gb := new(big.Rat).Quo(bytesRat, new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), 30)))
		diff := new(big.Rat).Sub(gb, view)
		if diff.Abs(diff).Cmp(big.NewRat(1, 1000)) > 0 {
			mismatch("req_mem_bytes", fmt.Sprintf("is %s GB and the view says %s", gb.FloatString(3), row.ViewMemReqGB.Value))
		}
	}
	compareInt := func(field string, oursValue Value, view Int, scale int64) {
		switch {
		case !oursValue.Valid && !view.Valid:
		case oursValue.Valid != view.Valid:
			mismatch(field, fmt.Sprintf("null-ness differs from the view (ours %q, view %v)", cell(oursValue), view))
		default:
			got, err := strconv.ParseInt(oursValue.Text, 10, 64)
			if err != nil || got != view.Value*scale {
				mismatch(field, fmt.Sprintf("is %s and the view gives %d", oursValue.Text, view.Value*scale))
			}
		}
	}
	compareInt("req_walltime_s", n.Values["req_walltime_s"], row.ViewTimelimitMin, 60)
	compareInt("req_gpus", n.Values["req_gpus"], row.ViewGpusReq, 1)
	compareInt("req_nodes", n.Values["req_nodes"], row.ViewNodesReq, 1)
}

func (a *validationAudit) checks(rawRows int64) []Check {
	var unknown []string
	for flag := range a.unknownFlags {
		unknown = append(unknown, flag)
	}
	mismatches := int64(0)
	var parts []string
	for _, field := range []string{"req_mem_bytes", "req_walltime_s", "req_gpus", "req_nodes"} {
		mismatches += a.viewMismatch[field]
		parts = append(parts, fmt.Sprintf("%s %d", field, a.viewMismatch[field]))
	}
	return []Check{
		{Name: "normalized_rows_equal_raw_rows", Passed: a.rows == rawRows,
			Detail: fmt.Sprintf("%d normalized, %d raw", a.rows, rawRows)},
		{Name: "no_missing_value_became_a_number", Passed: a.zeroViolation == 0,
			Detail: fmt.Sprintf("%d values derived from a missing or unparseable source", a.zeroViolation)},
		{Name: "every_null_has_a_flag", Passed: a.unflaggedNull == 0,
			Detail: fmt.Sprintf("%d nulls without a flag in %s", a.unflaggedNull, strings.Join(nullNeedsFlag, ", "))},
		{Name: "every_flag_is_defined", Passed: len(unknown) == 0,
			Detail: "undefined flags: " + strings.Join(unknown, ", ")},
		{Name: "agrees_with_view", Passed: mismatches == 0,
			Detail: "disagreements with runTBL2_jobs: " + strings.Join(parts, ", ")},
	}
}

func hasFlag(n Normalized, field, flag string) bool {
	for _, f := range n.Flags[field] {
		if f == flag {
			return true
		}
	}
	return false
}

func isZeroDecimal(s string) bool {
	r, ok := new(big.Rat).SetString(s)
	return ok && r.Sign() == 0
}

// marshalManifest is used by tests that edit a manifest on disk.
func marshalManifest(m *Manifest) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.Encode(m)
	return buf.Bytes()
}
