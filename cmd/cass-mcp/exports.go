package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bindatype/cassandra/internal/export"
)

// The export tools are a thin wrapper: they authorize, start the
// deterministic exporter, and report its three outcomes as the manifest
// states them. No model is involved in an export.
const (
	exportToolName = "cass_export"
	statusToolName = "cass_export_status"
)

// ExportPermissions maps people to what they may export, from a file of
// lines "person export" or "person export,identify". Being on the question
// allowlist is not enough: exports are bulk job records.
type ExportPermissions struct {
	path    string
	mu      sync.Mutex
	modTime time.Time
	entries map[string]map[string]bool
}

func NewExportPermissions(path string) (*ExportPermissions, error) {
	p := &ExportPermissions{path: path}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.reloadLocked(); err != nil {
		return nil, err
	}
	return p, nil
}

// Allowed reports whether person holds permission ("export" or "identify").
func (p *ExportPermissions) Allowed(person, permission string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if info, err := os.Stat(p.path); err == nil && !info.ModTime().Equal(p.modTime) {
		p.reloadLocked()
	} else if err != nil {
		// A removed file revokes everyone, rather than leaving the last
		// version in force.
		p.entries = map[string]map[string]bool{}
	}
	return p.entries[person][permission]
}

func (p *ExportPermissions) reloadLocked() error {
	file, err := os.Open(p.path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	entries := map[string]map[string]bool{}
	scanner := bufio.NewScanner(file)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("%s line %d: want \"person export[,identify]\"", p.path, n)
		}
		person := strings.Join(fields[:len(fields)-1], " ")
		perms := map[string]bool{}
		for _, perm := range strings.Split(fields[len(fields)-1], ",") {
			switch perm {
			case "export", "identify":
				perms[perm] = true
			default:
				return fmt.Errorf("%s line %d: unknown permission %q", p.path, n, perm)
			}
		}
		if perms["identify"] && !perms["export"] {
			return fmt.Errorf("%s line %d: identify without export", p.path, n)
		}
		entries[person] = perms
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	p.entries, p.modTime = entries, info.ModTime()
	return nil
}

// ExportService runs exports for cass-mcp callers.
type ExportService struct {
	Definitions *export.Definitions
	Permissions *ExportPermissions
	Source      export.Source
	FS          export.FS
	Root        string
	Salt        []byte
	MaxRows     int64
	MaxRunning  int // exports running at once, across everyone
	Timeout     time.Duration
	Retention   time.Duration
	AuditPath   string
	ToolVersion string
	Log         io.Writer

	mu      sync.Mutex
	jobs    map[string]*exportJob
	running map[string]string // person -> export id
}

type exportJob struct {
	id       string
	owner    string
	started  time.Time
	rows     int64
	done     bool
	summary  *export.Summary
	failed   string
	finished time.Time
}

var exportIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$`)

// Start validates and authorizes a request and, if both pass, starts the
// export in the background. A refusal returns before anything is read.
func (e *ExportService) Start(caller Caller, raw json.RawMessage) map[string]any {
	if !e.Permissions.Allowed(caller.Person, "export") {
		return toolError("you do not have export permission; ask the Cassandra administrator. Questions (cass_ask) are unaffected")
	}
	req, err := export.DecodeRequest(raw)
	if err != nil {
		return refusal(err)
	}
	canIdentify := e.Permissions.Allowed(caller.Person, "identify")
	if _, err := e.Definitions.Validate(req, canIdentify); err != nil {
		e.audit(caller, "", req, "refused", err.Error(), nil)
		return refusal(err)
	}

	e.mu.Lock()
	if id, busy := e.running[caller.Person]; busy {
		e.mu.Unlock()
		return toolError("you already have export " + id + " running; check it with " + statusToolName)
	}
	// A long window is a full pass over runTBL2 on the production database
	// (the optimizer chooses a scan for June-September; EXPLAIN 2026-10-07,
	// about 20 s). One at a time keeps lucee from running several at once.
	if limit := e.MaxRunning; limit > 0 && len(e.running) >= limit {
		e.mu.Unlock()
		return toolError(fmt.Sprintf("%d export(s) already running, the most allowed at once; try again in a minute", len(e.running)))
	}
	id := export.NewExportID()
	job := &exportJob{id: id, owner: caller.Person, started: time.Now()}
	e.jobs[id] = job
	e.running[caller.Person] = id
	e.mu.Unlock()

	go e.run(caller, req, job, canIdentify)
	text := "Export " + id + " started. Call " + statusToolName + " with this export_id until it finishes; " +
		"nothing is complete until then, and nothing is verified until verify_export.py exits 0."
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": text}},
		"structuredContent": map[string]any{"export_id": id, "phase": "running"},
		"isError":           false,
	}
}

func (e *ExportService) run(caller Caller, req export.Request, job *exportJob, canIdentify bool) {
	ctx, cancel := context.WithTimeout(context.Background(), e.Timeout)
	defer cancel()
	m, _, err := export.Run(ctx, req, export.Options{
		Definitions: e.Definitions, Source: e.Source, FS: e.FS, Root: e.Root, Caller: caller.Person,
		CanIdentify: canIdentify, Salt: e.Salt, MaxRows: e.MaxRows, ToolVersion: e.ToolVersion,
		NewID:    func() string { return job.id },
		Progress: func(rows int64) { e.mu.Lock(); job.rows = rows; e.mu.Unlock() },
	})
	e.mu.Lock()
	job.done, job.finished = true, time.Now()
	delete(e.running, caller.Person)
	if err != nil {
		job.failed = err.Error()
	} else {
		summary := export.Summarize(m, "")
		job.summary = &summary
		job.rows = m.Raw.RowsWritten
	}
	e.mu.Unlock()
	outcome := "finished"
	if err != nil {
		outcome = "failed"
	}
	e.audit(caller, job.id, req, outcome, job.failed, m)
}

// Status reports an export to its owner: running, failed, or finished with
// the three outcomes and the download links.
func (e *ExportService) Status(caller Caller, raw json.RawMessage, host string) map[string]any {
	var args struct {
		ExportID string `json:"export_id"`
	}
	if err := json.Unmarshal(raw, &args); err != nil || !exportIDPattern.MatchString(args.ExportID) {
		return toolError("export_id is required, as returned by " + exportToolName)
	}
	e.mu.Lock()
	job, ok := e.jobs[args.ExportID]
	var snapshot exportJob
	if ok {
		snapshot = *job
	}
	e.mu.Unlock()
	if !ok {
		// Not started by this process: a finished export on disk still has
		// its manifest.
		m, err := e.manifest(args.ExportID)
		if err != nil || m.Caller != caller.Person {
			return toolError("no export " + args.ExportID + " of yours is known; it may have expired after the retention period")
		}
		summary := export.Summarize(m, "")
		snapshot = exportJob{id: args.ExportID, owner: m.Caller, done: true, summary: &summary}
	} else if snapshot.owner != caller.Person {
		return toolError("no export " + args.ExportID + " of yours is known; it may have expired after the retention period")
	}

	switch {
	case !snapshot.done:
		text := fmt.Sprintf("Export %s is running: %d rows so far. It is not complete; check again shortly.", snapshot.id, snapshot.rows)
		return result(text, map[string]any{"export_id": snapshot.id, "phase": "running", "rows_so_far": snapshot.rows})
	case snapshot.failed != "":
		text := "Export " + snapshot.id + " FAILED and produced nothing usable: " + snapshot.failed
		return map[string]any{
			"content":           []any{map[string]any{"type": "text", "text": text}},
			"structuredContent": map[string]any{"export_id": snapshot.id, "phase": "failed", "error": snapshot.failed},
			"isError":           true,
		}
	}
	s := snapshot.summary
	base := "https://" + host + "/exports/" + s.ExportID + "/"
	var urls []string
	for _, f := range s.Files {
		urls = append(urls, base+f)
	}
	text := fmt.Sprintf("Export %s finished (as of %s). raw: %s (%d rows). normalization: %s. fulfillment: %s.",
		s.ExportID, s.AsOf, s.Raw, s.RawRows, s.Normalization, s.Fulfillment)
	for _, reason := range []string{s.RawReason, s.NormReason, s.FulfillReason} {
		if reason != "" {
			text += " " + reason + "."
		}
	}
	text += " Download with your Cassandra key as a Bearer token. " + export.VerifyInstruction
	return result(text, map[string]any{"export_id": s.ExportID, "phase": "finished", "summary": s, "download_urls": urls})
}

// ServeFile serves one file of an export to its owner. Only names the
// manifest lists, and the manifest itself, are served.
func (e *ExportService) ServeFile(w http.ResponseWriter, r *http.Request, caller Caller) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/exports/"), "/")
	if len(parts) != 2 || !exportIDPattern.MatchString(parts[0]) || !e.Permissions.Allowed(caller.Person, "export") {
		http.NotFound(w, r)
		return
	}
	id, name := parts[0], parts[1]
	m, err := e.manifest(id)
	if err != nil || m.Caller != caller.Person {
		http.NotFound(w, r) // someone else's export is indistinguishable from none
		return
	}
	listed := name == export.ManifestFile
	for _, f := range m.Files {
		listed = listed || f.Name == name
	}
	if !listed {
		http.NotFound(w, r)
		return
	}
	file, err := os.Open(filepath.Join(e.Root, id, name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(w, r, name, time.Time{}, file)
	fmt.Fprintf(e.Log, "%s %s downloaded %s/%s\n", time.Now().UTC().Format(time.RFC3339), caller.Person, id, name)
}

func (e *ExportService) manifest(id string) (*export.Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(e.Root, id, export.ManifestFile))
	if err != nil {
		return nil, err
	}
	var m export.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Sweep deletes exports past the retention period and staging left by a
// crash. It runs at start and hourly.
func (e *ExportService) Sweep(now time.Time) {
	entries, err := os.ReadDir(e.Root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !entry.IsDir() {
			continue
		}
		limit := e.Retention
		if strings.HasPrefix(entry.Name(), ".staging-") {
			limit = 24 * time.Hour
		}
		if now.Sub(info.ModTime()) > limit {
			os.RemoveAll(filepath.Join(e.Root, entry.Name()))
			fmt.Fprintf(e.Log, "%s export %s removed after %s\n", now.UTC().Format(time.RFC3339), entry.Name(), limit)
		}
	}
	e.mu.Lock()
	for id, job := range e.jobs {
		if job.done && now.Sub(job.finished) > e.Retention {
			delete(e.jobs, id)
		}
	}
	e.mu.Unlock()
}

// audit appends one line per export decision: who, what, why, and how it ended.
func (e *ExportService) audit(caller Caller, id string, req export.Request, outcome, detail string, m *export.Manifest) {
	entry := map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "caller": caller.Person, "client": caller.Client,
		"export_id": id, "request": req, "purpose": req.Purpose, "outcome": outcome, "detail": detail,
	}
	if m != nil {
		entry["raw"], entry["normalization"], entry["fulfillment"] = m.Raw.State, m.Normalization.State, m.Fulfillment.State
		entry["rows"], entry["as_of"], entry["files"] = m.Raw.RowsWritten, m.AsOf, m.Files
	}
	line, _ := json.Marshal(entry)
	file, err := os.OpenFile(e.AuditPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintf(e.Log, "export audit: %v\n", err)
		return
	}
	defer file.Close()
	file.Write(append(line, '\n'))
}

func refusal(err error) map[string]any {
	var refused *export.RequestError
	if errors.As(err, &refused) {
		return map[string]any{
			"content":           []any{map[string]any{"type": "text", "text": "Refused; nothing was exported. " + err.Error()}},
			"structuredContent": map[string]any{"phase": "refused", "issues": refused.Issues},
			"isError":           true,
		}
	}
	return toolError(err.Error())
}

func result(text string, structured any) map[string]any {
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": text}},
		"structuredContent": structured,
		"isError":           false,
	}
}

// exportTools describes the two tools. The request schema is the contract:
// dates, never epochs, and only defined fields.
func exportTools(defs *export.Definitions) []any {
	var deliverable, unavailable []string
	for _, f := range defs.Fields {
		if f.Status == export.StatusNotRecorded {
			unavailable = append(unavailable, f.Name)
		} else {
			deliverable = append(deliverable, f.Name)
		}
	}
	date := map[string]any{"type": "string", "pattern": `^\d{4}-\d{2}-\d{2}$`}
	return []any{
		map[string]any{
			"name": exportToolName,
			"description": "Export Pegasus job resource requests to verifiable files. Deterministic: no model writes SQL or " +
				"interprets columns. Give whole dates and a time zone; the exporter computes the epochs. Fields are defined in " +
				"fields.json; " + strings.Join(unavailable, ", ") + " are not recorded and are refused unless allow_unavailable " +
				"is true, in which case they are omitted and listed. Returns an export_id; poll " + statusToolName + ". " +
				"The result reports raw extraction, normalization and fulfillment separately; an export is done only when " +
				"verify_export.py, shipped with it, exits 0. Requires export permission. Results are internal GW IT data, subject to GW data policy.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"source": map[string]any{"type": "string", "enum": []string{"pegasus"}},
					"window": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"start":    date,
							"end":      date,
							"timezone": map[string]any{"type": "string", "description": "IANA name, such as America/New_York"},
						},
						"required":             []string{"start", "end", "timezone"},
						"additionalProperties": false,
						"description":          "[start, end): whole days at midnight in timezone; end excluded.",
					},
					"fields": map[string]any{"type": "array", "items": map[string]any{"type": "string",
						"enum": append(append([]string{}, deliverable...), unavailable...)}, "minItems": 1},
					"deliver":           map[string]any{"type": "string", "enum": []string{"raw", "normalized"}},
					"identity":          map[string]any{"type": "string", "enum": []string{"pseudonymous", "netid"}},
					"allow_unavailable": map[string]any{"type": "boolean"},
					"purpose":           map[string]any{"type": "string", "description": "What the export is for; audited."},
				},
				"required":             []string{"source", "window", "fields", "deliver", "identity", "allow_unavailable", "purpose"},
				"additionalProperties": false,
			},
		},
		map[string]any{
			"name":        statusToolName,
			"description": "Report an export started with " + exportToolName + ": running, failed, or finished with its raw, normalization and fulfillment outcomes and download links.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{"export_id": map[string]any{"type": "string"}},
				"required":             []string{"export_id"},
				"additionalProperties": false,
			},
		},
	}
}
