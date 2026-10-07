package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bindatype/cassandra/internal/export"
)

const aliceKey = "mr2_alice_test_key"

// memSource serves export rows from memory; block, when set, holds Rows until
// it is closed.
type memSource struct {
	rows  []export.SourceRow
	block chan struct{}
}

func (m *memSource) Snapshot(ctx context.Context) (export.Snapshot, error) { return m, nil }
func (m *memSource) AsOf() time.Time                                       { return time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC) }
func (m *memSource) Describe() export.SourceInfo {
	return export.SourceInfo{Relation: "runTBL2_jobs", Engine: "InnoDB"}
}
func (m *memSource) Query() string { return export.RowsQuery }
func (m *memSource) Close() error  { return nil }
func (m *memSource) Count(ctx context.Context, start, end int64) (int64, error) {
	return int64(len(m.rows)), nil
}
func (m *memSource) Rows(ctx context.Context, start, end int64, each func(export.SourceRow) error) error {
	if m.block != nil {
		<-m.block
	}
	for _, r := range m.rows {
		if err := each(r); err != nil {
			return err
		}
	}
	return nil
}

func sampleRows() []export.SourceRow {
	t := func(s string) export.Text { return export.Text{Value: s, Valid: true} }
	i := func(n int64) export.Int { return export.Int{Value: n, Valid: true} }
	row := export.SourceRow{JobID: t("73299647_1"), Netid: t("alice"), GroupName: t("physgrp"), SubmitTime: 1780286400,
		Partition: t("gpu"), State: t("COMPLETED"), ReqCPUS: i(4), TRESReqCPU: t("4"), TRESReqNode: t("1"),
		TRESReqGresGPU: t("1"), TRESReqMem: t("16G"), TimelimitRaw: t("30"),
		ViewMemReqGB: t("16.000"), ViewTimelimitMin: i(30), ViewGpusReq: i(1), ViewNodesReq: i(1)}
	second := row
	second.JobID, second.TRESReqGresGPU, second.TRESReqMem, second.ViewMemReqGB, second.ViewGpusReq = t("73299648"), t(""), t("512M"), t("0.500"), i(0)
	return []export.SourceRow{row, second}
}

const exportRequest = `{"source":"pegasus","window":{"start":"2026-06-01","end":"2026-10-01","timezone":"America/New_York"},` +
	`"fields":["job_id","researcher_key","submit_month","req_cpus","req_nodes","req_gpus","req_mem_raw","req_mem_bytes","quality_flags"],` +
	`"deliver":"normalized","identity":"pseudonymous","allow_unavailable":false,"purpose":"test"}`

// exportServer is a server with glen and alice on the question allowlist and
// the given export permissions.
func exportServer(t *testing.T, permissions string, source export.Source) (*Server, *ExportService) {
	t.Helper()
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "allowlist")
	os.WriteFile(allowlistPath, []byte(TokenHash(glenKey)+" glen\n"+TokenHash(aliceKey)+" alice\n"), 0o600)
	allowlist, err := NewAllowlist(allowlistPath)
	if err != nil {
		t.Fatal(err)
	}
	permsPath := filepath.Join(dir, "export-allowlist")
	os.WriteFile(permsPath, []byte(permissions), 0o600)
	perms, err := NewExportPermissions(permsPath)
	if err != nil {
		t.Fatal(err)
	}
	defs, err := export.LoadDefinitions()
	if err != nil {
		t.Fatal(err)
	}
	if source == nil {
		source = &memSource{rows: sampleRows()}
	}
	exports := &ExportService{
		Definitions: defs, Permissions: perms, Source: source, FS: export.OSFS{}, Root: filepath.Join(dir, "exports"),
		Salt: []byte("0123456789abcdef-salt"), MaxRows: 1000, MaxRunning: 1, Timeout: time.Minute, Retention: 14 * 24 * time.Hour,
		AuditPath: filepath.Join(dir, "export-audit.jsonl"), ToolVersion: "test", Log: io.Discard,
		jobs: map[string]*exportJob{}, running: map[string]string{},
	}
	server := NewServer(allowlist, func(context.Context, string) (bool, error) { return true, nil },
		func(context.Context, Caller, string) (Answer, error) { return Answer{}, nil }, 4, 2, io.Discard)
	server.exports = exports
	return server, exports
}

type toolResult struct {
	Result struct {
		IsError           bool            `json:"isError"`
		StructuredContent json.RawMessage `json:"structuredContent"`
		Content           []struct {
			Text string `json:"text"`
		} `json:"content"`
	} `json:"result"`
}

func callExportTool(t *testing.T, s *Server, key, name, arguments string) toolResult {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `}}`
	rec := rpc(t, s, key, "", body)
	var out toolResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v\n%s", name, err, rec.Body.String())
	}
	return out
}

func waitForExport(t *testing.T, s *Server, key, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out := callExportTool(t, s, key, statusToolName, `{"export_id":"`+id+`"}`)
		var status map[string]any
		json.Unmarshal(out.Result.StructuredContent, &status)
		if status["phase"] != "running" {
			return status
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("export did not finish")
	return nil
}

func download(t *testing.T, s *Server, key, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestExportsNeedTheirOwnPermission(t *testing.T) {
	s, exports := exportServer(t, "alice export\n", nil)
	out := callExportTool(t, s, glenKey, exportToolName, exportRequest)
	if !out.Result.IsError || !strings.Contains(out.Result.Content[0].Text, "export permission") {
		t.Errorf("glen, on the question allowlist only, was not refused: %+v", out.Result)
	}
	if entries, _ := os.ReadDir(exports.Root); len(entries) != 0 {
		t.Error("a refused caller's request created files")
	}
	netid := strings.Replace(exportRequest, `"pseudonymous"`, `"netid"`, 1)
	if out := callExportTool(t, s, aliceKey, exportToolName, netid); !out.Result.IsError ||
		!strings.Contains(out.Result.Content[0].Text, "identify permission") {
		t.Errorf("netids without the identify permission were not refused: %+v", out.Result)
	}
}

func TestARefusedRequestStartsNothingAndSaysWhy(t *testing.T) {
	s, exports := exportServer(t, "glen export\n", nil)
	gpuType := strings.Replace(exportRequest, `"quality_flags"]`, `"quality_flags","req_gpu_type"]`, 1)
	out := callExportTool(t, s, glenKey, exportToolName, gpuType)
	var refused struct {
		Phase  string         `json:"phase"`
		Issues []export.Issue `json:"issues"`
	}
	json.Unmarshal(out.Result.StructuredContent, &refused)
	if !out.Result.IsError || refused.Phase != "refused" || len(refused.Issues) != 1 || refused.Issues[0].Field != "req_gpu_type" {
		t.Errorf("an unavailable field was not refused with its reason: %+v", out.Result)
	}
	withEpoch := strings.Replace(exportRequest, `"purpose":"test"`, `"purpose":"test","start_epoch":1748736000`, 1)
	if out := callExportTool(t, s, glenKey, exportToolName, withEpoch); !out.Result.IsError {
		t.Error("a request carrying an epoch was accepted")
	}
	if entries, _ := os.ReadDir(exports.Root); len(entries) != 0 {
		t.Error("a refused request created files")
	}
	audit, _ := os.ReadFile(exports.AuditPath)
	if !strings.Contains(string(audit), `"outcome":"refused"`) {
		t.Errorf("the refusal was not audited: %s", audit)
	}
}

// The whole path: start, poll, download over HTTPS with the caller's key,
// then the shipped verifier. This is the completion rule Hermes follows.
func TestAnExportCanBeStartedDownloadedAndVerified(t *testing.T) {
	s, exports := exportServer(t, "glen export\nalice export\n", nil)
	started := callExportTool(t, s, glenKey, exportToolName, exportRequest)
	var start map[string]any
	json.Unmarshal(started.Result.StructuredContent, &start)
	id, _ := start["export_id"].(string)
	if started.Result.IsError || id == "" {
		t.Fatalf("start: %+v", started.Result)
	}
	status := waitForExport(t, s, glenKey, id)
	summary, _ := status["summary"].(map[string]any)
	if status["phase"] != "finished" || summary["raw"] != export.RawComplete ||
		summary["normalization"] != export.NormValidated || summary["fulfillment"] != export.Fulfilled {
		t.Fatalf("status %v", status)
	}

	local := t.TempDir()
	urls, _ := status["download_urls"].([]any)
	for _, u := range urls {
		path := strings.TrimPrefix(u.(string), "https://example.com")
		rec := download(t, s, glenKey, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("download %s: %d %s", path, rec.Code, rec.Body.String())
		}
		os.WriteFile(filepath.Join(local, filepath.Base(path)), rec.Body.Bytes(), 0o600)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	out, err := exec.Command(python, filepath.Join(local, export.VerifierFile), local).CombinedOutput()
	if err != nil {
		t.Errorf("the downloaded export does not verify: %v\n%s", err, out)
	}

	// Only the owner, only listed files, only with a key.
	raw := "/exports/" + id + "/" + export.RawFile
	for name, check := range map[string]struct {
		key, path string
		want      int
	}{
		"another person's export": {aliceKey, raw, http.StatusNotFound},
		"no key":                  {"", raw, http.StatusUnauthorized},
		"an unlisted file":        {glenKey, "/exports/" + id + "/secrets.txt", http.StatusNotFound},
		"path traversal":          {glenKey, "/exports/" + id + "/../../export-allowlist", http.StatusNotFound},
		"a made-up export":        {glenKey, "/exports/20260101T000000Z-000000000000/" + export.RawFile, http.StatusNotFound},
	} {
		if rec := download(t, s, check.key, check.path); rec.Code != check.want {
			t.Errorf("%s: %d, want %d", name, rec.Code, check.want)
		}
	}
	other := callExportTool(t, s, aliceKey, statusToolName, `{"export_id":"`+id+`"}`)
	if !other.Result.IsError {
		t.Error("another person could read the export's status")
	}

	// Status still works from disk after a restart forgets the job.
	exports.mu.Lock()
	exports.jobs = map[string]*exportJob{}
	exports.mu.Unlock()
	if again := waitForExport(t, s, glenKey, id); again["phase"] != "finished" {
		t.Errorf("after a restart the status is %v", again)
	}
	audit, _ := os.ReadFile(exports.AuditPath)
	if !strings.Contains(string(audit), `"fulfillment":"fulfilled"`) {
		t.Errorf("the export's outcome was not audited: %s", audit)
	}
}

func TestOneRunningExportPerPerson(t *testing.T) {
	block := make(chan struct{})
	s, _ := exportServer(t, "glen export\n", &memSource{rows: sampleRows(), block: block})
	first := callExportTool(t, s, glenKey, exportToolName, exportRequest)
	second := callExportTool(t, s, glenKey, exportToolName, exportRequest)
	close(block)
	if first.Result.IsError || !second.Result.IsError || !strings.Contains(second.Result.Content[0].Text, "already have") {
		t.Errorf("first %+v, second %+v", first.Result, second.Result)
	}
	var start map[string]any
	json.Unmarshal(first.Result.StructuredContent, &start)
	waitForExport(t, s, glenKey, start["export_id"].(string))
}

func TestAFailedExportIsReportedAsFailed(t *testing.T) {
	s, exports := exportServer(t, "glen export\n", nil)
	os.WriteFile(exports.Root, []byte("a file where the export root should be"), 0o600)
	started := callExportTool(t, s, glenKey, exportToolName, exportRequest)
	var start map[string]any
	json.Unmarshal(started.Result.StructuredContent, &start)
	status := waitForExport(t, s, glenKey, start["export_id"].(string))
	if status["phase"] != "failed" || status["error"] == "" {
		t.Errorf("status %v, want failed with the error", status)
	}
}

func TestSweepRemovesExpiredExportsAndAbandonedStaging(t *testing.T) {
	_, exports := exportServer(t, "glen export\n", nil)
	now := time.Now()
	for name, age := range map[string]time.Duration{
		"20260901T000000Z-aaaaaaaaaaaa": 15 * 24 * time.Hour,
		"20261006T000000Z-bbbbbbbbbbbb": 24 * time.Hour,
		".staging-x-1":                  25 * time.Hour,
		".staging-y-2":                  time.Hour,
	} {
		dir := filepath.Join(exports.Root, name)
		os.MkdirAll(dir, 0o700)
		os.Chtimes(dir, now.Add(-age), now.Add(-age))
	}
	exports.Sweep(now)
	entries, _ := os.ReadDir(exports.Root)
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if strings.Join(left, " ") != ".staging-y-2 20261006T000000Z-bbbbbbbbbbbb" {
		t.Errorf("left %v; want the expired export and the day-old staging removed", left)
	}
}

func TestExportPermissionsFileIsStrict(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{"glen\n", "glen exports\n", "glen identify\n"} {
		path := filepath.Join(dir, "p")
		os.WriteFile(path, []byte(body), 0o600)
		if _, err := NewExportPermissions(path); err == nil {
			t.Errorf("%q was accepted", body)
		}
	}
	path := filepath.Join(dir, "ok")
	os.WriteFile(path, []byte("# comment\nGlen Mac export,identify\n"), 0o600)
	perms, err := NewExportPermissions(path)
	if err != nil || !perms.Allowed("Glen Mac", "identify") {
		t.Fatalf("%v %v", perms, err)
	}
	os.Remove(path)
	if perms.Allowed("Glen Mac", "export") {
		t.Error("removing the file did not revoke permissions")
	}
}

func TestTheExportToolTakesDatesNotEpochs(t *testing.T) {
	defs, _ := export.LoadDefinitions()
	tools := exportTools(defs)
	schema := tools[0].(map[string]any)["inputSchema"].(map[string]any)
	properties := schema["properties"].(map[string]any)
	for name := range properties {
		if strings.Contains(name, "epoch") {
			t.Errorf("the request schema has %s; epochs are the exporter's to compute", name)
		}
	}
	window := properties["window"].(map[string]any)
	if window["additionalProperties"] != false || schema["additionalProperties"] != false {
		t.Error("the schema accepts keys it does not define")
	}
	raw, _ := json.Marshal(tools)
	if !strings.Contains(string(raw), "verify_export.py") || !strings.Contains(string(raw), "req_gpu_type") {
		t.Error("the tool description does not state the completion rule and the unavailable fields")
	}
	s, _ := testServer(t, nil)
	rec := rpc(t, s, glenKey, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if strings.Contains(rec.Body.String(), exportToolName) {
		t.Error("export tools are listed on a server without exports configured")
	}
}

// A long export is a full pass over runTBL2 on lucee, so only one runs at a
// time across everyone, not just per person.
func TestOneRunningExportAcrossEveryone(t *testing.T) {
	block := make(chan struct{})
	s, _ := exportServer(t, "glen export\nalice export\n", &memSource{rows: sampleRows(), block: block})
	first := callExportTool(t, s, glenKey, exportToolName, exportRequest)
	second := callExportTool(t, s, aliceKey, exportToolName, exportRequest)
	close(block)
	if first.Result.IsError || !second.Result.IsError || !strings.Contains(second.Result.Content[0].Text, "most allowed at once") {
		t.Errorf("first %+v, second %+v", first.Result, second.Result)
	}
	var start map[string]any
	json.Unmarshal(first.Result.StructuredContent, &start)
	waitForExport(t, s, glenKey, start["export_id"].(string))
	third := callExportTool(t, s, aliceKey, exportToolName, exportRequest)
	if third.Result.IsError {
		t.Fatalf("after the first finished, the next was still refused: %+v", third.Result)
	}
	json.Unmarshal(third.Result.StructuredContent, &start)
	waitForExport(t, s, aliceKey, start["export_id"].(string))
}
