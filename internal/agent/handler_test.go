package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCapabilitiesEndpoint(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHealthEndpointDoesNotRequireAuth(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestCapabilitiesEndpointRejectsMissingAuth(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatalf("expected WWW-Authenticate header")
	}
}

func TestCapabilitiesEndpointAcceptsRotatedToken(t *testing.T) {
	handler, _ := newTestHandlerWithConfig(t, func(cfg *Config) {
		cfg.AuthTokens = []string{"primary-token", "rotated-token"}
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	req.Header.Set("Authorization", "Bearer rotated-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestFilesystemListAllowsWorkspaceRoot(t *testing.T) {
	handler, tempDir := newTestHandler(t)

	body := `{
		"operation": "filesystem.list",
		"target": {"path": "` + filepath.ToSlash(filepath.Join(tempDir, "workspace")) + `"},
		"params": {"max_entries": 10}
	}`

	rec := performJSONRequest(t, handler, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"entries"`) {
		t.Fatalf("expected entries in response, got %s", rec.Body.String())
	}
}

func TestFilesystemReadBlocksTraversalOutsideAllowedRoot(t *testing.T) {
	handler, tempDir := newTestHandler(t)

	body := `{
		"operation": "filesystem.read",
		"target": {"path": "` + filepath.ToSlash(filepath.Join(tempDir, "outside.txt")) + `"},
		"params": {"max_bytes": 10}
	}`

	rec := performJSONRequest(t, handler, body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestFilesystemReadClampsExcessiveRead(t *testing.T) {
	handler, tempDir := newTestHandler(t)

	body := `{
		"operation": "filesystem.read",
		"target": {"path": "` + filepath.ToSlash(filepath.Join(tempDir, "workspace", "sample.txt")) + `"},
		"params": {"max_bytes": 999999}
	}`

	rec := performJSONRequest(t, handler, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var payload ResponseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Status != "ok" {
		t.Fatalf("expected ok, got %s", payload.Status)
	}
}

func TestMalformedJSONRejected(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/operations", bytes.NewBufferString(`{"operation":`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestMultipleJSONValuesRejected(t *testing.T) {
	handler, _ := newTestHandler(t)

	rec := performJSONRequest(t, handler, `{"operation":"host.info"} {"operation":"host.info"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOversizedRequestRejected(t *testing.T) {
	handler, root := newTestHandlerWithConfig(t, func(cfg *Config) {
		cfg.MaxRequestBytes = 48
	})

	body := `{"operation":"host.info","params":{"padding":"` + strings.Repeat("x", 64) + `"}}`
	rec := performJSONRequest(t, handler, body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"request_too_large"`) {
		t.Fatalf("expected request_too_large error, got %s", rec.Body.String())
	}
	audit, err := os.ReadFile(filepath.Join(root, "audit.log"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(audit), `"code":"request_too_large"`) {
		t.Fatalf("expected oversized request audit event, got %s", audit)
	}
}

func TestProcessListUsesConfiguredProcRootWithoutCommandLine(t *testing.T) {
	handler, _ := newTestHandler(t)

	body := `{"operation": "process.list"}`
	rec := performJSONRequest(t, handler, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"count"`) {
		t.Fatalf("expected count in response, got %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"cmdline"`) || strings.Contains(rec.Body.String(), "--flag") {
		t.Fatalf("process response disclosed command-line data: %s", rec.Body.String())
	}
}

func TestDisabledOperationIsNotAdvertisedOrExecutable(t *testing.T) {
	handler, _ := newTestHandlerWithConfig(t, func(cfg *Config) {
		cfg.EnabledOperations = []string{operationCapabilitiesDescribe, operationHostInfo}
	})

	rec := performJSONRequest(t, handler, `{"operation":"process.list"}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"operation_disabled"`) {
		t.Fatalf("expected disabled operation response, got %d body=%s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), operationProcessList) {
		t.Fatalf("disabled operation was advertised: %s", rec.Body.String())
	}
}

func TestCapabilitiesDescribeCanBeDisabled(t *testing.T) {
	handler, _ := newTestHandlerWithConfig(t, func(cfg *Config) {
		cfg.EnabledOperations = []string{operationHostInfo}
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"operation_disabled"`) {
		t.Fatalf("expected disabled operation response, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostInfoReturnsOnlyConfiguredFields(t *testing.T) {
	handler, _ := newTestHandlerWithConfig(t, func(cfg *Config) {
		cfg.HostInfoFields = []string{hostInfoArch}
	})

	rec := performJSONRequest(t, handler, `{"operation":"host.info"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var payload ResponseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, ok := payload.Data.(map[string]any)
	if !ok || len(data) != 1 || data[hostInfoArch] == nil {
		t.Fatalf("expected only arch host info, got %#v", payload.Data)
	}
	if strings.Contains(rec.Body.String(), "os_release_raw") {
		t.Fatalf("host info included unmanaged os-release data: %s", rec.Body.String())
	}
}

func TestFilesystemAuditIncludesCallerAndTarget(t *testing.T) {
	handler, root := newTestHandler(t)
	target := filepath.ToSlash(filepath.Join(root, "workspace", "sample.txt"))

	rec := performJSONRequest(t, handler, `{"operation":"filesystem.stat","target":{"path":"`+target+`"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	auditData, err := os.ReadFile(filepath.Join(root, "audit.log"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var event AuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(auditData), &event); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	if event.CallerID != credentialID("test-token") || event.TargetPath != target {
		t.Fatalf("unexpected audit identity or target: %+v", event)
	}
	if strings.Contains(string(auditData), "test-token") {
		t.Fatalf("audit log disclosed bearer token: %s", auditData)
	}
}

func TestAuditFailureWithholdsOperationResult(t *testing.T) {
	handler, _ := newTestHandlerWithRecorder(t, nil, failingAuditRecorder{})

	rec := performJSONRequest(t, handler, `{"operation":"host.info"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"audit_unavailable"`) || strings.Contains(rec.Body.String(), `"data"`) {
		t.Fatalf("expected withheld result, got %s", rec.Body.String())
	}
}

func TestAuditFailureWithholdsCapabilities(t *testing.T) {
	handler, _ := newTestHandlerWithRecorder(t, nil, failingAuditRecorder{})

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"audit_unavailable"`) || strings.Contains(rec.Body.String(), `"operations"`) {
		t.Fatalf("expected withheld capabilities, got %s", rec.Body.String())
	}
}

func newTestHandler(t *testing.T) (http.Handler, string) {
	return newTestHandlerWithConfig(t, nil)
}

func newTestHandlerWithConfig(t *testing.T, configure func(*Config)) (http.Handler, string) {
	return newTestHandlerWithRecorder(t, configure, nil)
}

func newTestHandlerWithRecorder(
	t *testing.T,
	configure func(*Config),
	recorder AuditRecorder,
) (http.Handler, string) {
	t.Helper()

	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	procRoot := filepath.Join(root, "proc")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(procRoot, "100"), 0o755); err != nil {
		t.Fatalf("mkdir proc pid: %v", err)
	}
	// A real /proc always has PID 1, and process.list refuses a view that
	// lacks it -- that absence is how a hidepid-restricted agent looking only
	// at its own processes gives itself away. A fixture without it would be
	// testing a state no host is ever in.
	if err := os.MkdirAll(filepath.Join(procRoot, "1"), 0o755); err != nil {
		t.Fatalf("mkdir proc pid 1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "1", "status"),
		[]byte("Name:\tsystemd\nState:\tS (sleeping)\nPPid:\t0\n"), 0o644); err != nil {
		t.Fatalf("write proc 1 status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "sample.txt"), []byte("hello world"), 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "outside.txt"), []byte("blocked"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	status := "Name:\ttestproc\nState:\tS (sleeping)\nPPid:\t1\n"
	if err := os.WriteFile(filepath.Join(procRoot, "100", "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write proc status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "100", "cmdline"), []byte("testproc\x00--flag\x00"), 0o644); err != nil {
		t.Fatalf("write proc cmdline: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "uptime"), []byte("42.5 10.0\n"), 0o644); err != nil {
		t.Fatalf("write proc uptime: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "version"), []byte("test kernel\n"), 0o644); err != nil {
		t.Fatalf("write proc version: %v", err)
	}

	cfg := Config{
		BindAddr:          ":0",
		AuthTokens:        []string{"test-token"},
		AllowedRoots:      []string{workspace},
		ProcRoot:          procRoot,
		EnabledOperations: allOperationsForTest(),
		HostInfoFields:    defaultHostInfoFields(),
		MaxRequestBytes:   1024,
		MaxReadBytes:      16,
		MaxTailBytes:      16,
		MaxListEntries:    8,
		MaxProcessEntries: 8,
		AuditPath:         filepath.Join(root, "audit.log"),
	}
	if configure != nil {
		configure(&cfg)
	}
	if recorder == nil {
		auditor, err := NewAuditor(cfg.AuditPath)
		if err != nil {
			t.Fatalf("new auditor: %v", err)
		}
		recorder = auditor
	}
	service := NewService(cfg, recorder)
	return NewHandler(service, cfg), root
}

type failingAuditRecorder struct{}

func (failingAuditRecorder) Record(AuditEvent) error {
	return errors.New("simulated audit failure")
}

func allOperationsForTest() []string {
	operations := make([]string, 0, len(operationCatalog))
	for _, capability := range operationCatalog {
		operations = append(operations, capability.Name)
	}
	return operations
}

func performJSONRequest(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/operations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
