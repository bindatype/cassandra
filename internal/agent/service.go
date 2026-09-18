package agent

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	agentName    = "cass-agent"
	agentVersion = "0.1.0"
)

type Service struct {
	cfg               Config
	auditor           AuditRecorder
	enabledOperations map[string]struct{}
	hostInfoFields    map[string]struct{}
}

func NewService(cfg Config, auditor AuditRecorder) *Service {
	cfg.AllowedRoots = canonicalizeRoots(cfg.AllowedRoots)
	return &Service{
		cfg:               cfg,
		auditor:           auditor,
		enabledOperations: nameSet(cfg.EnabledOperations),
		hostInfoFields:    nameSet(cfg.HostInfoFields),
	}
}

func (s *Service) Capabilities() CapabilitiesResponse {
	operations := make([]OperationCapability, 0, len(operationCatalog))
	for _, capability := range operationCatalog {
		if s.operationEnabled(capability.Name) {
			operations = append(operations, capability)
		}
	}
	return CapabilitiesResponse{
		Operations: operations,
		Limits: map[string]any{
			"allowed_roots":       s.cfg.AllowedRoots,
			"host_info_fields":    s.cfg.HostInfoFields,
			"max_read_bytes":      s.cfg.MaxReadBytes,
			"max_tail_bytes":      s.cfg.MaxTailBytes,
			"max_list_entries":    s.cfg.MaxListEntries,
			"max_process_entries": s.cfg.MaxProcessEntries,
			"process_cmdline":     false,
		},
	}
}

func (s *Service) Execute(ctx context.Context, req RequestEnvelope) (ResponseEnvelope, int) {
	start := time.Now().UTC()
	requestID := req.RequestID
	if requestID == "" {
		requestID = newRequestID()
	}

	resp := ResponseEnvelope{
		RequestID: requestID,
		Operation: req.Operation,
		Status:    "ok",
		Metadata: ResponseMeta{
			Timestamp: start.Format(time.RFC3339Nano),
			Agent:     agentName,
			Version:   agentVersion,
			Host:      selfHostname(),
		},
	}

	var (
		data      any
		truncated bool
		apiErr    *APIError
	)

	if _, known := knownOperations[req.Operation]; !known {
		apiErr = newAPIError(400, "unknown_operation", "operation is not supported")
	} else if !s.operationEnabled(req.Operation) {
		apiErr = newAPIError(403, "operation_disabled", "operation is disabled by agent policy")
	} else {
		switch req.Operation {
		case operationCapabilitiesDescribe:
			data = s.Capabilities()
		case operationHostInfo:
			data, truncated, apiErr = s.hostInfo()
		case operationFilesystemList:
			data, truncated, apiErr = s.filesystemList(req)
		case operationFilesystemStat:
			data, truncated, apiErr = s.filesystemStat(req)
		case operationFilesystemRead:
			data, truncated, apiErr = s.filesystemRead(req)
		case operationFilesystemTail:
			data, truncated, apiErr = s.filesystemTail(req)
		case operationProcessList:
			data, truncated, apiErr = s.processList()
		case operationHostUptime, operationHostDiskFree, operationHostNetwork,
			operationHostListeners, operationKernelMessages:
			data, truncated, apiErr = s.runCommandOperation(ctx, req.Operation)
		}
	}

	resp.Metadata.DurationMS = time.Since(start).Milliseconds()
	resp.Metadata.Truncated = truncated

	if apiErr != nil {
		resp.Status = "error"
		resp.Error = &ErrorPayload{
			Code:    apiErr.Code,
			Message: apiErr.Message,
		}
		return resp, apiErr.HTTPStatus
	}

	resp.Data = data
	return resp, 200
}

type pathTarget struct {
	Path string `json:"path"`
}

type listParams struct {
	MaxEntries int `json:"max_entries"`
}

type readParams struct {
	Offset   int64 `json:"offset"`
	MaxBytes int64 `json:"max_bytes"`
}

type processRecord struct {
	PID   int    `json:"pid"`
	PPID  int    `json:"ppid"`
	Name  string `json:"name"`
	State string `json:"state"`
}

func (s *Service) hostInfo() (any, bool, *APIError) {
	info := map[string]any{}
	if s.hostInfoFieldEnabled(hostInfoHostname) {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, false, newAPIError(500, "host_info_failed", "could not determine hostname")
		}
		info[hostInfoHostname] = hostname
	}
	if s.hostInfoFieldEnabled(hostInfoOS) {
		info[hostInfoOS] = runtime.GOOS
	}
	if s.hostInfoFieldEnabled(hostInfoArch) {
		info[hostInfoArch] = runtime.GOARCH
	}
	if s.hostInfoFieldEnabled(hostInfoCPUs) {
		info[hostInfoCPUs] = runtime.NumCPU()
	}
	if s.hostInfoFieldEnabled(hostInfoUptimeSeconds) {
		if uptime, ok := readProcUptime(s.cfg.ProcRoot); ok {
			info[hostInfoUptimeSeconds] = uptime
		}
	}
	if s.hostInfoFieldEnabled(hostInfoKernelVersion) {
		if version, ok := readTrimmedFile(filepath.Join(s.cfg.ProcRoot, "version")); ok {
			info[hostInfoKernelVersion] = version
		}
	}
	return info, false, nil
}

func (s *Service) filesystemList(req RequestEnvelope) (any, bool, *APIError) {
	target, params, apiErr := s.decodePathAndList(req)
	if apiErr != nil {
		return nil, false, apiErr
	}
	resolved, apiErr := s.resolveAllowedPath(target.Path)
	if apiErr != nil {
		return nil, false, apiErr
	}

	entries, err := os.ReadDir(resolved)
	if err != nil {
		if os.IsPermission(err) {
			return nil, false, newAPIError(403, "permission_denied", "could not read directory")
		}
		return nil, false, newAPIError(500, "list_failed", "could not read directory")
	}

	maxEntries := params.MaxEntries
	if maxEntries <= 0 || maxEntries > s.cfg.MaxListEntries {
		maxEntries = s.cfg.MaxListEntries
	}
	truncated := len(entries) > maxEntries
	entries = entries[:minInt(len(entries), maxEntries)]

	result := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		record := map[string]any{
			"name":     entry.Name(),
			"path":     filepath.Join(resolved, entry.Name()),
			"mode":     info.Mode().String(),
			"size":     info.Size(),
			"mod_time": info.ModTime().UTC().Format(time.RFC3339Nano),
			"type":     fileType(info.Mode()),
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			if link, err := os.Readlink(filepath.Join(resolved, entry.Name())); err == nil {
				record["symlink_target"] = link
			}
		}
		result = append(result, record)
	}

	return map[string]any{
		"path":    resolved,
		"entries": result,
	}, truncated, nil
}

func (s *Service) filesystemStat(req RequestEnvelope) (any, bool, *APIError) {
	var target pathTarget
	if err := decodeJSON(req.Target, &target); err != nil {
		return nil, false, newAPIError(400, "invalid_target", "target.path is required")
	}
	resolved, apiErr := s.resolveAllowedPath(target.Path)
	if apiErr != nil {
		return nil, false, apiErr
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, newAPIError(404, "not_found", "target path does not exist")
		}
		return nil, false, newAPIError(500, "stat_failed", "could not stat target path")
	}

	data := map[string]any{
		"path":     resolved,
		"mode":     info.Mode().String(),
		"size":     info.Size(),
		"mod_time": info.ModTime().UTC().Format(time.RFC3339Nano),
		"type":     fileType(info.Mode()),
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		if link, err := os.Readlink(resolved); err == nil {
			data["symlink_target"] = link
		}
	}
	return data, false, nil
}

func (s *Service) filesystemRead(req RequestEnvelope) (any, bool, *APIError) {
	target, params, apiErr := s.decodePathAndRead(req)
	if apiErr != nil {
		return nil, false, apiErr
	}
	resolved, apiErr := s.resolveAllowedPath(target.Path)
	if apiErr != nil {
		return nil, false, apiErr
	}

	if params.Offset < 0 {
		return nil, false, newAPIError(400, "invalid_params", "offset must be non-negative")
	}
	maxBytes := params.MaxBytes
	if maxBytes <= 0 || maxBytes > s.cfg.MaxReadBytes {
		maxBytes = s.cfg.MaxReadBytes
	}

	file, err := os.Open(resolved)
	if err != nil {
		if os.IsPermission(err) {
			return nil, false, newAPIError(403, "permission_denied", "could not read file")
		}
		return nil, false, newAPIError(500, "read_failed", "could not open file")
	}
	defer file.Close()

	if _, err := file.Seek(params.Offset, io.SeekStart); err != nil {
		return nil, false, newAPIError(400, "invalid_params", "offset could not be applied")
	}

	limitReader := io.LimitReader(file, maxBytes+1)
	content, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, false, newAPIError(500, "read_failed", "could not read file")
	}

	truncated := int64(len(content)) > maxBytes
	if truncated {
		content = content[:maxBytes]
	}

	return map[string]any{
		"path":       resolved,
		"offset":     params.Offset,
		"bytes_read": len(content),
		"content":    encodeContent(content),
	}, truncated, nil
}

func (s *Service) filesystemTail(req RequestEnvelope) (any, bool, *APIError) {
	target, params, apiErr := s.decodePathAndRead(req)
	if apiErr != nil {
		return nil, false, apiErr
	}
	resolved, apiErr := s.resolveAllowedPath(target.Path)
	if apiErr != nil {
		return nil, false, apiErr
	}

	maxBytes := params.MaxBytes
	if maxBytes <= 0 || maxBytes > s.cfg.MaxTailBytes {
		maxBytes = s.cfg.MaxTailBytes
	}

	file, err := os.Open(resolved)
	if err != nil {
		if os.IsPermission(err) {
			return nil, false, newAPIError(403, "permission_denied", "could not read file")
		}
		return nil, false, newAPIError(500, "tail_failed", "could not open file")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, false, newAPIError(500, "tail_failed", "could not stat file")
	}
	size := info.Size()
	offset := size - maxBytes
	if offset < 0 {
		offset = 0
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, false, newAPIError(500, "tail_failed", "could not seek file")
	}

	content, err := io.ReadAll(io.LimitReader(file, maxBytes))
	if err != nil {
		return nil, false, newAPIError(500, "tail_failed", "could not read file")
	}

	lines := []string{}
	if utf8.Valid(content) {
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
	}

	return map[string]any{
		"path":       resolved,
		"start":      offset,
		"bytes_read": len(content),
		"content":    encodeContent(content),
		"lines":      lines,
	}, offset > 0, nil
}

func (s *Service) processList() (any, bool, *APIError) {
	entries, err := os.ReadDir(s.cfg.ProcRoot)
	if err != nil {
		return nil, false, newAPIError(500, "process_list_failed", "could not read proc root")
	}

	records := make([]processRecord, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		record := processRecord{PID: pid}
		statusPath := filepath.Join(s.cfg.ProcRoot, entry.Name(), "status")
		if content, err := os.ReadFile(statusPath); err == nil {
			parseProcStatus(content, &record)
		}
		records = append(records, record)
	}

	// Measured on sgtstubby 2026-09-18: the deployed unit sets
	// ProtectProc=invisible, which mounts /proc with hidepid=invisible, and
	// the agent runs as a DynamicUser that owns almost nothing. The list that
	// comes back is then the agent's own two or three processes -- correctly
	// formed, plausibly short, and describing nothing about the machine.
	//
	// Refusing is the only honest answer. A caller cannot tell a quiet host
	// from a blindfolded agent, and this operation exists to answer questions
	// about the host.
	if restricted, reason := procVisibilityRestricted(s.cfg.ProcRoot, records); restricted {
		return nil, false, newAPIError(503, "process_view_restricted", reason)
	}

	sort.Slice(records, func(i, j int) bool { return records[i].PID < records[j].PID })
	truncated := len(records) > s.cfg.MaxProcessEntries
	if truncated {
		records = records[:s.cfg.MaxProcessEntries]
	}

	return map[string]any{
		"processes": records,
		"count":     len(records),
	}, truncated, nil
}

func (s *Service) decodePathAndList(req RequestEnvelope) (pathTarget, listParams, *APIError) {
	var target pathTarget
	var params listParams
	if err := decodeJSON(req.Target, &target); err != nil {
		return target, params, newAPIError(400, "invalid_target", "target.path is required")
	}
	if len(req.Params) > 0 {
		if err := decodeJSON(req.Params, &params); err != nil {
			return target, params, newAPIError(400, "invalid_params", "params are malformed")
		}
	}
	return target, params, nil
}

func (s *Service) decodePathAndRead(req RequestEnvelope) (pathTarget, readParams, *APIError) {
	var target pathTarget
	var params readParams
	if err := decodeJSON(req.Target, &target); err != nil {
		return target, params, newAPIError(400, "invalid_target", "target.path is required")
	}
	if len(req.Params) > 0 {
		if err := decodeJSON(req.Params, &params); err != nil {
			return target, params, newAPIError(400, "invalid_params", "params are malformed")
		}
	}
	return target, params, nil
}

func decodeJSON(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		return fmt.Errorf("missing payload")
	}
	return json.Unmarshal(raw, target)
}

func fileType(mode fs.FileMode) string {
	switch {
	case mode.IsDir():
		return "directory"
	case mode&fs.ModeSymlink != 0:
		return "symlink"
	default:
		return "file"
	}
}

func readTrimmedFile(path string) (string, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(content)), true
}

func readProcUptime(procRoot string) (float64, bool) {
	content, ok := readTrimmedFile(filepath.Join(procRoot, "uptime"))
	if !ok {
		return 0, false
	}
	parts := strings.Fields(content)
	if len(parts) == 0 {
		return 0, false
	}
	uptime, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0, false
	}
	return uptime, true
}

func parseProcStatus(content []byte, record *processRecord) {
	for _, line := range strings.Split(string(content), "\n") {
		switch {
		case strings.HasPrefix(line, "Name:"):
			record.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "State:"):
			record.State = strings.TrimSpace(strings.TrimPrefix(line, "State:"))
		case strings.HasPrefix(line, "PPid:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			if parsed, err := strconv.Atoi(value); err == nil {
				record.PPID = parsed
			}
		}
	}
}

func encodeContent(content []byte) map[string]any {
	if utf8.Valid(content) {
		return map[string]any{
			"format": "text/plain; charset=utf-8",
			"raw":    string(content),
		}
	}
	return map[string]any{
		"format": "application/octet-stream;base64",
		"raw":    base64.StdEncoding.EncodeToString(content),
	}
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func nameSet(names []string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}

func (s *Service) operationEnabled(operation string) bool {
	_, ok := s.enabledOperations[operation]
	return ok
}

func (s *Service) hostInfoFieldEnabled(field string) bool {
	_, ok := s.hostInfoFields[field]
	return ok
}

func canonicalizeRoots(roots []string) []string {
	canonical := make([]string, 0, len(roots))
	for _, root := range roots {
		resolved, err := filepath.EvalSymlinks(root)
		if err == nil {
			canonical = append(canonical, filepath.Clean(resolved))
			continue
		}
		canonical = append(canonical, filepath.Clean(root))
	}
	return canonical
}

// selfHostname reports this host's name for the response metadata.
//
// Resolved once and cached: it is asked for on every response, it does not
// change while the process runs, and a hostname lookup inside a request path
// is a syscall nobody budgeted for.
//
// An error yields the empty string rather than a failure. The identity is a
// cross-check, and a cross-check that can take the whole service down when it
// cannot run is a worse bargain than one that declines to answer -- the
// connector treats an unnamed host as unverifiable and says so.
var selfHostname = sync.OnceValue(func() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
})

// procVisibilityRestricted reports whether this agent is seeing only its own
// processes rather than the host's.
//
// PID 1 is the test. It always exists, it is always root's, and under
// hidepid=invisible a process belonging to another user is not merely
// unreadable but absent from the directory listing. So a scan that produced
// records and yet never saw PID 1 was looking at a filtered view.
//
// A scan that found nothing at all is a different failure and is reported as
// one, rather than being folded in here.
func procVisibilityRestricted(procRoot string, records []processRecord) (bool, string) {
	if len(records) == 0 {
		return true, "no processes were visible at all, which is not a state a running host can be in; " +
			"the proc root is unreadable or empty"
	}
	for _, record := range records {
		if record.PID == 1 {
			return false, ""
		}
	}
	return true, fmt.Sprintf(
		"PID 1 is not visible, so this agent is seeing only its own %d process(es), not the host's. "+
			"The unit sets ProtectProc=invisible (hidepid), which hides processes belonging to other "+
			"users. Reporting this list would describe the agent, not the machine. Dropping "+
			"ProtectProc=invisible is a deliberate privilege grant: it also exposes every process's "+
			"full command line", len(records))
}
