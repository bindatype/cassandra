package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunProducesBoundedLivePlan(t *testing.T) {
	policyPath := writeTestPolicy(t)
	stdin := strings.NewReader(`{"intent":"live.evidence","host":"docker-harness","resource":"system-log"}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"-policy", policyPath}, stdin, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected success, got %d: %s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"source": "cass-agent"`) ||
		!strings.Contains(stdout.String(), `"path": "/var/log/cass/system.log"`) {
		t.Fatalf("unexpected plan: %s", stdout.String())
	}
}

func TestRunRejectsModelSelectedPath(t *testing.T) {
	policyPath := writeTestPolicy(t)
	stdin := strings.NewReader(`{"intent":"live.evidence","host":"docker-harness","resource":"system-log","path":"/etc/shadow"}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"-policy", policyPath}, stdin, &stdout, &stderr)
	if exitCode == 0 || !strings.Contains(stderr.String(), "unknown field") {
		t.Fatalf("expected path rejection, got exit=%d stderr=%s", exitCode, stderr.String())
	}
}

func writeTestPolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	policy := `{
		"version": 1,
		"live_hosts": {
			"docker-harness": {"resources": ["system-log"]}
		},
		"resources": {
			"system-log": {
				"operation": "filesystem.tail",
				"path": "/var/log/cass/system.log",
				"params": {"max_bytes": 8192}
			}
		}
	}`
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}
