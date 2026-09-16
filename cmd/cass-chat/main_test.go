package main

import (
	"bytes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The example policy is the one `ask` falls back to, so testing against it also
// checks that the shipped default still loads.
func examplePolicy(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "configs", "broker-policy.example.json")
}

// clearEnv removes every variable buildSession reads, so a test does not pass
// or fail because of what happens to be exported on the machine running it.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		mindrouterEndpointEnv, mindrouterKeyEnv, mindrouterModelEnv,
		zabbixEndpointEnv, zabbixTokenEnv,
		wazuhEndpointEnv, wazuhUsernameEnv, wazuhPasswordEnv, wazuhCriticalGroupsEnv,
		pegasusDSNEnv, pegasusMaxRowsEnv, pegasusMaxBytesEnv, auditPathEnv,
		rtEndpointEnv, rtTokenEnv, rtQueuesEnv, cassAgentConfigEnv,
	} {
		t.Setenv(name, "")
	}
}

func TestConfiguredModel(t *testing.T) {
	t.Setenv(mindrouterModelEnv, "")
	if got := configuredModel(); got != defaultModel {
		t.Fatalf("configuredModel() = %q without an override, want %q", got, defaultModel)
	}

	t.Setenv(mindrouterModelEnv, "default-agent")
	if got := configuredModel(); got != "default-agent" {
		t.Fatalf("configuredModel() = %q with an override, want default-agent", got)
	}
}

// The operator-facing failures: what a person sees when the invocation is
// wrong. Each asserts the exit status and that the message names the thing
// that is actually missing -- "-policy is required" was printed for a missing
// -model until this test existed.
func TestRunRejectsBadInvocations(t *testing.T) {
	policy := examplePolicy(t)
	tests := []struct {
		name   string
		args   []string
		stdin  string
		env    map[string]string
		status int
		says   string
	}{
		{
			name:   "no policy",
			args:   []string{"what is broken?"},
			status: 2,
			says:   "-policy is required",
		},
		{
			name:   "empty model",
			args:   []string{"-policy", policy, "-model", "", "what is broken?"},
			status: 2,
			says:   "-model",
		},
		{
			name:   "unknown flag",
			args:   []string{"-policy", policy, "-nonsense"},
			status: 2,
		},
		{
			name:   "no question in args or stdin",
			args:   []string{"-policy", policy},
			stdin:  "   \n",
			status: 2,
			says:   "no question supplied",
		},
		{
			name:   "unreadable policy",
			args:   []string{"-policy", filepath.Join(t.TempDir(), "absent.json"), "what is broken?"},
			status: 2,
			says:   "open policy",
		},
		{
			// Reached only after the question is resolved, so this also proves
			// the stdin path works: the question came from stdin, not args.
			name:   "no mindrouter endpoint",
			args:   []string{"-policy", policy},
			stdin:  "what is broken?",
			status: 2,
			says:   mindrouterEndpointEnv,
		},
		{
			name:   "endpoint without an api key",
			args:   []string{"-policy", policy, "what is broken?"},
			env:    map[string]string{mindrouterEndpointEnv: "http://mindrouter.invalid"},
			status: 2,
			says:   mindrouterKeyEnv,
		},
		{
			// A key and an endpoint are not enough: with no data source the
			// session can only answer from the model, which is the one thing
			// this project exists to prevent.
			name: "no connectors configured",
			args: []string{"-policy", policy, "what is broken?"},
			env: map[string]string{
				mindrouterEndpointEnv: "http://mindrouter.invalid",
				mindrouterKeyEnv:      "test-key",
			},
			status: 2,
			says:   "no connectors configured",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearEnv(t)
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			var stdout, stderr bytes.Buffer
			status := run(test.args, strings.NewReader(test.stdin), &stdout, &stderr)
			if status != test.status {
				t.Fatalf("status = %d, want %d (stderr: %s)", status, test.status, stderr.String())
			}
			if test.says != "" && !strings.Contains(stderr.String(), test.says) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr.String(), test.says)
			}
			if stdout.Len() != 0 {
				t.Fatalf("a failed run wrote to stdout: %q", stdout.String())
			}
		})
	}
}

func TestSplitList(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"RTS_Ops", []string{"RTS_Ops"}},
		{"RTS_Ops,Viper", []string{"RTS_Ops", "Viper"}},
		// A trailing comma or a stray space must not become a group name that
		// matches no agent and silently narrows escalation to nothing.
		{"RTS_Ops, Viper,", []string{"RTS_Ops", "Viper"}},
		{",,", nil},
	}
	for _, test := range tests {
		if got := splitList(test.in); !reflect.DeepEqual(got, test.want) {
			t.Errorf("splitList(%q) = %#v, want %#v", test.in, got, test.want)
		}
	}
}

// Both caps fall back to the connector default -- signalled by 0 -- rather than
// to a value of their own, so a typo in the environment cannot quietly raise a
// budget. Anything unparseable, negative, or zero means "use the default".
func TestPegasusCapOverrides(t *testing.T) {
	tests := []struct {
		value string
		want  int
	}{
		{"", 0},
		{"not-a-number", 0},
		{"0", 0},
		{"-5", 0},
		{"250", 250},
	}
	for _, test := range tests {
		t.Run("rows/"+test.value, func(t *testing.T) {
			t.Setenv(pegasusMaxRowsEnv, test.value)
			if got := pegasusMaxRows(); got != test.want {
				t.Fatalf("pegasusMaxRows(%q) = %d, want %d", test.value, got, test.want)
			}
		})
		t.Run("bytes/"+test.value, func(t *testing.T) {
			t.Setenv(pegasusMaxBytesEnv, test.value)
			if got := pegasusMaxBytes(); got != test.want {
				t.Fatalf("pegasusMaxBytes(%q) = %d, want %d", test.value, got, test.want)
			}
		})
	}
}

// TestHalfConfiguredSourceIsRefused pins the failure that cost an afternoon on
// 2026-09-02. RT was compiled in and unconfigured; the connector was skipped
// without a word, the intent was withheld from the tool schema, and the model
// reported RT as "currently unavailable" -- which reads as an outage. The
// cause was three unset environment variables.
//
// An endpoint set without its credential is not a choice to disable a source.
// It is a mistake, and it now names the variable.
func TestHalfConfiguredSourceIsRefused(t *testing.T) {
	t.Setenv(mindrouterKeyEnv, "test-key")
	t.Setenv(rtTokenEnv, "")

	_, err := buildSession("../../configs/broker-policy.example.json", "m", "http://localhost:8000",
		"", "", "https://rt.example.edu", false, false)
	if err == nil {
		t.Fatal("an RT endpoint with no token must be refused, not silently skipped")
	}
	if !strings.Contains(err.Error(), rtTokenEnv) {
		t.Errorf("the error must name the missing variable; got %q", err)
	}
}

// TestUnconfiguredSourcesNameTheirVariables asserts the note that would have
// answered the question immediately: which sources are off, and what turns
// them on. A source that is absent is indistinguishable from one that is
// broken unless something says so.
func TestUnconfiguredSourcesNameTheirVariables(t *testing.T) {
	t.Setenv(pegasusDSNEnv, "")
	t.Setenv(cassAgentConfigEnv, "")
	off := strings.Join(unconfiguredSources("", "", ""), "; ")

	for _, name := range []string{
		zabbixEndpointEnv, wazuhEndpointEnv, pegasusDSNEnv,
		rtEndpointEnv, rtTokenEnv, rtQueuesEnv,
		cassAgentConfigEnv,
	} {
		if !strings.Contains(off, name) {
			t.Errorf("the note does not name %s, so nobody learns to set it: %q", name, off)
		}
	}

	// A configured source must not be reported as off.
	if got := unconfiguredSources("https://zabbix.example.edu", "", ""); strings.Contains(strings.Join(got, "; "), zabbixEndpointEnv) {
		t.Errorf("a configured source was reported unconfigured: %q", got)
	}
}

func TestEndpointAgentConfigurationOffersLiveEvidence(t *testing.T) {
	clearEnv(t)
	t.Setenv(mindrouterKeyEnv, "test-key")
	t.Setenv(cassAgentConfigEnv, `{
		"docker-harness": {
			"endpoint": "http://127.0.0.1:18081",
			"token": "agent-token"
		}
	}`)

	session, err := buildSession(examplePolicy(t), "test-model", "http://localhost:8000", "", "", "", false, false)
	if err != nil {
		t.Fatalf("buildSession() error = %v", err)
	}
	if !contains(session.Intents(), "live.evidence") {
		t.Errorf("intents = %q, want live.evidence when an agent is configured", session.Intents())
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
