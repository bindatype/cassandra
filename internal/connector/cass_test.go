package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/agent"
	"github.com/bindatype/cassandra/internal/broker"
)

func TestCassConnectorExecutesOnlyTheApprovedStep(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "system.log")
	if err := os.WriteFile(logPath, []byte("first line\nlast line\n"), 0o600); err != nil {
		t.Fatalf("write agent fixture: %v", err)
	}
	resolvedLogPath, err := filepath.EvalSymlinks(logPath)
	if err != nil {
		t.Fatalf("resolve agent fixture: %v", err)
	}
	auditor := &recordingAgentAuditor{}
	cfg := agent.Config{
		AuthTokens:        []string{"endpoint-token"},
		AllowedRoots:      []string{root},
		EnabledOperations: []string{"filesystem.tail"},
		MaxRequestBytes:   65536,
		MaxTailBytes:      10,
	}
	server := httptest.NewServer(agent.NewHandler(agent.NewService(cfg, auditor), cfg))
	defer server.Close()

	connector := newTestCass(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source:    broker.SourceCass,
		Action:    "operations.execute",
		Host:      testHost(t),
		Operation: "filesystem.tail",
		Target:    &broker.OperationTarget{Path: logPath},
		Params:    &broker.OperationParams{MaxBytes: 1024},
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if evidence.Source != string(broker.SourceCass) || evidence.Action != "operations.execute" {
		t.Errorf("provenance = %s %s", evidence.Source, evidence.Action)
	}
	if !evidence.Truncated {
		t.Error("agent truncation status must reach evidence")
	}
	data, ok := evidence.Data.(map[string]any)
	if !ok || data["path"] != resolvedLogPath {
		t.Errorf("Data = %#v", evidence.Data)
	}
	if len(auditor.events) != 1 || auditor.events[0].TargetPath != logPath {
		t.Errorf("agent audit = %#v, want one event for %s", auditor.events, logPath)
	}
}

type recordingAgentAuditor struct {
	events []agent.AuditEvent
}

func (a *recordingAgentAuditor) Record(event agent.AuditEvent) error {
	a.events = append(a.events, event)
	return nil
}

func TestCassConnectorRefusesAnUnconfiguredHost(t *testing.T) {
	connector := newTestCass(t, "http://127.0.0.1:8080")
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source:    broker.SourceCass,
		Action:    "operations.execute",
		Host:      "other.example.edu",
		Operation: "filesystem.read",
		Target:    &broker.OperationTarget{Path: "/workspace/sample.txt"},
	})
	if err == nil || !strings.Contains(err.Error(), "host_not_configured") {
		t.Fatalf("error = %v, want host_not_configured", err)
	}
}

func TestCassConnectorDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		if r.Header.Get("Authorization") != "" {
			t.Error("bearer token reached redirect target")
		}
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	connector := newTestCass(t, redirector.URL)
	_, err := connector.Execute(context.Background(), validCassStep(t))
	if err == nil || !strings.Contains(err.Error(), "agent_error") {
		t.Fatalf("error = %v, want redirect refusal", err)
	}
	if redirected {
		t.Error("connector followed an agent-controlled redirect")
	}
}

func TestCassConnectorRejectsUnsafeEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"http://agent.example.edu:8080",
		"https://agent.example.edu/v1/operations",
		"https://agent.example.edu/?override=true",
	} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := NewCassConnector(CassConfig{Agents: map[string]CassAgentConfig{
				"sgtstubby.arc.gwu.edu": {Endpoint: endpoint, Token: "token"},
			}})
			if err == nil {
				t.Fatal("unsafe endpoint was accepted")
			}
		})
	}
}

func TestParseCassAgentsRejectsUnknownFields(t *testing.T) {
	_, err := ParseCassAgents(`{"sgtstubby.arc.gwu.edu":{"endpoint":"https://agent.example.edu","token":"t","extra":true}}`)
	if err == nil {
		t.Fatal("unknown configuration field was accepted")
	}
}

// testHost is the name these fixtures address.
//
// It is this machine's hostname, not a plausible-looking one, because the
// fixtures run a REAL agent over httptest and that agent reports where it
// actually is. Addressing it as sgtstubby made every one of these tests a
// host mismatch the moment the identity check existed -- correctly, which is
// the point: a fake agent claiming to be a production host is exactly what the
// check refuses.
func testHost(t *testing.T) string {
	t.Helper()
	name, err := os.Hostname()
	if err != nil {
		t.Fatalf("hostname: %v", err)
	}
	return name
}

func newTestCass(t *testing.T, endpoint string) *CassConnector {
	t.Helper()
	connector, err := NewCassConnector(CassConfig{Agents: map[string]CassAgentConfig{
		testHost(t): {Endpoint: endpoint, Token: "endpoint-token"},
	}})
	if err != nil {
		t.Fatalf("NewCassConnector() error = %v", err)
	}
	return connector
}

func validCassStep(t *testing.T) broker.RouteStep {
	t.Helper()
	return broker.RouteStep{
		Source:    broker.SourceCass,
		Action:    "operations.execute",
		Host:      testHost(t),
		Operation: "filesystem.read",
		Target:    &broker.OperationTarget{Path: "/workspace/sample.txt"},
		Params:    &broker.OperationParams{MaxBytes: 128},
	}
}

// TestCassEvidenceCarriesComputedCounts pins the rule every other connector
// already follows: a population figure is computed here, in code, never left
// for a model to tally off the rows.
//
// The endpoint connector arrived without it. Data is the right shape for a
// directory listing -- re-encoding it into synthetic rows would obscure what
// an operator asked for -- but it reached the model as a raw array alongside a
// prompt rule forbidding the model to count arrays, which leaves no way to
// answer "how many" that is not either a refusal or a violation.
func TestCassEvidenceCarriesComputedCounts(t *testing.T) {
	tests := []struct {
		operation string
		data      map[string]any
		wantKey   string
		wantValue int
		wantItems int
	}{
		{"filesystem.list", map[string]any{"path": "/workspace",
			"entries": []any{map[string]any{"name": "a"}, map[string]any{"name": "b"}, map[string]any{"name": "c"}}},
			"entries", 3, 3},
		{"process.list", map[string]any{
			"processes": []any{map[string]any{"pid": 1}, map[string]any{"pid": 2}},
			"count":     float64(2)},
			"processes", 2, 2},
		{"filesystem.read", map[string]any{"path": "/var/log/x", "bytes_read": float64(5),
			"content": map[string]any{"format": "text/plain; charset=utf-8", "raw": "hello"}},
			"bytes", 5, 0},
	}

	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			summary, items, warnings := summarizeAgentData(test.operation, test.data)
			if summary[test.wantKey] != test.wantValue {
				t.Errorf("summary[%q] = %d, want %d", test.wantKey, summary[test.wantKey], test.wantValue)
			}
			if items != test.wantItems {
				t.Errorf("item count = %d, want %d", items, test.wantItems)
			}
			if len(warnings) != 0 {
				t.Errorf("unexpected warnings on well-formed data: %v", warnings)
			}
		})
	}
}

// TestCassCountsAreMeasuredNotBelieved asserts the agent's own figure is
// checked rather than copied. An agent that miscounts is a defect worth
// naming, and copying its number would launder that defect into evidence.
func TestCassCountsAreMeasuredNotBelieved(t *testing.T) {
	summary, _, warnings := summarizeAgentData("process.list", map[string]any{
		"processes": []any{map[string]any{"pid": 1}, map[string]any{"pid": 2}},
		"count":     float64(97),
	})
	if summary["processes"] != 2 {
		t.Errorf("summary reported %d processes; the two that arrived are what exists", summary["processes"])
	}
	if len(warnings) == 0 {
		t.Fatal("the agent claimed 97 processes and sent 2, and nothing said so")
	}
	if !strings.Contains(warnings[0], "97") || !strings.Contains(warnings[0], "2") {
		t.Errorf("the warning must name both figures so a reader can see the disagreement; got %q", warnings[0])
	}
}

// TestCassUncountableDataWarns asserts that evidence supporting no
// population claim says so. A count that was never computed is not zero, and
// every mechanism in this project that expressed that by omission has been
// read the reassuring way.
func TestCassUncountableDataWarns(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation string
		data      any
	}{
		{"unknown operation", "filesystem.newthing", map[string]any{"whatever": 1}},
		{"data is not an object", "filesystem.list", []any{"a", "b"}},
		{"entries missing", "filesystem.list", map[string]any{"path": "/x"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, warnings := summarizeAgentData(test.operation, test.data)
			if len(warnings) == 0 {
				t.Error("evidence that supports no population claim returned no warning saying so")
			}
		})
	}
}

// TestCassKeepsHostsIsolated asserts the property the per-host token design
// exists for: a step for one host reaches that host's endpoint with that
// host's token, and never another's. Every other test here configures a single
// agent, so the claim in Execute's comment had nothing behind it.
func TestCassKeepsHostsIsolated(t *testing.T) {
	type seen struct{ auth, path string }
	got := map[string]seen{}

	// Each stand-in names itself, as a real agent does on every response. The
	// connector refuses an answer from a host other than the one addressed, so
	// a stand-in that reported nothing would be rejected before this test
	// could observe which token it received.
	mk := func(name, host string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got[name] = seen{auth: r.Header.Get("Authorization"), path: r.URL.Path}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"request_id":"1","operation":"filesystem.list","status":"ok",
				"metadata":{"truncated":false,"host":%q},"data":{"path":"/workspace","entries":[]}}`, host)
		}))
	}
	alpha, beta := mk("alpha", "alpha.example.edu"), mk("beta", "beta.example.edu")
	defer alpha.Close()
	defer beta.Close()

	rt, err := NewCassConnector(CassConfig{Agents: map[string]CassAgentConfig{
		"alpha.example.edu": {Endpoint: alpha.URL, Token: "token-for-alpha"},
		"beta.example.edu":  {Endpoint: beta.URL, Token: "token-for-beta"},
	}})
	if err != nil {
		t.Fatalf("build connector: %v", err)
	}

	// Both directions, because one is not enough: resolving to "whichever
	// agent the map yields first" passes a single-host check whenever the map
	// happens to yield the right one. Measured at 2 detections in 7 runs
	// before this loop existed. Exercising both hosts fails under either
	// iteration order.
	for _, host := range []string{"alpha.example.edu", "beta.example.edu"} {
		for k := range got {
			delete(got, k)
		}
		step := broker.RouteStep{
			Source: broker.SourceCass, Action: "operations.execute",
			Host: host, Operation: "filesystem.list",
			Target: &broker.OperationTarget{Path: "/workspace"},
		}
		if _, err := rt.Execute(context.Background(), step); err != nil {
			t.Fatalf("execute for %s: %v", host, err)
		}

		want := strings.Split(host, ".")[0]
		other := map[string]string{"alpha": "beta", "beta": "alpha"}[want]

		if _, reached := got[other]; reached {
			t.Errorf("a step for %s reached %s's endpoint", want, other)
		}
		reached, ok := got[want]
		if !ok {
			t.Fatalf("the step for %s never reached the host it named", want)
		}
		if reached.auth != "Bearer token-for-"+want {
			t.Errorf("%s was sent %q; a host must only ever receive its own token", want, reached.auth)
		}
	}
}

// TestCassRefusesAnAnswerFromTheWrongHost is the whole reason the agent names
// itself.
//
// The endpoint for a host is operator configuration: a URL and a port. Once
// several agents are reached through several local forwards, a transposed port
// sends one host's question to another host's agent, and the answer comes back
// describing the wrong machine under the right name. Nothing about it looks
// wrong -- it parses, the operation matches, the data is real -- and it is a
// wrong answer of the kind this project spends most of its effort preventing.
func TestCassRefusesAnAnswerFromTheWrongHost(t *testing.T) {
	// A perfectly healthy agent, on winston, reached by a forward that the
	// configuration believes goes to sgtstubby.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"request_id":"1","operation":"filesystem.list","status":"ok",
			"metadata":{"truncated":false,"host":"winston.arc.gwu.edu"},
			"data":{"path":"/var/log","entries":[]}}`)
	}))
	defer server.Close()

	connector, err := NewCassConnector(CassConfig{Agents: map[string]CassAgentConfig{
		"sgtstubby.arc.gwu.edu": {Endpoint: server.URL, Token: "t"},
	}})
	if err != nil {
		t.Fatalf("build connector: %v", err)
	}

	_, err = connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceCass, Action: "operations.execute",
		Host: "sgtstubby.arc.gwu.edu", Operation: "filesystem.list",
		Target: &broker.OperationTarget{Path: "/var/log"},
		Params: &broker.OperationParams{MaxEntries: 10},
	})
	if err == nil {
		t.Fatal("winston's filesystem was accepted as sgtstubby's; a transposed port now yields a wrong answer that looks right")
	}
	// The message has to name both hosts. "host mismatch" alone sends someone
	// looking at the agent, when the fault is in the endpoint mapping.
	for _, want := range []string{"sgtstubby.arc.gwu.edu", "winston.arc.gwu.edu"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
}

// TestCassRefusesAnAgentThatWillNotNameItself pins the unverifiable case as a
// refusal rather than an exception. An agent too old to report a host is
// precisely the situation the check exists for.
func TestCassRefusesAnAgentThatWillNotNameItself(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"request_id":"1","operation":"filesystem.list","status":"ok",
			"metadata":{"truncated":false},"data":{"path":"/var/log","entries":[]}}`)
	}))
	defer server.Close()

	connector, err := NewCassConnector(CassConfig{Agents: map[string]CassAgentConfig{
		"sgtstubby.arc.gwu.edu": {Endpoint: server.URL, Token: "t"},
	}})
	if err != nil {
		t.Fatalf("build connector: %v", err)
	}
	if _, err = connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceCass, Action: "operations.execute",
		Host: "sgtstubby.arc.gwu.edu", Operation: "filesystem.list",
		Target: &broker.OperationTarget{Path: "/var/log"},
		Params: &broker.OperationParams{MaxEntries: 10},
	}); err == nil {
		t.Fatal("an agent that named no host was trusted")
	}
}

// TestShortHostMatching documents the deliberate looseness: a policy naming an
// FQDN and an agent reporting the bare name are the same machine.
func TestShortHostMatching(t *testing.T) {
	for _, tc := range []struct {
		planned, reported string
		want              bool
	}{
		{"winston.arc.gwu.edu", "winston", true},
		{"winston", "winston.arc.gwu.edu", true},
		{"WINSTON.arc.gwu.edu", "winston", true},
		{"winston.arc.gwu.edu", "sgtstubby.arc.gwu.edu", false},
		{"winston.arc.gwu.edu", "winston2", false},
		{"winston.arc.gwu.edu", "", false},
	} {
		if got := sameHost(tc.planned, tc.reported) && tc.reported != ""; got != tc.want {
			t.Errorf("sameHost(%q, %q) = %v, want %v", tc.planned, tc.reported, got, tc.want)
		}
	}
}
