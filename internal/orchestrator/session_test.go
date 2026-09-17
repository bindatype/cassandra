package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
	"github.com/bindatype/cassandra/internal/connector"
)

// fakeConnector stands in for a real data source so the loop can be tested
// without network access or credentials.
type fakeConnector struct {
	source broker.Source
	calls  []broker.RouteStep
}

func (f *fakeConnector) Source() broker.Source { return f.source }

func (f *fakeConnector) Execute(ctx context.Context, step broker.RouteStep) (connector.Evidence, error) {
	f.calls = append(f.calls, step)
	return connector.Evidence{
		Source:    string(f.source),
		Action:    step.Action,
		ItemCount: 1,
		Items: []connector.EvidenceItem{
			{ID: "001", Host: "node02", Description: "Wazuh agent", State: "disconnected"},
		},
	}, nil
}

func TestSessionRunsFullLoop(t *testing.T) {
	var turns int
	var secondRequest map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer mr2_test" {
			t.Errorf("Authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		turns++
		if turns == 1 {
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":"","tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"agent.status\",\"host\":\"node02\"}"}}
			]}}]}`)
			return
		}
		json.Unmarshal(body, &secondRequest)
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"node02 is disconnected."}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourceWazuhAPI}
	session := newTestSession(t, server.URL, fake)

	answer, err := session.Ask(context.Background(), "is node02 healthy?")
	if err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if answer != "node02 is disconnected." {
		t.Errorf("answer = %q", answer)
	}
	if turns != 2 {
		t.Errorf("model turns = %d, want 2", turns)
	}
	if len(fake.calls) != 1 || fake.calls[0].Action != "agents.status" {
		t.Fatalf("connector calls = %+v, want one agents.status", fake.calls)
	}
	if fake.calls[0].Host != "node02" {
		t.Errorf("host = %q, want node02", fake.calls[0].Host)
	}

	// The evidence must be returned to the model as a tool-role message.
	messages, _ := secondRequest["messages"].([]any)
	last, _ := messages[len(messages)-1].(map[string]any)
	if last["role"] != "tool" {
		t.Errorf("final message role = %v, want tool", last["role"])
	}
	if !strings.Contains(last["content"].(string), "disconnected") {
		t.Error("tool message should carry the evidence")
	}
}

func TestSessionDeniesUnauthorizedIntent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"live.evidence\",\"host\":\"not-authorized\",\"resource\":\"system-log\"}"}}
		]}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourceCass}
	session := newTestSession(t, server.URL, fake)

	if _, err := session.Ask(context.Background(), "read the log on not-authorized"); err == nil {
		t.Fatal("expected policy to deny an unauthorized host")
	}
	if len(fake.calls) != 0 {
		t.Errorf("connector was called %d times; policy must block before execution", len(fake.calls))
	}

	var denied bool
	for _, entry := range session.Trace() {
		if entry.Stage == "policy_denied" {
			denied = true
		}
	}
	if !denied {
		t.Error("trace should record the policy denial")
	}
}

func TestSessionRejectsInventedToolArguments(t *testing.T) {
	// A model that tries to smuggle an execution detail past policy must be
	// rejected by strict decoding, not silently ignored.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"fleet.inventory\",\"url\":\"https://evil.example/api\"}"}}
		]}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourceWazuhAPI}
	session := newTestSession(t, server.URL, fake)

	if _, err := session.Ask(context.Background(), "list agents"); err == nil {
		t.Fatal("expected an unknown tool-argument field to be rejected")
	}
	if len(fake.calls) != 0 {
		t.Error("nothing should execute after an undecodable intent")
	}
}

func TestSessionPassesThroughDirectAnswers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"I need a host name."}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourceWazuhAPI}
	session := newTestSession(t, server.URL, fake)

	answer, err := session.Ask(context.Background(), "check that host")
	if err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if answer != "I need a host name." {
		t.Errorf("answer = %q", answer)
	}
	if len(fake.calls) != 0 {
		t.Error("no tool call means no execution")
	}
}

func newTestSession(t *testing.T, endpoint string, c connector.Connector) *Session {
	t.Helper()

	client, err := NewMindRouterClient(MindRouterConfig{
		Endpoint: endpoint,
		APIKey:   "mr2_test",
		Model:    "test-model",
	})
	if err != nil {
		t.Fatalf("NewMindRouterClient() error = %v", err)
	}

	policy, err := broker.LoadPolicy(strings.NewReader(`{
		"version": 1,
		"live_hosts": {"docker-harness": {"resources": ["system-log"]}},
		"resources": {"system-log": {"operation": "filesystem.tail", "path": "/var/log/cass/system.log", "params": {"max_bytes": 8192}}}
	}`))
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	router, err := broker.NewRouter(policy)
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	executor, err := connector.NewExecutor(c)
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
	return NewSession(client, router, executor)
}

func TestSessionOffersOnlyExecutableIntents(t *testing.T) {
	// A capability advertised with no connector behind it is a capability that
	// does not exist. The enum must follow what the executor can reach.
	tests := []struct {
		name   string
		source broker.Source
		want   []string
		absent string
	}{
		{
			name:   "zabbix only",
			source: broker.SourceZabbixAPI,
			want:   []string{"monitoring.problems"},
			absent: "fleet.inventory",
		},
		{
			name:   "wazuh only",
			source: broker.SourceWazuhAPI,
			want:   []string{"fleet.inventory", "agent.status"},
			absent: "live.evidence",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newTestSession(t, "http://unused.invalid", &fakeConnector{source: test.source})
			got := strings.Join(session.Intents(), ",")
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("intents = %q, want it to include %q", got, want)
				}
			}
			if strings.Contains(got, test.absent) {
				t.Errorf("intents = %q, must not include %q with no connector for it", got, test.absent)
			}
		})
	}
}

func TestLiveEvidenceIsWithheldUntilItsConnectorExists(t *testing.T) {
	// There is no Cass endpoint connector yet. Until there is, the intent
	// must not reach the model: the router would authorize it and execution
	// would then fail with an internal error.
	session := newTestSession(t, "http://unused.invalid", &fakeConnector{source: broker.SourceZabbixAPI})
	for _, intent := range session.Intents() {
		if intent == string(broker.IntentLiveEvidence) {
			t.Fatal("live.evidence was offered with no cass-agent connector registered")
		}
	}
}

func TestRetryIsOfferedForMalformedCallsButNotRefusals(t *testing.T) {
	// A model that puts a value in the wrong field made a mistake it can fix.
	// A model told a host is not authorized received an answer, and retrying
	// would turn a refusal into an invitation to look for a host that is.
	tests := []struct {
		name        string
		err         error
		wantRetried bool
	}{
		{"malformed request", &broker.RouteError{Code: "invalid_request"}, true},
		{"invalid query", &broker.RouteError{Code: "invalid_query"}, true},
		{"missing host", &broker.RouteError{Code: "missing_host"}, true},
		{"unauthorized host", &broker.RouteError{Code: "host_not_authorized"}, false},
		{"unauthorized resource", &broker.RouteError{Code: "resource_not_authorized"}, false},
		{"unrelated error", errors.New("boom"), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isRetryableRouteError(test.err); got != test.wantRetried {
				t.Errorf("isRetryableRouteError(%v) = %v, want %v", test.err, got, test.wantRetried)
			}
		})
	}
}

func TestSessionRetriesOnceAfterAFailedExecution(t *testing.T) {
	var turns int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turns++
		switch turns {
		case 1:
			// First attempt names a host the fake connector will reject.
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
				{"id":"c1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"agent.status\",\"host\":\"broken\"}"}}]}}]}`)
		case 2:
			// Shown the error, it corrects itself.
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
				{"id":"c2","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"agent.status\",\"host\":\"node02\"}"}}]}}]}`)
		default:
			io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"node02 is disconnected."}}]}`)
		}
	}))
	defer server.Close()

	fake := &failingOnceConnector{fakeConnector{source: broker.SourceWazuhAPI}}
	session := newTestSession(t, server.URL, fake)

	answer, err := session.Ask(context.Background(), "is that host healthy?")
	if err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if answer != "node02 is disconnected." {
		t.Errorf("answer = %q", answer)
	}

	var failed, recovered bool
	for _, entry := range session.Trace() {
		if entry.Stage == "execution_failed" {
			failed = true
		}
		if failed && entry.Stage == "evidence_collected" {
			recovered = true
		}
	}
	if !failed || !recovered {
		t.Errorf("trace should show a failed call followed by a successful one: %+v", session.Trace())
	}
}

func TestSessionCanLookBeforeItQueries(t *testing.T) {
	// The behaviour a single tool call made impossible. Asked about something
	// unfamiliar the model inspects first and answers second; with one call it
	// would spend the call looking and stop without an answer.
	var calls []broker.RouteStep
	var turns int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turns++
		switch turns {
		case 1:
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
				{"id":"c1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"database.query\",\"query\":\"SELECT column_name FROM information_schema.columns\"}"}}]}}]}`)
		case 2:
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
				{"id":"c2","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"database.query\",\"query\":\"SELECT shares FROM sshare_data LIMIT 5\"}"}}]}}]}`)
		default:
			io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"sshare_data has 11 columns; here are the shares."}}]}`)
		}
	}))
	defer server.Close()

	recorder := &recordingConnector{fakeConnector{source: broker.SourcePegasusDB}, &calls}
	session := newTestSession(t, server.URL, recorder)

	answer, err := session.Ask(context.Background(), "what is in sshare_data?")
	if err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("connector calls = %d, want 2 (inspect then query)", len(calls))
	}
	if !strings.Contains(calls[0].Query, "information_schema") {
		t.Errorf("first call should inspect the schema, got %q", calls[0].Query)
	}
	if strings.Contains(calls[1].Query, "information_schema") {
		t.Errorf("second call should query the table, got %q", calls[1].Query)
	}
	if answer == "" {
		t.Error("a two-step question must still produce an answer")
	}
}

func TestSessionStopsAtTheTurnLimit(t *testing.T) {
	// A model that never answers must not loop forever.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
			{"id":"c","type":"function","function":{"name":"cass_evidence","arguments":"{"intent":"fleet.inventory"}"}}]}}]}`)
	}))
	defer server.Close()

	session := newTestSession(t, server.URL, &fakeConnector{source: broker.SourceWazuhAPI})
	if _, err := session.Ask(context.Background(), "list agents forever"); err == nil {
		t.Fatal("expected the turn limit to end the loop")
	}
}

// recordingConnector captures the steps it is asked to execute.
type recordingConnector struct {
	fakeConnector
	steps *[]broker.RouteStep
}

func (r *recordingConnector) Execute(ctx context.Context, step broker.RouteStep) (connector.Evidence, error) {
	*r.steps = append(*r.steps, step)
	return r.fakeConnector.Execute(ctx, step)
}

// failingOnceConnector rejects the first host it is given and accepts the next,
// standing in for a query that fails for a reason the model can correct.
type failingOnceConnector struct{ fakeConnector }

func (f *failingOnceConnector) Execute(ctx context.Context, step broker.RouteStep) (connector.Evidence, error) {
	if step.Host == "broken" {
		return connector.Evidence{}, errors.New("query_failed: syntax error near 'Partition'")
	}
	return f.fakeConnector.Execute(ctx, step)
}

func TestAuditRecordsTheTranslationAndTheDenial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
			{"id":"c1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"live.evidence\",\"host\":\"not-authorized\",\"resource\":\"system-log\"}"}}]}}]}`)
	}))
	defer server.Close()

	auditor, err := NewAuditor(path)
	if err != nil {
		t.Fatalf("NewAuditor() error = %v", err)
	}
	defer auditor.Close()

	session := newTestSession(t, server.URL, &fakeConnector{source: broker.SourceCass}).
		WithAudit(auditor, "test-model")

	if _, err := session.Ask(context.Background(), "read the log on not-authorized"); err == nil {
		t.Fatal("expected the unauthorized host to be denied")
	}

	// A denial must be recorded. A log that kept only successful requests would
	// omit exactly the events worth reviewing.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var event AuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(raw), &event); err != nil {
		t.Fatalf("decode audit line: %v", err)
	}
	if event.Decision != "denied" {
		t.Errorf("decision = %q, want denied", event.Decision)
	}
	if !strings.Contains(event.Proposed, "not-authorized") {
		t.Errorf("proposed = %q, want the model's verbatim arguments", event.Proposed)
	}
	if event.Question != "read the log on not-authorized" {
		t.Errorf("question = %q", event.Question)
	}
	if event.Model != "test-model" || event.RequestID == "" || event.Timestamp == "" {
		t.Errorf("event is missing correlation fields: %+v", event)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("audit file mode = %o, want 600", mode)
	}
}

func TestSessionPushesBackWhenACallIsDescribedNotMade(t *testing.T) {
	// A weaker model sometimes writes out the call it intends and stops. The
	// answer looks deliberate and contains no result, so returning it hands the
	// caller a plan where an answer should be.
	var turns int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turns++
		if turns == 1 {
			io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"Let's construct the query. I will use intent='database.query' with a SELECT over runTBL2."}}]}`)
			return
		}
		if turns == 2 {
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
				{"id":"c1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"fleet.inventory\"}"}}]}}]}`)
			return
		}
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"275 agents, 52 disconnected."}}]}`)
	}))
	defer server.Close()

	session := newTestSession(t, server.URL, &fakeConnector{source: broker.SourceWazuhAPI})
	answer, err := session.Ask(context.Background(), "how many agents are there?")
	if err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if strings.Contains(answer, "construct the query") {
		t.Errorf("a described call was returned as the answer: %q", answer)
	}
	if answer != "275 agents, 52 disconnected." {
		t.Errorf("answer = %q", answer)
	}

	var pushedBack bool
	for _, entry := range session.Trace() {
		if entry.Stage == "described_instead_of_called" {
			pushedBack = true
		}
	}
	if !pushedBack {
		t.Error("trace should record the push-back")
	}
}

func TestDescribesACallInsteadLetsRealAnswersThrough(t *testing.T) {
	// False positives cost a turn; false negatives return a plan to a person
	// who asked a question. Real answers must not trip it.
	for _, answer := range []string{
		"There were 503 completed jobs with a median runtime of 224 seconds.",
		"The Wazuh agent on log001 is active, last seen 2026-08-27T18:15:20Z.",
		"No critical CVEs can be reported; there is no vulnerability data source.",
		"dss01 has 7 active problems, the most severe being a GPFS filesystem panic.",
	} {
		if describesACallInstead(answer) {
			t.Errorf("real answer misread as a described call: %q", answer)
		}
	}
}

// The answer is the claim the rest of the record exists to check, so it must
// be in the record. A scheduled report posts with nobody watching, and a
// length alone cannot be reviewed.
func TestAuditRecordsTheAnswerText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	auditor, err := NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	answer := "1,242 problems since yesterday: 374 high, 433 average, 435 warning."
	if err := auditor.Record(AuditEvent{
		Question: "what problems started since yesterday?",
		Status:   "answered", Decision: "allowed",
		Answer: answer, AnswerChars: len(answer),
	}); err != nil {
		t.Fatal(err)
	}
	auditor.Close()

	var event AuditEvent
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &event); err != nil {
		t.Fatal(err)
	}
	if event.Answer != answer {
		t.Fatalf("answer = %q, want %q", event.Answer, answer)
	}
	if event.AnswerChars != len(answer) {
		t.Fatalf("answer_chars = %d, want %d", event.AnswerChars, len(answer))
	}
}

// A runaway answer must not fill the file, and a capped record must still
// report the true length so the truncation is visible.
func TestAuditCapsALongAnswer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	auditor, err := NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	answer := strings.Repeat("x", maxAuditAnswer*2)
	if err := auditor.Record(AuditEvent{
		Status: "answered", Decision: "allowed",
		Answer: answer, AnswerChars: len(answer),
	}); err != nil {
		t.Fatal(err)
	}
	auditor.Close()

	var event AuditEvent
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(bytes.TrimSpace(raw), &event); err != nil {
		t.Fatal(err)
	}
	if len(event.Answer) > maxAuditAnswer+32 {
		t.Fatalf("stored %d bytes, cap is %d", len(event.Answer), maxAuditAnswer)
	}
	if !strings.Contains(event.Answer, "truncated") {
		t.Fatal("a capped answer must say it was capped")
	}
	if event.AnswerChars != len(answer) {
		t.Fatalf("answer_chars = %d, want the true length %d", event.AnswerChars, len(answer))
	}
}

// TestDenialAfterEvidenceStillAnswers pins the behaviour that cost a working
// answer: the model fetched evidence successfully, then speculatively asked
// for something the policy does not allow, and the refusal discarded the
// evidence already in hand and failed the whole question.
//
// The policy refused the second call in both versions. The only thing that
// changed is whether the refusal also destroys unrelated work that was already
// authorized and already done.
func TestDenialAfterEvidenceStillAnswers(t *testing.T) {
	var turns int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		turns++
		switch turns {
		case 1: // a call the policy allows
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":"","tool_calls":[
				{"id":"c1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"agent.status\",\"host\":\"node02\"}"}}
			]}}]}`)
		case 2: // then one it does not
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":"","tool_calls":[
				{"id":"c2","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"live.evidence\",\"host\":\"node02\",\"resource\":\"nope\"}"}}
			]}}]}`)
		default: // and answers from what it got
			io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"node02 is disconnected. The second lookup was refused."}}]}`)
		}
	}))
	defer server.Close()

	session := newTestSession(t, server.URL, &fakeConnector{source: broker.SourceWazuhAPI})

	answer, err := session.Ask(context.Background(), "is node02 healthy?")
	if err != nil {
		t.Fatalf("a refusal after successful evidence failed the whole question: %v", err)
	}
	if !strings.Contains(answer, "disconnected") {
		t.Errorf("answer lost the evidence that was collected: %q", answer)
	}
	if turns < 3 {
		t.Errorf("model turns = %d; the refusal should have gone back as a tool result", turns)
	}
}
