package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
	"github.com/bindatype/cassandra/internal/connector"
)

func TestSQLFromQuestion(t *testing.T) {
	asked := "Run this SQL against PegasusDB: SELECT netid, COUNT(*) FROM FY2026\n  WHERE NNodes = 1 GROUP BY netid;"
	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"SELECT netid, COUNT(*) FROM FY2026 WHERE NNodes = 1 GROUP BY netid", true},
		{"select netid, count(*)\nfrom fy2026 where nnodes = 1 group by netid;", true},
		{"SELECT netid, COUNT(*) FROM runTBL2_jobs WHERE NNodes = 1 GROUP BY netid", false},
		{"SELECT 1", false}, // too short to say anything
		{"", false},
	} {
		if got := sqlFromQuestion(asked, tc.query); got != tc.want {
			t.Errorf("sqlFromQuestion(%q) = %v, want %v", tc.query, got, tc.want)
		}
	}
	if sqlFromQuestion("How many jobs ran on cpu067 in September?",
		"SELECT COUNT(*) FROM runTBL2 WHERE FIND_IN_SET('cpu067', NodeList) > 0") {
		t.Error("a query written from a plain-English question is not taken from it")
	}
}

// queryEchoConnector returns the executed query in its evidence, as the
// Pegasus connector does, so the audit can compare it with the question.
type queryEchoConnector struct{}

func (queryEchoConnector) Source() broker.Source { return broker.SourcePegasusDB }

func (queryEchoConnector) Execute(ctx context.Context, step broker.RouteStep) (connector.Evidence, error) {
	return connector.Evidence{
		Source: string(broker.SourcePegasusDB), Action: step.Action, Query: step.Query,
		ItemCount: 1, Summary: map[string]int{"returned": 1, "total_matching": 1},
		Items: []connector.EvidenceItem{{ID: "0", Fields: map[string]string{"n": "42"}}},
	}, nil
}

func TestAuditMarksSQLTakenFromTheQuestion(t *testing.T) {
	const query = "SELECT COUNT(*) AS n FROM FY2026 WHERE NNodes > 1"
	var turns int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turns++
		if turns == 1 {
			args, _ := json.Marshal(map[string]string{"intent": "database.query", "query": query})
			call, _ := json.Marshal(string(args))
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
				{"id":"c1","type":"function","function":{"name":"cass_evidence","arguments":`+string(call)+`}}]}}]}`)
			return
		}
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"42 jobs. SQL: `+query+`"}}]}`)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	auditor, err := NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	session := newTestSession(t, server.URL, queryEchoConnector{}).WithAudit(auditor, "test-model")
	if _, err := session.Ask(context.Background(), "Run this SQL against PegasusDB: "+query+";"); err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	auditor.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event AuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(raw), &event); err != nil {
		t.Fatal(err)
	}
	if len(event.Calls) != 1 || !event.Calls[0].SQLFromQuestion {
		t.Fatalf("calls = %+v, want one call marked sql_from_question", event.Calls)
	}
	if !bytes.Contains(raw, []byte(`"sql_from_question":true`)) {
		t.Errorf("the flag must be in the audit line under its JSON name: %s", raw)
	}
}
