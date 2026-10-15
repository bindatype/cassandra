package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
	"github.com/bindatype/cassandra/internal/connector"
)

// The two queries the 2026-10-08 15:07 run executed, verbatim from its audit.
const (
	ranCompleteDay = "SELECT DATE(FROM_UNIXTIME(MAX(SubmitTime)) - INTERVAL 1 DAY) AS complete_day FROM runTBL2;"
	ranCounts      = "SELECT workload, COUNT(CASE WHEN State = 'COMPLETED' THEN 1 END) AS completed, COUNT(CASE WHEN State = 'FAILED' THEN 1 END) AS failed FROM runTBL2_workload WHERE DATE(FROM_UNIXTIME(SubmitTime)) = '2026-10-07' GROUP BY workload;"
)

// Its answer's "SQL Ran" block: the two real queries, reformatted, and a
// percentile query that was never executed.
const fabricatedAnswer = "**cpu partition**\n* P50: 263 sec (4.4 min)\n\n**SQL Ran**\n```sql\n" +
	"SELECT DATE(FROM_UNIXTIME(MAX(SubmitTime)) - INTERVAL 1 DAY) AS complete_day FROM runTBL2;\n\n" +
	"SELECT workload, \n       COUNT(CASE WHEN State = 'COMPLETED' THEN 1 END) AS completed, \n" +
	"       COUNT(CASE WHEN State = 'FAILED' THEN 1 END) AS failed \nFROM runTBL2_workload \n" +
	"WHERE DATE(FROM_UNIXTIME(SubmitTime)) = '2026-10-07' \nGROUP BY workload;\n\n" +
	"SELECT DISTINCT `partition`, \n       ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY StartTime - SubmitTime) OVER (PARTITION BY `partition`), 0) AS p50_wait_sec \n" +
	"FROM runTBL2 \nWHERE DATE(FROM_UNIXTIME(SubmitTime)) = '2026-10-07' \n  AND `partition` IN ('cpu', 'gpu')\n  AND StartTime > 0;\n```\n"

func ran(queries ...string) []AuditCall {
	var calls []AuditCall
	for _, q := range queries {
		calls = append(calls, AuditCall{Source: "pegasus-db", Query: q})
	}
	return calls
}

func TestTheFabricatedListingIsCaught(t *testing.T) {
	unrun := unrunSQL(fabricatedAnswer, ran(ranCompleteDay, ranCounts))
	if len(unrun) != 1 || !strings.Contains(unrun[0], "PERCENTILE_CONT") {
		t.Fatalf("unrun = %q, want exactly the percentile query", unrun)
	}
}

func TestRealSQLPassesHoweverItIsFormatted(t *testing.T) {
	calls := ran("SELECT COUNT(*) AS n FROM runTBL2 WHERE SubmitTime >= UNIX_TIMESTAMP('2026-09-01') AND `partition` = 'gpu' AND StartTime > 0")
	for name, answer := range map[string]string{
		"fenced, reformatted":           "```sql\nselect count( * ) as n\n  from RUNTBL2\n where SubmitTime >= unix_timestamp('2026-09-01')\n   and partition = 'gpu' and StartTime > 0;\n```",
		"inline with its own backticks": "SQL: `SELECT COUNT(*) AS n FROM runTBL2 WHERE SubmitTime >= UNIX_TIMESTAMP('2026-09-01') AND `partition` = 'gpu' AND StartTime > 0;`",
		"a quoted fragment":             "Filtered with `SELECT COUNT(*) AS n FROM runTBL2 WHERE SubmitTime >= UNIX_TIMESTAMP('2026-09-01')` and more.",
		"elided":                        "```sql\nSELECT COUNT(*) FROM runTBL2 WHERE ... AND StartTime > 0\n```",
		"no SQL at all":                 "There were 30,200 GPU jobs. Scope: `SubmitTime >= 1778299200`.",
	} {
		if unrun := unrunSQL(answer, calls); len(unrun) != 0 {
			t.Errorf("%s: flagged %q", name, unrun)
		}
	}
	if unrun := unrunSQL("```sql\nSELECT COUNT(*) FROM runTBL2 WHERE `partition` = 'cpu'\n```", calls); len(unrun) != 1 {
		t.Errorf("a different query passed: %q", unrun)
	}
	failed := []AuditCall{{Source: "orchestrator", Action: "attempt_failed", Query: "SELECT x FROM runTBL2 WHERE SubmitTime > 0", Error: "Error 1054"}}
	if unrun := unrunSQL("```sql\nSELECT x FROM runTBL2 WHERE SubmitTime > 0\n```", failed); len(unrun) != 0 {
		t.Errorf("a query that ran and failed was reported as never run: %q", unrun)
	}
}

// echoPegasus returns evidence carrying the query it ran, as the real
// connector does.
type echoPegasus struct{ calls []broker.RouteStep }

func (e *echoPegasus) Source() broker.Source { return broker.SourcePegasusDB }
func (e *echoPegasus) Execute(ctx context.Context, step broker.RouteStep) (connector.Evidence, error) {
	e.calls = append(e.calls, step)
	return connector.Evidence{Source: string(broker.SourcePegasusDB), Action: step.Action, Query: step.Query, ItemCount: 1,
		Items: []connector.EvidenceItem{{ID: "1", Fields: map[string]string{"n": "42"}}}}, nil
}

// sqlScriptedModel answers each turn from a list: a query string means "call
// database.query with it"; anything else is a final answer. It keeps the
// last message of every request so tests can read what the model was told.
func sqlScriptedModel(t *testing.T, turns []string, seen *[]string) *httptest.Server {
	t.Helper()
	n := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []map[string]any `json:"messages"`
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &req)
		last, _ := req.Messages[len(req.Messages)-1]["content"].(string)
		*seen = append(*seen, last)
		if n >= len(turns) {
			t.Fatalf("model asked for turn %d, script has %d", n+1, len(turns))
		}
		step := turns[n]
		n++
		if strings.HasPrefix(step, "SELECT") {
			args, _ := json.Marshal(map[string]string{"intent": "database.query", "query": step})
			call, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("call_%d", n), "type": "function",
				"function": map[string]string{"name": toolName, "arguments": string(args)}})
			fmt.Fprintf(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":"","tool_calls":[%s]}}]}`, call)
			return
		}
		content, _ := json.Marshal(step)
		fmt.Fprintf(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":%s}}]}`, content)
	}))
}

const (
	countQuery = "SELECT COUNT(*) AS n FROM runTBL2 WHERE SubmitTime >= 1790000000"
	waitQuery  = "SELECT DISTINCT `partition`, PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY StartTime - SubmitTime) OVER (PARTITION BY `partition`) AS p50 FROM runTBL2 WHERE SubmitTime >= 1790000000"
)

func stages(s *Session) map[string]bool {
	out := map[string]bool{}
	for _, e := range s.Trace() {
		out[e.Stage] = true
	}
	return out
}

func TestAnAnswerQuotingUnrunSQLIsSentBack(t *testing.T) {
	var seen []string
	model := sqlScriptedModel(t, []string{
		countQuery,
		"42 jobs; P50 wait 263 s.\n```sql\n" + countQuery + ";\n" + waitQuery + ";\n```",
		"42 jobs. The wait time was not computed.\n```sql\n" + countQuery + ";\n```",
	}, &seen)
	defer model.Close()
	source := &echoPegasus{}
	session := newTestSession(t, model.URL, source)
	answer, err := session.Ask(context.Background(), "how many jobs, and the median wait?")
	if err != nil {
		t.Fatal(err)
	}
	if !stages(session)["unrun_sql_claimed"] || stages(session)["unrun_sql_in_answer"] {
		t.Errorf("trace %v: want unrun_sql_claimed once, then a clean answer", stages(session))
	}
	if !strings.Contains(seen[2], "quotes SQL that was not run") || !strings.Contains(seen[2], "PERCENTILE_CONT") {
		t.Errorf("the model was not told which statement was not run: %q", seen[2])
	}
	if strings.Contains(answer, "263") || strings.HasPrefix(answer, "Warning") {
		t.Errorf("answer %q", answer)
	}
	if len(source.calls) != 1 {
		t.Errorf("%d queries ran, want 1", len(source.calls))
	}
}

func TestASecondFabricationIsDeliveredWithAWarning(t *testing.T) {
	var seen []string
	fabricated := "42 jobs; P50 wait 263 s.\n```sql\n" + waitQuery + ";\n```"
	model := sqlScriptedModel(t, []string{countQuery, fabricated, fabricated}, &seen)
	defer model.Close()
	session := newTestSession(t, model.URL, &echoPegasus{})
	answer, err := session.Ask(context.Background(), "how many jobs, and the median wait?")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(answer, unrunSQLWarning) {
		t.Errorf("answer does not open with the warning: %q", answer)
	}
	if st := stages(session); !st["unrun_sql_claimed"] || !st["unrun_sql_in_answer"] {
		t.Errorf("trace %v", st)
	}
}

func TestWithNoTurnLeftTheAnswerCarriesTheWarning(t *testing.T) {
	var seen []string
	turns := []string{}
	for i := 0; i < maxToolCalls-1; i++ {
		turns = append(turns, fmt.Sprintf("%s AND JobID <> '%d'", countQuery, i))
	}
	turns = append(turns, "P50 wait 263 s.\n```sql\n"+waitQuery+"\n```")
	model := sqlScriptedModel(t, turns, &seen)
	defer model.Close()
	session := newTestSession(t, model.URL, &echoPegasus{})
	answer, err := session.Ask(context.Background(), "median wait?")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(answer, unrunSQLWarning) || stages(session)["unrun_sql_claimed"] {
		t.Errorf("on the last turn there is no push-back, only the warning: %q, trace %v", answer, stages(session))
	}
}

func TestAnswersThatQuoteWhatRanAreUntouched(t *testing.T) {
	var seen []string
	model := sqlScriptedModel(t, []string{countQuery, "42 jobs.\n\nSQL: `" + countQuery + ";`"}, &seen)
	defer model.Close()
	session := newTestSession(t, model.URL, &echoPegasus{})
	answer, err := session.Ask(context.Background(), "how many jobs?")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(answer, "Warning") || stages(session)["unrun_sql_claimed"] {
		t.Errorf("a truthful answer was flagged: %q", answer)
	}
}
