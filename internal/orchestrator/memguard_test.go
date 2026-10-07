package orchestrator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
)

func TestMemoryUnitFilterRefusesNumericUseOfMemoryColumns(t *testing.T) {
	refused := []string{
		// The query from the live check that answered "6,662,568 units".
		"SELECT SUM(CAST(TRESReq_mem AS UNSIGNED)) AS total FROM runTBL2_workload WHERE workload = 'gpu' AND SubmitTime > 0",
		"SELECT AVG(TRESalloc_mem) FROM runTBL2 WHERE SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE TRESReq_mem > 100 AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE 100 < r.TRESReq_mem AND SubmitTime > 0",
		"SELECT JobID FROM runTBL2 WHERE SubmitTime > 0 ORDER BY TRESReq_mem DESC LIMIT 5",
		"SELECT JobID FROM runTBL2 WHERE SubmitTime > 0 ORDER BY netid, `TRESReq_mem` DESC LIMIT 5",
		"SELECT SUM(TRESReq_mem * 1) FROM runTBL2 WHERE SubmitTime > 0",
		"SELECT MAX(TRESReq_mem) FROM runTBL2 WHERE SubmitTime > 0",
		"SELECT SUM(CONVERT(TRESalloc_mem, UNSIGNED)) FROM runTBL2 WHERE SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE TRESReq_mem BETWEEN 10 AND 20 AND SubmitTime > 0",
		// Digits without the unit are the same mistake.
		"SELECT SUM(LEFT(TRESReq_mem, CHAR_LENGTH(TRESReq_mem)-1)) FROM runTBL2 WHERE SubmitTime > 0",
		"SELECT SUM(REGEXP_REPLACE(tresreq_mem, '[A-Z]', '')) FROM runTBL2 WHERE SubmitTime > 0",
	}
	for _, query := range refused {
		err := memoryUnitFilter(broker.RouteRequest{Intent: broker.IntentDatabaseQuery, Query: query})
		if err == nil {
			t.Errorf("not refused: %s", query)
			continue
		}
		if !strings.Contains(err.Error(), "RIGHT(TRESReq_mem,1)") || !strings.Contains(err.Error(), "22 January 2026") {
			t.Errorf("refusal does not give the conversion and the coverage: %v", err)
		}
	}
}

func TestMemoryUnitFilterPassesTextUseAndConversions(t *testing.T) {
	passed := []string{
		"SELECT JobID, TRESReq_mem FROM runTBL2 WHERE SubmitTime > 0 LIMIT 5",
		"SELECT TRESReq_mem, COUNT(*) FROM runTBL2 WHERE SubmitTime > 0 GROUP BY TRESReq_mem",
		"SELECT COUNT(*) FROM runTBL2 WHERE TRESReq_mem = '16G' AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE TRESReq_mem <> '16G' AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE TRESReq_mem != '' AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE TRESReq_mem LIKE '%T' AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE TRESReq_mem IS NULL AND SubmitTime > 0",
		"SELECT RIGHT(TRESReq_mem, 1) AS unit, COUNT(*) FROM runTBL2 WHERE SubmitTime > 0 GROUP BY unit",
		// The expression the refusal hands back must pass, or the model is stuck.
		"SELECT ROUND(SUM(" + memoryToGB + "),1) AS gb FROM runTBL2_workload WHERE workload = 'gpu' AND SubmitTime > 0",
		"SELECT JobID FROM runTBL2 WHERE SubmitTime > 0 ORDER BY " + memoryToGB + " DESC LIMIT 5",
		// Only G values, compared in GB: the pattern reads the unit.
		"SELECT COUNT(*) FROM runTBL2 WHERE TRESReq_mem LIKE '%G' AND CAST(LEFT(TRESReq_mem, CHAR_LENGTH(TRESReq_mem)-1) AS UNSIGNED) > 100 AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE StartTime - SubmitTime > 3600 AND SubmitTime > 0",
		// Counting jobs without a value sums a test, not sizes. Refused by the
		// first version of this guard, in the live check's own ground truth.
		"SELECT SUM(TRESReq_mem IS NULL OR TRESReq_mem = '') AS no_value, COUNT(*) FROM runTBL2 WHERE SubmitTime > 0",
		"SELECT SUM(TRESalloc_mem LIKE '%T') FROM runTBL2 WHERE SubmitTime > 0",
	}
	for _, query := range passed {
		if err := memoryUnitFilter(broker.RouteRequest{Intent: broker.IntentDatabaseQuery, Query: query}); err != nil {
			t.Errorf("refused: %s: %v", query, err)
		}
	}
	if err := memoryUnitFilter(broker.RouteRequest{Intent: broker.IntentInventoryProcesses,
		Host: "node01", Match: "TRESReq_mem"}); err != nil {
		t.Errorf("a non-SQL intent was checked: %v", err)
	}
}

// Wired into the loop: the unconverted sum never reaches the database, and the
// model is handed the conversion and another turn.
func TestAnUnconvertedMemorySumNeverReachesTheDatabase(t *testing.T) {
	var turns int
	var secondRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		turns++
		if turns == 1 {
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":"","tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"database.query\",\"query\":\"SELECT SUM(CAST(TRESReq_mem AS UNSIGNED)) FROM runTBL2 WHERE SubmitTime > 1788000000\"}"}}
			]}}]}`)
			return
		}
		json.Unmarshal(body, &secondRequest)
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"done"}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourcePegasusDB}
	session := newTestSession(t, server.URL, fake)
	if _, err := session.Ask(context.Background(), "how much memory did jobs request this week?"); err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("the unconverted sum reached the database: %+v", fake.calls)
	}
	refused := false
	for _, entry := range session.Trace() {
		if entry.Stage == "memory_units_refused" {
			refused = true
		}
	}
	if !refused {
		t.Error("the trace does not record the refusal")
	}
	messages, _ := secondRequest["messages"].([]any)
	last, _ := messages[len(messages)-1].(map[string]any)
	if content, _ := last["content"].(string); !strings.Contains(content, "RIGHT(TRESReq_mem,1)") {
		t.Errorf("the model was not handed the conversion; last message: %v", last)
	}
}
