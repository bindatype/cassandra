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

func TestPartitionPatternFilterRefusesGpuAndCpuNamePatterns(t *testing.T) {
	refused := []string{
		"SELECT COUNT(*) FROM runTBL2 WHERE `partition` LIKE '%gpu%' AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE `partition` NOT LIKE '%gpu%' AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE partition like '%-cpu' AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE `partition` REGEXP 'gpu' AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE `Partition`\n  LIKE '%GPU%' AND SubmitTime > 0",
	}
	for _, query := range refused {
		err := partitionPatternFilter(broker.RouteRequest{Intent: broker.IntentDatabaseQuery, Query: query})
		if err == nil {
			t.Errorf("not refused: %s", query)
			continue
		}
		if !strings.Contains(err.Error(), "runTBL2_workload") || !strings.Contains(err.Error(), "`partition` = 'gpu'") {
			t.Errorf("refusal does not give both corrections: %v", err)
		}
	}
}

// Naming a partition is a legitimate question about that partition, and a
// family pattern without gpu or cpu in it is how a person asks about superChip*.
func TestPartitionPatternFilterPassesNamedPartitionsAndTheView(t *testing.T) {
	passed := []string{
		"SELECT COUNT(*) FROM runTBL2 WHERE `partition` = 'gpu' AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE `partition` IN ('gpu', 'viz', 'superChip') AND SubmitTime > 0",
		"SELECT COUNT(*) FROM runTBL2 WHERE `partition` LIKE 'superChip%' AND SubmitTime > 0",
		"SELECT workload, COUNT(*) FROM runTBL2_workload WHERE workload = 'gpu' AND SubmitTime > 0 GROUP BY workload",
		"SELECT COUNT(*) FROM runTBL2 WHERE NodeList LIKE '%gpu013%' AND SubmitTime > 0",
	}
	for _, query := range passed {
		if err := partitionPatternFilter(broker.RouteRequest{Intent: broker.IntentDatabaseQuery, Query: query}); err != nil {
			t.Errorf("refused: %s: %v", query, err)
		}
	}
	// Only database queries are checked.
	if err := partitionPatternFilter(broker.RouteRequest{Intent: broker.IntentInventoryProcesses,
		Host: "node01", Match: "gpu"}); err != nil {
		t.Errorf("a non-SQL intent was checked: %v", err)
	}
}

// The guard must be wired into the loop: the pattern query never reaches the
// database, and the model is told why and gets another turn.
func TestAPartitionPatternQueryNeverReachesTheDatabase(t *testing.T) {
	var turns int
	var secondRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		turns++
		if turns == 1 {
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":"","tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"cass_evidence","arguments":"{\"intent\":\"database.query\",\"query\":\"SELECT COUNT(*) FROM runTBL2 WHERE `+"`partition`"+` LIKE '%gpu%' AND SubmitTime > 1778299200\"}"}}
			]}}]}`)
			return
		}
		json.Unmarshal(body, &secondRequest)
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"done"}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourcePegasusDB}
	session := newTestSession(t, server.URL, fake)
	if _, err := session.Ask(context.Background(), "how many GPU jobs ran since May?"); err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("the pattern query reached the database: %+v", fake.calls)
	}
	refused := false
	for _, entry := range session.Trace() {
		if entry.Stage == "partition_pattern_refused" {
			refused = true
		}
	}
	if !refused {
		t.Error("the trace does not record the refusal")
	}
	messages, _ := secondRequest["messages"].([]any)
	last, _ := messages[len(messages)-1].(map[string]any)
	if content, _ := last["content"].(string); !strings.Contains(content, "runTBL2_workload") {
		t.Errorf("the model was not told to use the view; last message: %v", last)
	}
}
