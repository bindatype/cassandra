package orchestrator

import (
	"strings"
	"testing"

	"github.com/bindatype/cassandra/internal/broker"
)

// The forms graded case F2 actually produced, and their neighbours.
func TestDerivedDateFilterRefusesWrongForms(t *testing.T) {
	refused := []string{
		"SELECT AVG(wait_s) FROM runTBL2_jobs WHERE workload = 'gpu' AND submit_month = 9",
		"SELECT AVG(wait_s) FROM runTBL2_jobs WHERE workload = 'gpu' AND submit_month = 'September'",
		"SELECT AVG(wait_s) FROM runTBL2_jobs WHERE submit_month = 9 AND submit_day BETWEEN 1 AND 30",
		"SELECT COUNT(*) FROM runTBL2_jobs WHERE submit_month IN ('2026-09', '10')",
		"SELECT COUNT(*) FROM runTBL2_jobs WHERE submit_day = 15",
		"SELECT COUNT(*) FROM runTBL2_jobs WHERE SUBMIT_MONTH='2026-9'",
		"SELECT COUNT(*) FROM runTBL2_jobs WHERE submit_month = \"Sep\"",
	}
	for _, query := range refused {
		err := derivedDateFilter(broker.RouteRequest{Intent: broker.IntentDatabaseQuery, Query: query})
		if err == nil {
			t.Errorf("not refused: %s", query)
			continue
		}
		if !strings.Contains(err.Error(), "'2026-09'") || !strings.Contains(err.Error(), "SubmitTime >=") {
			t.Errorf("refusal does not give the form and the range: %v", err)
		}
	}
}

func TestDerivedDateFilterPassesRightFormsAndNonLiterals(t *testing.T) {
	passed := []string{
		"SELECT AVG(wait_s) FROM runTBL2_jobs WHERE workload = 'gpu' AND submit_month = '2026-09'",
		"SELECT COUNT(*) FROM runTBL2_jobs WHERE submit_day BETWEEN '2026-09-01' AND '2026-09-30'",
		"SELECT COUNT(*) FROM runTBL2_jobs WHERE submit_month IN ('2026-09', '2026-10')",
		"SELECT submit_month, COUNT(*) FROM runTBL2_jobs WHERE SubmitTime >= UNIX_TIMESTAMP('2026-09-01') GROUP BY submit_month",
		"SELECT COUNT(*) FROM runTBL2_jobs WHERE submit_day = CURDATE() - INTERVAL 1 DAY",
		"SELECT COUNT(*) FROM runTBL2_jobs WHERE submit_month >= DATE_FORMAT(NOW(), '%Y-%m')",
	}
	for _, query := range passed {
		if err := derivedDateFilter(broker.RouteRequest{Intent: broker.IntentDatabaseQuery, Query: query}); err != nil {
			t.Errorf("refused a correct query: %s: %v", query, err)
		}
	}
	if err := derivedDateFilter(broker.RouteRequest{Intent: broker.IntentMonitoringProblems}); err != nil {
		t.Errorf("checked a non-database intent: %v", err)
	}
}
