package broker

import (
	"strings"
	"testing"
)

func TestValidateQueryRejectsLockingAndStallingConstructs(t *testing.T) {
	for _, query := range []string{
		"SELECT netid FROM runTBL2 WHERE SubmitTime >= 1 FOR UPDATE",
		"SELECT netid FROM runTBL2 WHERE SubmitTime >= 1 for   update",
		"SELECT netid FROM runTBL2 WHERE SubmitTime >= 1 LOCK IN SHARE MODE",
		"SELECT netid FROM runTBL2 WHERE SubmitTime >= 1\nFOR /* a comment between */ UPDATE",
		"SELECT GET_LOCK('ingest', 10)",
		"SELECT RELEASE_LOCK('ingest')",
		"SELECT RELEASE_ALL_LOCKS()",
		"SELECT SLEEP(50)",
		"SELECT sleep (50)",
		"SELECT BENCHMARK(100000000, MD5('x'))",
		"WITH t AS (SELECT netid FROM runTBL2 FOR UPDATE) SELECT COUNT(*) FROM t",
	} {
		err := ValidateQuery(query)
		if err == nil {
			t.Errorf("must reject %q", query)
			continue
		}
		if !strings.Contains(err.Error(), "not allowed") || !strings.Contains(err.Error(), "Remove it") {
			t.Errorf("refusal for %q must say what to remove: %v", query, err)
		}
	}
}

func TestValidateQueryAcceptsLockWordsThatAreNotConstructs(t *testing.T) {
	for _, query := range []string{
		"SELECT 'FOR UPDATE' AS note FROM runTBL2 LIMIT 1",
		"SELECT COUNT(*) FROM runTBL2 -- FOR UPDATE would lock rows\nWHERE SubmitTime >= 1",
		"SELECT COUNT(*) FROM runTBL2 /* SLEEP(5) */ WHERE SubmitTime >= 1",
		"SELECT `sleep` FROM t",
		"SELECT sleep FROM t",
		"SELECT JobName FROM runTBL2 WHERE JobName = 'benchmark(1,1)'",
		"SELECT update_count FROM t",
	} {
		if err := ValidateQuery(query); err != nil {
			t.Errorf("must accept %q: %v", query, err)
		}
	}
}

// The server runs an executable comment's contents, and every guard here skips
// comments, so a construct hidden in one would pass unseen without this.
func TestValidateQueryRejectsExecutableComments(t *testing.T) {
	for _, query := range []string{
		"SELECT netid FROM runTBL2 /*! FOR UPDATE */",
		"SELECT netid FROM runTBL2 /*!50000 FOR UPDATE */",
		"SELECT netid FROM runTBL2 /*M! FOR UPDATE */",
		"SELECT netid FROM runTBL2 /*M!100300 LOCK IN SHARE MODE */",
		"SELECT /*! SLEEP(50) */ 1",
	} {
		err := ValidateQuery(query)
		if err == nil || !strings.Contains(err.Error(), "executable comments") {
			t.Errorf("must reject %q as an executable comment, got %v", query, err)
		}
	}
	for _, query := range []string{
		"SELECT '/*! not a comment */' AS s",
		"SELECT 1 /* ! a space first makes it ordinary */",
		"SELECT 1 -- /*! inside a line comment",
	} {
		if err := ValidateQuery(query); err != nil {
			t.Errorf("must accept %q: %v", query, err)
		}
	}
}
