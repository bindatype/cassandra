package broker

import (
	"strings"
	"testing"
)

// The exact query a live askcass run produced on 2026-09-23, asked to report
// each of seven research groups' completed job count and median and 95th
// percentile wait time. It ran, and returned a P50 equal to its own P95 for
// every group -- 0.00/0.00, 0.00/0.00, 6.79/6.79, and so on -- because GROUP
// BY groupName had already collapsed to one row per group before OVER
// (PARTITION BY groupName) ran, leaving each partition exactly one row.
//
// It reproduced identically with and without the prompt rule written to stop
// it, which is why this exists as a code-level guard rather than prose.
const brokenGroupByPartitionQuery = `
SELECT groupName,
       COUNT(*) AS completed_count,
       ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY StartTime - SubmitTime) OVER (PARTITION BY groupName) / 3600, 2) AS p50_wait_hr,
       ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY StartTime - SubmitTime) OVER (PARTITION BY groupName) / 3600, 2) AS p95_wait_hr
FROM runTBL2
WHERE SubmitTime >= UNIX_TIMESTAMP('2026-05-10')
  AND groupName IN ('MG-anenberggrp', 'MG-cbi', 'MG-diaolab')
  AND State = 'COMPLETED'
  AND StartTime > 0
GROUP BY groupName`

// The correct rewrite: the window function runs over the raw, uncollapsed
// rows in a subquery, and the outer GROUP BY only ever sees a value the
// window function already made constant within each group. MAX() is safe
// there for exactly that reason. This form contains the literal text
// "PARTITION BY groupName" and "GROUP BY groupName" too -- just in two
// different scopes -- which is the whole reason the guard has to track
// scope rather than search for both phrases anywhere in the query.
const fixedGroupByPartitionQuery = `
SELECT groupName, COUNT(*) AS total_jobs,
       MAX(p50_wait_hr) AS p50_wait_hr, MAX(p95_wait_hr) AS p95_wait_hr
FROM (
    SELECT groupName,
        ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY StartTime - SubmitTime)
          OVER (PARTITION BY groupName) / 3600, 2) AS p50_wait_hr,
        ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY StartTime - SubmitTime)
          OVER (PARTITION BY groupName) / 3600, 2) AS p95_wait_hr
    FROM runTBL2
    WHERE SubmitTime >= UNIX_TIMESTAMP('2026-05-10')
      AND groupName IN ('MG-anenberggrp', 'MG-cbi', 'MG-diaolab')
      AND State = 'COMPLETED' AND StartTime > 0
) sub
GROUP BY groupName`

func TestValidateQueryRejectsGroupByPartitionCollision(t *testing.T) {
	err := ValidateQuery(brokenGroupByPartitionQuery)
	if err == nil {
		t.Fatal("must reject: GROUP BY and PARTITION BY both name groupName in one scope")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "groupname") {
		t.Fatalf("error does not name the colliding column, model cannot self-correct from it: %v", err)
	}
}

func TestValidateQueryAcceptsTheSubqueryRewrite(t *testing.T) {
	if err := ValidateQuery(fixedGroupByPartitionQuery); err != nil {
		t.Fatalf("the correct rewrite must not be rejected: %v", err)
	}
}

// Grouping by one column while a window function ranks within a different
// one is an ordinary, unrelated pattern -- e.g. finding each partition's
// top submitter while reporting totals grouped by day. A guard that flags
// any co-occurrence of the two keywords, rather than the same column named
// by both, would break this.
func TestValidateQueryAcceptsGroupByAndPartitionByOnDifferentColumns(t *testing.T) {
	query := `SELECT day, COUNT(*),
       RANK() OVER (PARTITION BY netid ORDER BY COUNT(*) DESC) AS rnk
FROM runTBL2
WHERE SubmitTime >= UNIX_TIMESTAMP('2026-05-10')
GROUP BY day, netid`
	if err := ValidateQuery(query); err != nil {
		t.Fatalf("GROUP BY day / PARTITION BY netid do not collide: %v", err)
	}
}

// The ordinary per-group percentile form used everywhere else this
// project's own queries use it: PARTITION BY with no GROUP BY at all. Only
// a GROUP BY on the same column turns this into a degenerate partition.
func TestValidateQueryAcceptsPartitionByWithNoGroupBy(t *testing.T) {
	query := `SELECT DISTINCT partition,
       ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY StartTime - SubmitTime)
         OVER (PARTITION BY partition) / 3600, 2) AS p50_wait_hr
FROM runTBL2
WHERE SubmitTime >= UNIX_TIMESTAMP('2026-05-10')`
	if err := ValidateQuery(query); err != nil {
		t.Fatalf("a bare per-group percentile with no GROUP BY must not be rejected: %v", err)
	}
}

// An ordinary aggregate with no window function anywhere has nothing for
// this guard to catch, and must not be caught by it.
// The multi-column case that makes the fix real rather than incidental:
// every column GROUP BY groups by is also named by PARTITION BY, so the
// partition is still exactly one row per group, just with two columns
// naming the group instead of one.
func TestValidateQueryRejectsMultiColumnCollision(t *testing.T) {
	query := `SELECT day, netid, COUNT(*),
       ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY StartTime - SubmitTime)
         OVER (PARTITION BY day, netid) / 3600, 2) AS p50_wait_hr
FROM runTBL2
WHERE SubmitTime >= UNIX_TIMESTAMP('2026-05-10')
GROUP BY day, netid`
	err := ValidateQuery(query)
	if err == nil {
		t.Fatal("GROUP BY day, netid with PARTITION BY the same two columns is still degenerate")
	}
	if !strings.Contains(err.Error(), "day") || !strings.Contains(err.Error(), "netid") {
		t.Fatalf("error should name both colliding columns: %v", err)
	}
}

func TestValidateQueryAcceptsPlainGroupBy(t *testing.T) {
	query := `SELECT DATE(FROM_UNIXTIME(SubmitTime)) AS day, COUNT(*) AS jobs
FROM runTBL2
WHERE SubmitTime >= UNIX_TIMESTAMP('2026-05-01')
GROUP BY day
ORDER BY day`
	if err := ValidateQuery(query); err != nil {
		t.Fatalf("a plain aggregate has no window function to conflict with: %v", err)
	}
}
