package broker

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	maxQueryLen = 8192
	// maxQueryRows bounds any query the planner authorizes. A model-authored
	// query against a table of eighteen million rows would otherwise be a
	// legitimate SELECT that no context window can hold.
	maxQueryRows = 5000
)

// ValidateQuery checks that a model-authored query is a single read.
//
// This is deliberately a thin guard rather than a harness. The filesystem
// reasoning that justifies a bounded operation catalog does not apply here:
// a filesystem is unbounded and holds secrets, whereas this credential is
// confined to one schema and cannot write.
//
// This once also screened for a list of statement verbs that modify data. That
// check duplicated a control the server already applies -- the grant answers
// such a statement with a permission error -- while rejecting legitimate
// queries on substring matches, since "SELECT last_update FROM folderstats"
// contains one of them. A guard that blocks real work to repeat a check the
// database already performs is worse than no guard, so it was removed.
//
// What remains is that the statement is singular and reads, so that what gets
// audited is what actually ran and a second statement cannot hide behind the
// first.
func ValidateQuery(query string) error {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return fmt.Errorf("query is empty")
	}
	if len(trimmed) > maxQueryLen {
		return fmt.Errorf("query exceeds %d bytes", maxQueryLen)
	}
	for _, r := range trimmed {
		if r == '\x00' || (unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t') {
			return fmt.Errorf("query contains control characters")
		}
	}

	lowered := strings.ToLower(trimmed)
	if !strings.HasPrefix(lowered, "select") && !strings.HasPrefix(lowered, "with") {
		return fmt.Errorf("query must begin with SELECT or WITH")
	}

	// This server accepts stacked statements, so a trailing second statement
	// would run unseen by whatever recorded the first.
	if strings.Contains(strings.TrimRight(trimmed, "; \t\n\r"), ";") {
		return fmt.Errorf("only a single statement is allowed")
	}

	// See sql_group_partition.go: GROUP BY collapses to one row per group
	// before a window function runs, so PARTITION BY on that same column, in
	// the same scope, sees a partition of exactly one row -- PERCENTILE_CONT
	// then returns that row's own value for every percentile asked.
	if column, ok := conflictingGroupByPartitionColumn(trimmed); ok {
		return fmt.Errorf("GROUP BY and PARTITION BY both name %q in the same query scope; "+
			"GROUP BY collapses to one row per group before the window function runs, so "+
			"PERCENTILE_CONT sees one row per partition and returns it for every percentile "+
			"requested. Compute the window function over the raw rows in a subquery, then "+
			"GROUP BY the result in an outer query", column)
	}

	return nil
}
