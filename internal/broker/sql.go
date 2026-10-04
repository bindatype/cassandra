package broker

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	maxQueryLen = 8192
	// maxQueryRows bounds any query the planner authorizes; a valid SELECT
	// can return millions of rows.
	maxQueryRows = 5000
)

// ValidateQuery checks that a model-authored query is a single read.
//
// It is deliberately thin: the credential is confined to one schema and
// cannot write, so the database's grant is the write control, not a verb
// list here. What it checks is that the statement is a single read (so what
// is audited is what ran) and two SQL shapes known to compute wrong answers.
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
	withoutTrailing := strings.TrimRight(trimmed, "; \t\n\r")
	if strings.Contains(withoutTrailing, ";") {
		return fmt.Errorf("only a single statement is allowed")
	}

	if conflictingUngroupedAggregateWindow(withoutTrailing) {
		return fmt.Errorf("plain aggregate and window function appear in the same SELECT without GROUP BY; " +
			"the aggregate collapses the input to one row before the window runs, so the window sees one row. " +
			"Write COUNT/AVG as window functions with OVER (), or compute the aggregate and window calculation " +
			"in separate query scopes")
	}

	// Checks read withoutTrailing so a trailing ";" can't hide a column name
	// ("groupName;" never matched "groupname"). See sql_group_partition.go.
	if column, ok := conflictingGroupByPartitionColumn(withoutTrailing); ok {
		return fmt.Errorf("GROUP BY and PARTITION BY both name %q in the same query scope; "+
			"GROUP BY collapses to one row per group before the window function runs, so "+
			"PERCENTILE_CONT sees one row per partition and returns it for every percentile "+
			"requested. Compute the window function over the raw rows in a subquery, then "+
			"GROUP BY the result in an outer query", column)
	}

	return nil
}
