package broker

import (
	"regexp"
	"sort"
	"strings"
)

// conflictingGroupByPartitionColumn reports a column that appears in both a
// top-level GROUP BY and a same-scope PARTITION BY.
//
// GROUP BY collapses to one row per group before any window function runs,
// so PARTITION BY the same column ranks a one-row partition: PERCENTILE_CONT
// returns that row's own value, and P50 equals P95. The prompt rule against
// it did not hold, so it is caught here.
//
// The fix (window over raw rows in a subquery, GROUP BY outside) names both
// clauses too, in different scopes. So only a PARTITION BY not enclosed by a
// parenthesized span containing a SELECT counts, and each top-level UNION arm
// is checked on its own.
func conflictingGroupByPartitionColumn(query string) (column string, ok bool) {
	groupBy := findKeyword(query, `group\s+by`)
	partitionBy := findKeyword(query, `partition\s+by`)
	if len(groupBy) == 0 || len(partitionBy) == 0 {
		return "", false
	}

	depth := 0
	isSubquery := []bool{} // isSubquery[d] tracks the paren currently open at depth d+1
	inSubquery := func() bool {
		for _, b := range isSubquery {
			if b {
				return true
			}
		}
		return false
	}

	selectRE := regexp.MustCompile(`(?i)\bselect\b`)
	selects := selectRE.FindAllStringIndex(query, -1)
	selectAt := make(map[int]bool, len(selects))
	for _, s := range selects {
		selectAt[s[0]] = true
	}

	groupByAt := make(map[int]bool, len(groupBy))
	for _, g := range groupBy {
		groupByAt[g[0]] = true
	}
	partitionByAt := make(map[int]bool, len(partitionBy))
	for _, p := range partitionBy {
		partitionByAt[p[0]] = true
	}

	unionAt := make(map[int]bool)
	for _, u := range findKeyword(query, `union`) {
		unionAt[u[0]] = true
	}

	type selectArm struct {
		groupCols     []string
		sawGroupBy    bool
		partitionCols [][]string
	}
	arms := []selectArm{{}}
	arm := &arms[0]

	i := 0
	n := len(query)
	for i < n {
		c := query[i]
		switch c {
		case '\'', '"', '`':
			i = skipSQLQuoted(query, i)
			continue
		case '(':
			depth++
			isSubquery = append(isSubquery, false)
			i++
			continue
		case ')':
			if depth > 0 {
				depth--
				isSubquery = isSubquery[:len(isSubquery)-1]
			}
			i++
			continue
		}
		if unionAt[i] && depth == 0 {
			arms = append(arms, selectArm{})
			arm = &arms[len(arms)-1]
			i += len("union")
			continue
		}
		if selectAt[i] {
			if depth > 0 {
				isSubquery[depth-1] = true
			}
			i += len("select")
			continue
		}
		if partitionByAt[i] {
			if !inSubquery() {
				cols, next := readColumnList(query, matchEnd(query, i, `partition\s+by`))
				arm.partitionCols = append(arm.partitionCols, cols)
				i = next
				continue
			}
			i = matchEnd(query, i, `partition\s+by`)
			continue
		}
		if groupByAt[i] {
			if depth == 0 {
				cols, next := readColumnList(query, matchEnd(query, i, `group\s+by`))
				arm.groupCols = cols
				arm.sawGroupBy = true
				i = next
				continue
			}
			i = matchEnd(query, i, `group\s+by`)
			continue
		}
		i++
	}

	for _, a := range arms {
		if column, ok := degenerateGrouping(a.groupCols, a.sawGroupBy, a.partitionCols); ok {
			return column, true
		}
	}
	return "", false
}

// degenerateGrouping reports whether one SELECT arm's PARTITION BY columns
// include every GROUP BY column. GROUP BY day, netid with PARTITION BY netid
// still leaves one row per day in each partition.
func degenerateGrouping(groupCols []string, sawGroupBy bool, partitionCols [][]string) (string, bool) {
	if !sawGroupBy {
		return "", false
	}
	for _, cols := range partitionCols {
		partitionSet := make(map[string]bool, len(cols))
		for _, c := range cols {
			partitionSet[c] = true
		}
		allHeldConstant := true
		for _, g := range groupCols {
			if !partitionSet[g] {
				allHeldConstant = false
				break
			}
		}
		if allHeldConstant {
			names := append([]string{}, groupCols...)
			sort.Strings(names)
			return strings.Join(names, ", "), true
		}
	}
	return "", false
}

// findKeyword returns the byte-range of every case-insensitive match of a
// keyword pattern at a word boundary, so "grouping" is not mistaken for
// "group" and "partitioned" is not mistaken for "partition".
func findKeyword(query, pattern string) [][]int {
	re := regexp.MustCompile(`(?i)\b(` + pattern + `)\b`)
	return re.FindAllStringIndex(query, -1)
}

// matchEnd returns the byte offset immediately after the keyword match
// starting at i.
func matchEnd(query string, i int, pattern string) int {
	re := regexp.MustCompile(`(?i)\A(` + pattern + `)\b`)
	loc := re.FindStringIndex(query[i:])
	if loc == nil {
		return i + 1
	}
	return i + loc[1]
}

// readColumnList reads the column list following GROUP BY or PARTITION BY,
// stopping at the next clause keyword or an unmatched closing paren -- the
// end of the OVER(...) a PARTITION BY lives inside, or the end of the
// statement or UNION arm for a top-level GROUP BY.
func readColumnList(query string, from int) (cols []string, next int) {
	stop := regexp.MustCompile(`(?i)\b(order\s+by|having|limit|window|union)\b`)
	depth := 0
	end := len(query)
	for i := from; i < len(query); i++ {
		switch query[i] {
		case '\'', '"', '`':
			i = skipSQLQuoted(query, i) - 1
			continue
		case '(':
			depth++
		case ')':
			if depth == 0 {
				end = i
				goto done
			}
			depth--
		}
		if depth == 0 {
			if loc := stop.FindStringIndex(query[i:]); loc != nil && loc[0] == 0 {
				end = i
				goto done
			}
		}
	}
done:
	raw := query[from:end]
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "`\"")
		part = strings.ToLower(part)
		// An item may be an expression ("StartTime - SubmitTime"). Only bare
		// identifiers are compared, so expressions are kept as-is.
		if part != "" {
			cols = append(cols, part)
		}
	}
	return cols, end
}
