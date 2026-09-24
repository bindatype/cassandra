package broker

import (
	"regexp"
	"sort"
	"strings"
)

// conflictingGroupByPartitionColumn reports a column that appears in both a
// top-level GROUP BY and a same-scope PARTITION BY.
//
// GROUP BY collapses to one row per group before any window function runs.
// A query that also writes OVER (PARTITION BY <that same column>) is asking
// PERCENTILE_CONT to rank a partition that, by the time the window function
// sees it, holds exactly one row -- so it returns that row's own value for
// every percentile requested, and P50 comes back equal to P95. That is what
// a live askcass run produced for seven research groups on 2026-09-23, and
// it reproduced identically with and without the percentile-cont-with-
// group-by prompt rule: the model does not reliably self-check this, so it
// is caught here instead.
//
// The correct rewrite computes the window function over the raw rows in a
// subquery, then GROUP BYs the result outside. That rewrite also contains
// both "PARTITION BY x" and "GROUP BY x" -- just in two different scopes --
// so a check that only looks for both phrases anywhere in the text would
// flag the fix along with the bug. The distinguishing fact is scope: a
// PARTITION BY enclosed by any parenthesized span that itself contains a
// SELECT is inside a subquery and is safe, no matter which column it names.
// Only a PARTITION BY with no such enclosing subquery -- sitting at the same
// level as the query's own GROUP BY -- can collapse to one row per group.
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

	var groupCols []string
	sawTopLevelGroupBy := false
	var topLevelPartitionCols [][]string

	i := 0
	n := len(query)
	for i < n {
		c := query[i]
		switch c {
		case '\'', '"', '`':
			j := i + 1
			for j < n && query[j] != c {
				j++
			}
			i = j + 1
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
				topLevelPartitionCols = append(topLevelPartitionCols, cols)
				i = next
				continue
			}
			i = matchEnd(query, i, `partition\s+by`)
			continue
		}
		if groupByAt[i] {
			if depth == 0 {
				cols, next := readColumnList(query, matchEnd(query, i, `group\s+by`))
				groupCols = cols
				sawTopLevelGroupBy = true
				i = next
				continue
			}
			i = matchEnd(query, i, `group\s+by`)
			continue
		}
		i++
	}

	if !sawTopLevelGroupBy {
		return "", false
	}

	// The collapse to one row per partition only happens if the GROUP BY key
	// is held constant within that partition -- i.e. every column GROUP BY
	// groups by is also named by that PARTITION BY. GROUP BY day, netid with
	// PARTITION BY netid alone is not degenerate: within one netid-partition,
	// there is still one row per distinct day, because day is part of the
	// group key but not held constant by the partition. Only when the
	// partition's columns are a superset of the group's -- commonly, the
	// same single column on both sides -- can the partition it sees be down
	// to one row.
	for _, cols := range topLevelPartitionCols {
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
// statement for a top-level GROUP BY.
func readColumnList(query string, from int) (cols []string, next int) {
	stop := regexp.MustCompile(`(?i)\b(order\s+by|having|limit|window)\b`)
	depth := 0
	end := len(query)
	for i := from; i < len(query); i++ {
		switch query[i] {
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
		// A GROUP BY / PARTITION BY item can be an expression, not just a bare
		// column ("StartTime - SubmitTime"); only a bare identifier can ever
		// match the other clause's bare identifier, so anything with a space
		// or operator in it cannot conflict and is kept as-is for that reason
		// rather than parsed further.
		if part != "" {
			cols = append(cols, part)
		}
	}
	return cols, end
}
