package orchestrator

import (
	"regexp"
	"strings"
)

// Rule 9 asks every database answer to state the SQL it ran, and readers take
// that listing as proof. Observed 2026-10-08: asked for counts and wait times,
// the model ran two queries (the complete day and the counts), never ran the
// wait-time query, and answered with four wait-time figures and a "SQL Ran"
// block listing a percentile query that was never executed. The counts were
// real; the wait times were invented, and the listing vouched for them.
//
// unrunSQL finds SQL an answer quotes that this session did not execute. It
// compares text, not meaning, after removing what formatting changes: case,
// whitespace, backticks, trailing semicolons, spacing around punctuation. A
// quoted fragment of an executed query passes; elided SQL ("...") cannot be
// checked and is skipped.

var (
	fencedBlock = regexp.MustCompile("(?s)```[A-Za-z]*\n?(.*?)```")
	// Inline SQL starts at a backtick; quotedSQL unquotes the statement's own
	// identifiers (`partition`) and ends it at the next backtick on the line.
	inlineSQL    = regexp.MustCompile("(?im)`((?:SELECT|WITH)\\s[^\n]*)")
	sqlStart     = regexp.MustCompile(`(?is)^\s*(SELECT|WITH)\s`)
	sqlSpace     = regexp.MustCompile(`\s+`)
	sqlPunctGaps = regexp.MustCompile(`\s*([(),=<>*+/-])\s*`)
	// An identifier the statement quotes itself, such as `partition`.
	quotedIdent = regexp.MustCompile("`([A-Za-z_][A-Za-z0-9_]*)`")
)

// minClaimLength ignores fragments too short to be a claim about a query.
const minClaimLength = 15

func normalizeSQL(sql string) string {
	s := strings.ToLower(sql)
	s = strings.ReplaceAll(s, "`", "")
	s = sqlSpace.ReplaceAllString(s, " ")
	s = sqlPunctGaps.ReplaceAllString(s, "$1")
	return strings.TrimSpace(strings.TrimRight(strings.TrimSpace(s), ";"))
}

// quotedSQL returns the SELECT or WITH statements an answer quotes.
func quotedSQL(answer string) []string {
	var statements []string
	add := func(text string) {
		for _, part := range strings.Split(text, ";") {
			part = strings.TrimSpace(part)
			if sqlStart.MatchString(part) {
				statements = append(statements, part)
			}
		}
	}
	for _, m := range fencedBlock.FindAllStringSubmatch(answer, -1) {
		add(m[1])
	}
	outside := fencedBlock.ReplaceAllString(answer, " ")
	for _, m := range inlineSQL.FindAllStringSubmatch(outside, -1) {
		// Unquote the statement's own identifiers; the next backtick left is
		// the one that closes the inline span, and prose after it is not SQL.
		text := quotedIdent.ReplaceAllString(m[1], "$1")
		if end := strings.Index(text, "`"); end >= 0 {
			text = text[:end]
		}
		add(strings.TrimRight(strings.TrimSpace(text), ".,"))
	}
	return statements
}

// unrunSQL returns each statement the answer quotes that no call in this
// session executed. Failed attempts count as executed: they ran.
func unrunSQL(answer string, calls []AuditCall) []string {
	var executed []string
	for _, c := range calls {
		if q := normalizeSQL(c.Query); q != "" {
			executed = append(executed, q)
		}
	}
	var unrun []string
	for _, statement := range quotedSQL(answer) {
		if strings.Contains(statement, "...") || strings.Contains(statement, "…") {
			continue
		}
		claim := normalizeSQL(statement)
		if len(claim) < minClaimLength {
			continue
		}
		found := false
		for _, q := range executed {
			if strings.Contains(q, claim) {
				found = true
				break
			}
		}
		if !found {
			unrun = append(unrun, statement)
		}
	}
	return unrun
}

// unrunSQLWarning heads an answer that still quotes unexecuted SQL when no
// turn is left to fix it, so the claim cannot pass silently into a report.
const unrunSQLWarning = "Warning: this answer quotes SQL that Cassandra did not run; figures attributed to it are unverified."

func unrunSQLPushback(statement string) string {
	shown := sqlSpace.ReplaceAllString(strings.TrimSpace(statement), " ")
	if len(shown) > 200 {
		shown = shown[:200] + "..."
	}
	return "Your answer quotes SQL that was not run: " + shown + " Run it with " + toolName +
		" and answer from its result, or remove the figures that depend on it and say they were not computed."
}
