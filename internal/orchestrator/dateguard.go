package orchestrator

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bindatype/cassandra/internal/broker"
)

// runTBL2_jobs carries submit_month as text, '2026-09', and submit_day as a
// DATE, '2026-09-15'. A comparison with anything else matches no rows, and the
// answer reads as a real zero. Graded case F2 failed this way in one run of
// three on 2026-10-18 and in two of three on 2026-10-23: submit_month = 9,
// submit_month = 'September', and submit_day BETWEEN 1 AND 30. This refuses
// the comparison before it runs and says what the column holds.
var (
	derivedDateComparison = regexp.MustCompile(
		`(?i)\b(submit_month|submit_day)\b\s*(?:=|<>|!=|<=|>=|<|>)\s*('[^']*'|"[^"]*"|[^\s,)]+)`)
	derivedDateBetween = regexp.MustCompile(
		`(?i)\b(submit_month|submit_day)\b\s+(?:not\s+)?between\s+('[^']*'|"[^"]*"|[^\s]+)\s+and\s+('[^']*'|"[^"]*"|[^\s,)]+)`)
	derivedDateIn = regexp.MustCompile(
		`(?i)\b(submit_month|submit_day)\b\s+(?:not\s+)?in\s*\(([^)]*)\)`)
	monthLiteral = regexp.MustCompile(`^'\d{4}-\d{2}'$`)
	dayLiteral   = regexp.MustCompile(`^'\d{4}-\d{2}-\d{2}'$`)
)

// derivedDateFilter reports a database query that compares submit_month or
// submit_day with a value in the wrong form.
func derivedDateFilter(request broker.RouteRequest) error {
	if request.Intent != broker.IntentDatabaseQuery {
		return nil
	}
	query := request.Query
	var bad []string
	check := func(column, value string) {
		value = strings.TrimSpace(value)
		value = strings.ReplaceAll(value, `"`, "'")
		form := monthLiteral
		if strings.EqualFold(column, "submit_day") {
			form = dayLiteral
		}
		// Another column, a function or an expression is not a literal and
		// is left to the database.
		if !strings.HasPrefix(value, "'") && !regexp.MustCompile(`^-?\d+$`).MatchString(value) {
			return
		}
		if !form.MatchString(value) {
			bad = append(bad, strings.ToLower(column)+" compared with "+value)
		}
	}
	for _, m := range derivedDateComparison.FindAllStringSubmatch(query, -1) {
		check(m[1], m[2])
	}
	for _, m := range derivedDateBetween.FindAllStringSubmatch(query, -1) {
		check(m[1], m[2])
		check(m[1], m[3])
	}
	for _, m := range derivedDateIn.FindAllStringSubmatch(query, -1) {
		for _, v := range strings.Split(m[2], ",") {
			check(m[1], v)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("this query compares a runTBL2_jobs date column with a value in the wrong form (%s), "+
		"which matches no rows and would read as zero. submit_month is text like '2026-09' and submit_day is a "+
		"date like '2026-09-15'. Better still, filter the window on SubmitTime, which uses the index: "+
		"SubmitTime >= UNIX_TIMESTAMP('2026-09-01') AND SubmitTime < UNIX_TIMESTAMP('2026-10-01')",
		strings.Join(bad, "; "))
}
