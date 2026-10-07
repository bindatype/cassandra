package orchestrator

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bindatype/cassandra/internal/broker"
)

// TRESReq_mem and TRESalloc_mem are text with a unit suffix: 512M, 16G, 1T.
// Observed 2026-10-06: asked how much memory GPU jobs requested, the model
// wrote SUM(CAST(TRESReq_mem AS UNSIGNED)) with the column table telling it
// to convert units first. CAST keeps the leading digits, so 16G added 16 and
// 512M added 512, and the answer was "6,662,568 units" against a true
// 124,959 GB. This refuses a numeric use of either column that does not read
// the suffix, and hands back the expression that does.
var memoryColumn = regexp.MustCompile("(?i)(?:\\b\\w+\\.)?`?\\btres(?:req|alloc)_mem\\b`?")

var (
	// Immediately before the column: a numeric function, an operator, or a sort.
	memoryNumericBefore = regexp.MustCompile(`(?is)(?:\b(?:cast|convert|sum|avg|min|max)\s*\(\s*(?:distinct\s+)?|[*/+%-]\s*|(?:<=|>=|<|>)\s*|\bbetween\s+|\border\s+by\s+(?:[^()]*,\s*)?)$`)
	// Immediately after the column: a test on its text. SUM(TRESReq_mem IS
	// NULL) counts jobs; it adds no sizes.
	memoryTextTestAfter = regexp.MustCompile(`(?is)^\s*(?:is\b|=|<>|!=|(?:not\s+)?(?:like|rlike|regexp|in)\b)`)
	// Immediately after the column: an operator or a range comparison.
	memoryNumericAfter = regexp.MustCompile(`(?is)^\s*(?:<=|>=|<|>|[*/+%]|-|\bbetween\b)`)
	// A string function that strips the suffix and leaves digits behind. Fine
	// when the query also reads the suffix, which is the conversion.
	memoryStripBefore = regexp.MustCompile(`(?is)\b(?:left|substring|substr|mid|replace|regexp_replace|regexp_substr|trim)\s*\(\s*$`)
	// Reading the unit: RIGHT(col, 1), SUBSTRING(col, -1), or a pattern on M, G or T.
	memorySuffixRead = regexp.MustCompile("(?is)\\bright\\s*\\(\\s*(?:\\w+\\.)?`?tres(?:req|alloc)_mem`?|" +
		"\\bsubstr(?:ing)?\\s*\\(\\s*(?:\\w+\\.)?`?tres(?:req|alloc)_mem`?\\s*,\\s*-1|" +
		"tres(?:req|alloc)_mem`?\\s+(?:not\\s+)?(?:like|rlike|regexp)\\s+'[^']*[mgt][^']*'")
)

// memoryToGB is the conversion the refusal hands back. It is the query that
// produced the 124,959 GB ground truth, so it is known to run.
const memoryToGB = "CASE RIGHT(TRESReq_mem,1) " +
	"WHEN 'T' THEN CAST(LEFT(TRESReq_mem, CHAR_LENGTH(TRESReq_mem)-1) AS DECIMAL(20,3))*1024 " +
	"WHEN 'G' THEN CAST(LEFT(TRESReq_mem, CHAR_LENGTH(TRESReq_mem)-1) AS DECIMAL(20,3)) " +
	"WHEN 'M' THEN CAST(LEFT(TRESReq_mem, CHAR_LENGTH(TRESReq_mem)-1) AS DECIMAL(20,3))/1024 END"

// memoryUnitFilter reports a database query that adds, averages, compares or
// sorts a memory column without converting its unit. Selecting, grouping and
// matching the raw text pass.
func memoryUnitFilter(request broker.RouteRequest) error {
	if request.Intent != broker.IntentDatabaseQuery {
		return nil
	}
	query := request.Query
	occurrences := memoryColumn.FindAllStringIndex(query, -1)
	if len(occurrences) == 0 {
		return nil
	}
	numeric, stripped := false, false
	for _, at := range occurrences {
		before, after := query[:at[0]], query[at[1]:]
		trimmedAfter := strings.TrimLeft(after, " \t\r\n")
		// <> and != are equality tests on the text, and -- starts a comment.
		notOperator := strings.HasPrefix(trimmedAfter, "<>") || strings.HasPrefix(trimmedAfter, "--")
		textTest := memoryTextTestAfter.MatchString(after)
		if memoryNumericBefore.MatchString(before) && !textTest && !strings.HasSuffix(strings.TrimRight(before, " \t\r\n"), "<>") ||
			memoryNumericAfter.MatchString(after) && !notOperator {
			numeric = true
		}
		if memoryStripBefore.MatchString(before) {
			stripped = true
		}
	}
	if !numeric && !(stripped && !memorySuffixRead.MatchString(query)) {
		return nil
	}
	return fmt.Errorf("this query uses a memory column as a number, but TRESReq_mem and TRESalloc_mem are text "+
		"with a unit suffix (512M, 16G, 1T): CAST('16G' AS UNSIGNED) is 16 and CAST('512M' AS UNSIGNED) is 512, "+
		"so a sum, average, comparison or sort mixes units. Convert to GB first, and do the same for "+
		"TRESalloc_mem: %s. Memory is recorded only from 22 January 2026, and an empty or null value converts "+
		"to NULL and is not counted, so say how many jobs in the window had none", memoryToGB)
}
