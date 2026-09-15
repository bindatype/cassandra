package connector

import (
	"strings"
	"testing"
)

// TestDialectHintFiresOnlyOnTheMistakeItExplains pins a hint that is worse than
// useless if it appears on unrelated failures: a wrong explanation attached to
// a real error sends the reader somewhere else entirely.
func TestDialectHintFiresOnlyOnTheMistakeItExplains(t *testing.T) {
	const syntaxErr = "Error 1064 (42000): You have an error in your SQL syntax; " +
		"check the manual ... near 'OVER () / 60 AS p25_min' at line 2"

	cases := []struct {
		name  string
		query string
		err   string
		want  bool
	}{
		{"the real case", "SELECT PERCENTILE_CONT(0.25) OVER () FROM runTBL2", syntaxErr, true},
		{"the disc spelling", "SELECT PERCENTILE_DISC(0.9) OVER () FROM runTBL2", syntaxErr, true},
		{"lower case", "select percentile_cont(0.5) over () from runTBL2", syntaxErr, true},
		{"already correct, so a syntax error means something else",
			"SELECT PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY x) OVER (), FROM runTBL2", syntaxErr, false},
		{"a syntax error with no percentile in it",
			"SELECT COUNT(*) FROM WHERE", syntaxErr, false},
		{"percentile present but the failure is not syntax",
			"SELECT PERCENTILE_CONT(0.25) OVER () FROM runTBL2",
			"Error 1146 (42S02): Table 'pegasusdb.runTBL9' doesn't exist", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dialectHint(tc.query, tc.err) != ""; got != tc.want {
				t.Errorf("dialectHint fired=%v, want %v", got, tc.want)
			}
		})
	}

	// The hint has to carry the correction, not merely announce that one
	// exists. A model told it is wrong without being told the form tries
	// another wrong form, which is the loop this replaces.
	hint := dialectHint("SELECT PERCENTILE_CONT(0.25) OVER ()", syntaxErr)
	for _, want := range []string{"WITHIN GROUP", "ORDER BY", "MariaDB"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint does not mention %q; it says something is wrong without saying what", want)
		}
	}
}
