package connector

import (
	"strings"
	"testing"
	"time"
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

// TestPegasusBoundsComeFromOneValue pins the fix for three limits that
// disagreed: the driver's socket timeout came from the DSN, the connector's
// context came from a constant, and max_statement_time came from the constant
// too -- so the server-side limit sat at twice the client's and could never
// fire first.
func TestPegasusBoundsComeFromOneValue(t *testing.T) {
	// A DSN carrying its own, tighter timeouts -- the shape that was deployed.
	const dsn = "u:p@tcp(db.invalid:3306)/pegasusdb?timeout=10s&readTimeout=30s&parseTime=false"

	connector, err := NewPegasusConnector(PegasusConfig{DSN: dsn, Timeout: 45 * time.Second})
	if err != nil {
		t.Fatalf("NewPegasusConnector() error = %v", err)
	}

	// The server must give up before the client, so a slow query ends as a
	// diagnosis from MariaDB rather than as a disconnection that could equally
	// be a network fault.
	if connector.statementTimeout >= 45*time.Second {
		t.Errorf("statement timeout %s does not precede the connection timeout 45s",
			connector.statementTimeout)
	}
	if connector.statementTimeout <= 0 {
		t.Errorf("statement timeout %s would disable the server-side limit", connector.statementTimeout)
	}
}

// TestPegasusRejectsAStatementTimeoutPastTheConnection refuses the
// configuration that started this: a server-side limit that can never fire
// because the client gives up first. Accepting it silently is what made the
// protection look real.
func TestPegasusRejectsAStatementTimeoutPastTheConnection(t *testing.T) {
	_, err := NewPegasusConnector(PegasusConfig{
		DSN:              "u:p@tcp(db.invalid:3306)/pegasusdb",
		Timeout:          10 * time.Second,
		StatementTimeout: 60 * time.Second,
	})
	if err == nil {
		t.Fatal("a statement timeout beyond the connection timeout was accepted")
	}
	if !strings.Contains(err.Error(), "never fire first") {
		t.Errorf("error does not explain the consequence: %v", err)
	}
}
