package connector

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
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

// TestPegasusCountsOnlyWhenTheResultWasCut pins the end of a second execution
// on every query. A result read to the end already knows its total; only one
// stopped at the row or byte bound needs COUNT(*) to say how much it left out.
func TestPegasusCountsOnlyWhenTheResultWasCut(t *testing.T) {
	const query = "SELECT netid FROM jobs2VIEW"

	cases := []struct {
		name          string
		rows          int
		limit         int
		wantCount     bool
		wantTotal     int
		wantTruncated bool
	}{
		{"complete result", 3, 0, false, 3, false},
		{"empty result", 0, 0, false, 0, false},
		{"cut at the row limit", 5, 2, true, 5, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAccountingDB{rows: tc.rows}
			connector := &PegasusConnector{
				db:               sql.OpenDB(fake),
				maxRows:          pegasusDefaultMaxRows,
				maxBytes:         pegasusMaxTotalBytes,
				statementTimeout: time.Second,
			}
			defer connector.Close()

			evidence, err := connector.Execute(context.Background(), broker.RouteStep{
				Source: broker.SourcePegasusDB,
				Action: "query.execute",
				Query:  query,
				Limit:  tc.limit,
			})
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if counted := fake.ranCount(); counted != tc.wantCount {
				t.Errorf("COUNT(*) ran = %v, want %v; statements: %q", counted, tc.wantCount, fake.statements())
			}
			if evidence.TotalAvailable != tc.wantTotal || evidence.Summary["total_matching"] != tc.wantTotal {
				t.Errorf("total = %d (summary %d), want %d",
					evidence.TotalAvailable, evidence.Summary["total_matching"], tc.wantTotal)
			}
			if evidence.Truncated != tc.wantTruncated {
				t.Errorf("Truncated = %v, want %v", evidence.Truncated, tc.wantTruncated)
			}
		})
	}
}

// fakeAccountingDB is a database/sql connector that serves a fixed number of
// one-column rows, answers the COUNT(*) wrapper with that number, and records
// every statement it is sent.
type fakeAccountingDB struct {
	rows int

	mu   sync.Mutex
	sent []string
}

func (f *fakeAccountingDB) Connect(context.Context) (driver.Conn, error) { return fakeConn{f}, nil }
func (f *fakeAccountingDB) Driver() driver.Driver                        { return nil }

func (f *fakeAccountingDB) record(query string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, query)
}

func (f *fakeAccountingDB) statements() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

func (f *fakeAccountingDB) ranCount() bool {
	for _, query := range f.statements() {
		if strings.HasPrefix(query, "SELECT COUNT(*) FROM (") {
			return true
		}
	}
	return false
}

type fakeConn struct{ db *fakeAccountingDB }

func (c fakeConn) Prepare(query string) (driver.Stmt, error) { return fakeStmt{c.db, query}, nil }
func (c fakeConn) Close() error                              { return nil }
func (c fakeConn) Begin() (driver.Tx, error)                 { return nil, fmt.Errorf("no transactions") }

type fakeStmt struct {
	db    *fakeAccountingDB
	query string
}

func (s fakeStmt) Close() error  { return nil }
func (s fakeStmt) NumInput() int { return -1 }

func (s fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	s.db.record(s.query)
	return driver.ResultNoRows, nil
}

func (s fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	s.db.record(s.query)
	if strings.HasPrefix(s.query, "SELECT COUNT(*) FROM (") {
		return &fakeRows{column: "COUNT(*)", values: []string{fmt.Sprint(s.db.rows)}}, nil
	}
	values := make([]string, s.db.rows)
	for i := range values {
		values[i] = fmt.Sprintf("user%d", i)
	}
	return &fakeRows{column: "netid", values: values}, nil
}

type fakeRows struct {
	column string
	values []string
	next   int
}

func (r *fakeRows) Columns() []string { return []string{r.column} }
func (r *fakeRows) Close() error      { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.next >= len(r.values) {
		return io.EOF
	}
	dest[0] = []byte(r.values[r.next])
	r.next++
	return nil
}

func TestAccountingNotesStateTheDefinitionAndTheTime(t *testing.T) {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

	view := accountingNotes("SELECT workload, COUNT(*) FROM runTBL2_workload WHERE SubmitTime > 0 GROUP BY workload", at)
	if len(view) != 3 || view[0] != workloadDefinition || view[1] != workloadReporting ||
		!strings.Contains(view[2], "as of 2026-10-06T12:00:00Z") {
		t.Errorf("view query notes = %q, want the definition, what to report, and the as-of time", view)
	}
	for _, want := range []string{"1778299200", "before and after", "excluded or unclassified"} {
		if !strings.Contains(workloadReporting, want) {
			t.Errorf("the reporting note lacks %q", want)
		}
	}
	table := accountingNotes("SELECT COUNT(*) FROM runTBL2 WHERE SubmitTime > 0", at)
	if len(table) != 1 || !strings.Contains(table[0], "as of") || !strings.Contains(table[0], "can still grow") {
		t.Errorf("runTBL2 query notes = %q, want the as-of note only", table)
	}
	if other := accountingNotes("SELECT COUNT(*) FROM jobs2VIEW WHERE SubmitTime > 0", at); len(other) != 0 {
		t.Errorf("a query on another table got notes: %q", other)
	}
}

// A memory total needs its unit and its coverage: both columns are null before
// 22 January 2026.
func TestAccountingNotesCoverMemoryColumns(t *testing.T) {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	notes := accountingNotes("SELECT TRESalloc_mem, COUNT(*) FROM runTBL2 WHERE SubmitTime > 0 GROUP BY TRESalloc_mem", at)
	if len(notes) != 2 || notes[0] != memoryNote || !strings.Contains(notes[1], "as of") {
		t.Errorf("memory query notes = %q, want the memory note and the as-of time", notes)
	}
	for _, want := range []string{"22 January 2026", "GB", "no memory value"} {
		if !strings.Contains(memoryNote, want) {
			t.Errorf("the memory note lacks %q", want)
		}
	}
}

// The definition note restates the view. If the view's rules change and the
// note does not, answers would describe a definition that is no longer applied.
func TestWorkloadDefinitionMatchesTheView(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "pegasusdb", "runTBL2_workload.sql"))
	if err != nil {
		t.Fatalf("read the view: %v", err)
	}
	body := string(raw)
	body = body[strings.Index(body, "CREATE OR REPLACE"):]
	names := func(pattern string) []string {
		m := regexp.MustCompile(pattern).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("the view no longer has a list matching %s", pattern)
		}
		return regexp.MustCompile(`'([^']+)'`).FindAllString(m[1], -1)
	}
	// Every excluded partition is named in the note.
	for _, quoted := range names("IN \\(([^)]*)\\) THEN 'excluded'") {
		if name := strings.Trim(quoted, "'"); !strings.Contains(workloadDefinition, name) {
			t.Errorf("the view excludes %q but the note does not say so", name)
		}
	}
	// Every pre-cutover GPU partition is named, except the legacy -gpu ones,
	// which the note covers as a family.
	for _, quoted := range names("superChip%'\\s+OR r\\.`partition` IN \\(([^)]*)\\) THEN 'gpu'") {
		name := strings.Trim(quoted, "'")
		if strings.HasSuffix(name, "-gpu") {
			if !strings.Contains(workloadDefinition, "legacy -gpu partitions") {
				t.Errorf("the view counts %q as GPU but the note does not mention the legacy -gpu partitions", name)
			}
			continue
		}
		if !strings.Contains(workloadDefinition, name) {
			t.Errorf("the view counts %q as GPU but the note does not say so", name)
		}
	}
	for _, want := range []string{"1778299200", "superChip*", "--gres"} {
		if !strings.Contains(workloadDefinition, want) {
			t.Errorf("the definition note lacks %q", want)
		}
		if want != "--gres" && !strings.Contains(body, strings.ReplaceAll(want, "*", "%")) {
			t.Errorf("the view no longer has %q, which the note describes", want)
		}
	}
}
