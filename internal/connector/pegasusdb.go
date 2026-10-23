package connector

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	// The epoch notes need the server's zone whether or not the host running
	// Cassandra has zoneinfo installed.
	_ "time/tzdata"

	"github.com/bindatype/cassandra/internal/broker"
	"github.com/go-sql-driver/mysql"
)

const (
	pegasusDefaultTimeout = 60 * time.Second
	// Binds only on genuine listings; aggregates return a row or a few.
	// CASS_PEGASUS_MAX_ROWS overrides it.
	pegasusDefaultMaxRows = 500
	pegasusMaxCellBytes   = 4096
	// Kept below the orchestrator's 64 KB evidence cap (maxEvidenceJSON),
	// which discards an oversized result whole: a result that passes here but
	// fails there is a query that succeeds and still returns nothing.
	// CASS_PEGASUS_MAX_BYTES overrides it; raise CASS_MAX_EVIDENCE with it.
	pegasusMaxTotalBytes = 48 * 1024
)

// PegasusConfig carries operator-supplied connection details.
//
// Unlike the other connectors this one runs a query the model wrote, so the
// controls bound time and result size rather than which operations exist.
// That is acceptable only because the credential is SELECT-only on one
// schema.
type PegasusConfig struct {
	DSN              string
	Timeout          time.Duration
	MaxRows          int
	MaxBytes         int
	StatementTimeout time.Duration
}

// PegasusConnector runs read-only queries against the accounting database.
type PegasusConnector struct {
	db               *sql.DB
	maxRows          int
	maxBytes         int
	statementTimeout time.Duration
	endpoint         string
	// zoneNote is the server's zone, read once; see serverZoneNote.
	zoneOnce sync.Once
	zoneNote string
}

// NewPegasusConnector validates configuration and opens a pooled connection.
func NewPegasusConnector(config PegasusConfig) (*PegasusConnector, error) {
	if config.DSN == "" {
		return nil, fmt.Errorf("pegasus DSN is required")
	}
	parsed, err := mysql.ParseDSN(config.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse pegasus DSN: %w", err)
	}
	if parsed.DBName == "" {
		return nil, fmt.Errorf("pegasus DSN must name a database")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = pegasusDefaultTimeout
	}

	// One value sets the dial, read and statement limits. The DSN's own
	// timeouts are overwritten: if they were lower, the client would give up
	// before the server-side limit, which protects the database, could fire.
	parsed.Timeout = timeout
	parsed.ReadTimeout = timeout
	dsn := parsed.FormatDSN()
	maxRows := config.MaxRows
	if maxRows <= 0 {
		maxRows = pegasusDefaultMaxRows
	}
	maxBytes := config.MaxBytes
	if maxBytes <= 0 {
		maxBytes = pegasusMaxTotalBytes
	}
	// The server limit defaults to 90% of the client's, so a slow query ends
	// as MariaDB's "max_statement_time exceeded" (a diagnosis) rather than a
	// dropped connection (which looks like a network fault).
	statementTimeout := config.StatementTimeout
	if statementTimeout <= 0 {
		statementTimeout = timeout - timeout/10
	}
	if statementTimeout > timeout {
		return nil, fmt.Errorf("pegasus statement timeout %s exceeds the connection timeout %s; "+
			"the server-side limit would never fire first", statementTimeout, timeout)
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open pegasus: %w", err)
	}
	db.SetMaxOpenConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	return &PegasusConnector{
		db:               db,
		maxRows:          maxRows,
		maxBytes:         maxBytes,
		statementTimeout: statementTimeout,
		// Recorded for provenance without the credential the DSN carries.
		endpoint: parsed.Addr + "/" + parsed.DBName,
	}, nil
}

// Close releases pooled connections.
func (c *PegasusConnector) Close() error { return c.db.Close() }

// Source reports which route-step source this connector serves.
func (c *PegasusConnector) Source() broker.Source {
	return broker.SourcePegasusDB
}

// Execute runs one query and returns normalized evidence.
func (c *PegasusConnector) Execute(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Source != broker.SourcePegasusDB {
		return Evidence{}, newConnectorError("wrong_source", "step is not a pegasus-db step")
	}
	if step.Action != "query.execute" {
		return Evidence{}, newConnectorError("unsupported_action", fmt.Sprintf("action %q is not executable", step.Action))
	}
	// The planner already validated the query; re-check so the connector is
	// safe to call directly.
	if err := broker.ValidateQuery(step.Query); err != nil {
		return Evidence{}, newConnectorError("invalid_query", err.Error())
	}

	rowLimit := c.maxRows
	if step.Limit > 0 && step.Limit < rowLimit {
		rowLimit = step.Limit
	}

	requestedAt := time.Now().UTC()
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return Evidence{}, newConnectorError("transport", err.Error())
	}
	defer conn.Close()

	// MariaDB's default statement limit is unlimited. Read-only protects the
	// data, not the service.
	millis := c.statementTimeout.Milliseconds()
	if _, err := conn.ExecContext(ctx, "SET SESSION max_statement_time = ?", float64(millis)/1000.0); err != nil {
		return Evidence{}, newConnectorError("transport", "could not bound statement time: "+err.Error())
	}

	rows, err := conn.QueryContext(ctx, step.Query)
	if err != nil {
		return Evidence{}, newConnectorError("query_failed", err.Error()+dialectHint(step.Query, err.Error()))
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return Evidence{}, newConnectorError("query_failed", err.Error())
	}

	items, capped, err := scanRows(rows, columns, rowLimit, c.maxBytes)
	if err != nil {
		return Evidence{}, err
	}
	rows.Close()

	// The full row count, so a truncated result can be told from a complete
	// one. The rows can't show it: a grouped aggregate missing half its groups
	// still looks well formed. A result that stopped at neither bound was read
	// to the end, so its total is the rows returned and needs no second run.
	total := len(items)
	if capped {
		total, err = c.countRows(ctx, conn, step.Query)
		if err != nil {
			return Evidence{}, err
		}
	}

	summary := map[string]int{
		"returned":       len(items),
		"total_matching": total,
		"columns":        len(columns),
	}
	truncated := capped || total > len(items)
	if truncated {
		summary["row_limit"] = rowLimit
	}

	notes := accountingNotes(step.Query, requestedAt)
	if localTimeFunction.MatchString(step.Query) {
		if note := c.serverZoneNote(ctx, conn); note != "" {
			notes = append(notes, note)
		}
	}
	return Evidence{
		Source:         string(broker.SourcePegasusDB),
		Action:         step.Action,
		Endpoint:       c.endpoint,
		Query:          step.Query,
		Notes:          notes,
		RequestedAt:    requestedAt,
		DurationMS:     time.Since(requestedAt).Milliseconds(),
		ItemCount:      len(items),
		TotalAvailable: total,
		Truncated:      truncated,
		Summary:        summary,
		Items:          items,
	}, nil
}

// workloadDefinition states, for the reader, how runTBL2_workload classifies
// a job. It mirrors configs/pegasusdb/runTBL2_workload.sql, and a test holds
// the two together.
const workloadDefinition = "workload comes from the runTBL2_workload view: from 9 May 2026 (epoch 1778299200) " +
	"a job is gpu if it requested a GPU (--gres), on any partition, and cpu otherwise; before then it is " +
	"classified by partition, with gpu, viz, ait, any superChip* and the legacy -gpu partitions as gpu; " +
	"nano, the staff partitions deus, purge, secret and secret-gpu, and unresolved multi-partition requests " +
	"are excluded; a partition no rule covers is unclassified"

// workloadReporting is what an answer from the view must also give. It was a
// prompt rule first, and in a live check the model gave neither part; the
// as-of note beside it, carried in evidence, was quoted in every answer.
const workloadReporting = "before answering, also give: for a window that spans 9 May 2026, the counts before " +
	"and after that instant as well as the total (group by SubmitTime >= 1778299200); and how many jobs in the " +
	"window were excluded or unclassified, naming the unclassified partitions. Run one more query for these if " +
	"this result does not already show them"

// finalAttemptNote goes with any runTBL2 result that reads State. On
// 2026-10-23 a count of 56 failed jobs in an incident window was reported
// without a caveat; the scheduler's own accounting showed 111, because the
// requeued jobs' failed attempts are not rows here.
const finalAttemptNote = "runTBL2 keeps one row per JobID, holding that job's final attempt only. A job that " +
	"failed (for example NODE_FAIL) and was requeued appears once, with the state of its last attempt, so a " +
	"count of failures, lost work or incident impact from it counts final outcomes and misses earlier failed " +
	"attempts. Say so when reporting such a count"

// localTimeFunction matches the functions that read or write the server's
// local time, as opposed to the zone-free Unix-second columns.
var localTimeFunction = regexp.MustCompile(`(?i)\b(from_unixtime|unix_timestamp\s*\(\s*'|now\s*\(|curdate|current_date|current_timestamp|sysdate)`)

// serverZoneNote names the zone this database renders local times in. It is
// read from the server once per connector, not assumed: on 2026-10-23 its
// times were EDT while Zabbix and Wazuh evidence beside them was UTC, and
// nothing said so. A failed read leaves no note rather than failing the query.
func (c *PegasusConnector) serverZoneNote(ctx context.Context, conn *sql.Conn) string {
	c.zoneOnce.Do(func() {
		var system, session string
		if err := conn.QueryRowContext(ctx, "SELECT @@system_time_zone, @@session.time_zone").Scan(&system, &session); err != nil {
			return
		}
		c.zoneNote = fmt.Sprintf("this database renders times in its server zone, %s (time_zone=%s): FROM_UNIXTIME, "+
			"NOW() and UNIX_TIMESTAMP('...') read and write local time there, while SubmitTime, StartTime and EndTime "+
			"are Unix seconds and have no zone. Times this query formats are in that zone; Zabbix and Wazuh "+
			"evidence is UTC unless it carries a _local twin", system, session)
	})
	return c.zoneNote
}

// memoryNote goes with any result that touches a memory column. Before 22
// January 2026 both columns are null, so a total over a window that starts
// earlier silently covers part of it.
const memoryNote = "TRESReq_mem and TRESalloc_mem hold a size with a unit suffix (M, G or T) and are recorded " +
	"only from 22 January 2026; earlier rows are null. Give memory totals in GB; if the window starts before " +
	"22 January 2026, say that memory covers only the part from then on; and say how many jobs in the window " +
	"had no memory value"

// accountingNotes are what an accounting answer needs and the rows cannot
// show: which definition produced a workload count, and that a past window's
// totals are a snapshot. Jobs submitted in a window keep arriving until they
// finish and are ingested: a count for 9 May-29 Sep grew by four overnight.
func accountingNotes(query string, requestedAt time.Time) []string {
	lower := strings.ToLower(query)
	var notes []string
	if strings.Contains(lower, "runtbl2_workload") {
		notes = append(notes, workloadDefinition, workloadReporting)
	}
	if strings.Contains(lower, "tresreq_mem") || strings.Contains(lower, "tresalloc_mem") {
		notes = append(notes, memoryNote)
	}
	if strings.Contains(lower, "runtbl2") {
		notes = append(notes, "as of "+requestedAt.Format(time.RFC3339)+": totals for a past window can still "+
			"grow until every job submitted in it has finished and been ingested, so quote this time with the figures")
		if strings.Contains(lower, "state") {
			notes = append(notes, finalAttemptNote)
		}
	}
	notes = append(notes, fiscalYearNotes(lower)...)
	notes = append(notes, epochNotes(query)...)
	notes = append(notes, offsetLiteralNotes(query)...)
	return notes
}

// offsetLiteral matches a time literal that carries a zone offset or Z.
var offsetLiteral = regexp.MustCompile(`'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)(Z|[+-]\d{2}:?\d{2})'`)

// offsetLiteralNotes flags a time literal written with an offset. MariaDB
// 10.3 truncates the offset with only a warning and reads the rest as server
// time, measured 2026-10-23: '... 21:50:00+00:00' and '... 21:50:00-04:00'
// gave the same epoch. An offset other than the server's own then moves the
// window by hours without an error.
func offsetLiteralNotes(query string) []string {
	var notes []string
	seen := map[string]bool{}
	for _, match := range offsetLiteral.FindAllStringSubmatch(query, -1) {
		if seen[match[0]] {
			continue
		}
		seen[match[0]] = true
		notes = append(notes, fmt.Sprintf("the literal %s carries the offset %s, which this server ignores: it was "+
			"read as %s in the server's own zone. If the offset differs from the server's, the window is off by "+
			"the difference; write the time as server-local instead", match[0], match[2], match[1]))
	}
	return notes
}

// fiscalYearCoverage is the submit-time span each fiscal-year table holds,
// measured on the live tables (MIN and MAX of SubmitTime) on 2026-10-18. A
// fiscal year ends on 30 June; its earliest rows were submitted before the
// year began and finished in it. Closed years do not change.
var fiscalYearCoverage = map[string][2]string{
	"fy2019": {"2019-03-05", "2019-06-30"},
	"fy2020": {"2019-06-24", "2020-06-30"},
	"fy2021": {"2020-06-26", "2021-06-30"},
	"fy2022": {"2021-05-22", "2022-06-30"},
	"fy2023": {"2022-06-30", "2023-06-30"},
	"fy2024": {"2023-06-04", "2024-06-30"},
	"fy2025": {"2024-02-01", "2025-06-30"},
	"fy2026": {"2025-06-15", "2026-06-30"},
}

var fiscalYearTable = regexp.MustCompile(`\bfy20\d\d\b`)

// fiscalYearNotes states the coverage of each fiscal-year table a query
// reads. A window past a closed table's end returns fewer rows rather than an
// error, and on 2026-10-18 an analysis of May-October read FY2026 and
// reported that the data stopped in July when runTBL2 held three more months.
func fiscalYearNotes(lowerQuery string) []string {
	var notes []string
	seen := map[string]bool{}
	for _, table := range fiscalYearTable.FindAllString(lowerQuery, -1) {
		if seen[table] {
			continue
		}
		seen[table] = true
		name := strings.ToUpper(table[:2]) + table[2:]
		span, known := fiscalYearCoverage[table]
		if !known {
			notes = append(notes, name+" is a fiscal-year table with no recorded coverage; runTBL2 and "+
				"runTBL2_jobs are current, so prefer them unless the question names this fiscal year")
			continue
		}
		notes = append(notes, fmt.Sprintf("%s holds only jobs submitted %s to %s; it is closed and gains no "+
			"rows. For anything submitted after %s, or a window that crosses it, use runTBL2_jobs, which is "+
			"current and has the same wait, run and school columns precomputed (wait_s, run_s, schoolName)",
			name, span[0], span[1], span[1]))
	}
	return notes
}

// pegasusTimeZone is the zone the accounting server runs in. Day boundaries
// in questions mean midnight here, and UNIX_TIMESTAMP('YYYY-MM-DD') on this
// server returns that midnight.
const pegasusTimeZone = "America/New_York"

var epochComparison = regexp.MustCompile(`(?i)\b(submittime|starttime|endtime)\s*` +
	`(?:>=|<=|<>|!=|=|<|>|between)\s*(\d{9,10})\b(?:\s+and\s+(\d{9,10})\b)?`)

// epochNotes renders, in the server's zone, each integer a time column is
// compared with, unless it is a local midnight. An epoch computed for UTC
// midnight starts a day four or five hours early here: on 2026-10-18 a
// May 9 cutoff written as 1778284800 began at 8 p.m. on May 8.
func epochNotes(query string) []string {
	zone, err := time.LoadLocation(pegasusTimeZone)
	if err != nil {
		return nil
	}
	var notes []string
	seen := map[string]bool{}
	for _, match := range epochComparison.FindAllStringSubmatch(query, -1) {
		for _, literal := range match[2:] {
			if literal == "" || seen[literal] {
				continue
			}
			seen[literal] = true
			seconds, err := strconv.ParseInt(literal, 10, 64)
			if err != nil {
				continue
			}
			local := time.Unix(seconds, 0).In(zone)
			if local.Hour() == 0 && local.Minute() == 0 && local.Second() == 0 {
				continue
			}
			notes = append(notes, fmt.Sprintf("%s is %s, not a midnight in the server's zone (%s). A day "+
				"here starts at local midnight, which UNIX_TIMESTAMP('%s') gives on this server; if %s was "+
				"meant as a date boundary, it is off by %s and the window covers the wrong rows",
				literal, local.Format("2006-01-02 15:04:05 MST"), pegasusTimeZone,
				nearestLocalMidnight(local).Format("2006-01-02"), literal, offsetFromMidnight(local)))
		}
	}
	return notes
}

// nearestLocalMidnight is the date the literal was most likely meant to be.
func nearestLocalMidnight(local time.Time) time.Time {
	midnight := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, local.Location())
	if local.Sub(midnight) > 12*time.Hour {
		return midnight.AddDate(0, 0, 1)
	}
	return midnight
}

func offsetFromMidnight(local time.Time) time.Duration {
	d := local.Sub(nearestLocalMidnight(local))
	if d < 0 {
		d = -d
	}
	return d
}

// countRows reports how many rows the query yields by wrapping it in
// COUNT(*). It costs a second execution, so Execute calls it only when the
// result was cut short; the Zabbix connector makes the same trade.
func (c *PegasusConnector) countRows(ctx context.Context, conn *sql.Conn, query string) (int, error) {
	wrapped := "SELECT COUNT(*) FROM (" + strings.TrimRight(strings.TrimSpace(query), "; \t\n\r") + ") AS cass_rowcount"

	var total int
	if err := conn.QueryRowContext(ctx, wrapped).Scan(&total); err != nil {
		return 0, newConnectorError("count_failed", err.Error())
	}
	return total, nil
}

// scanRows converts result rows into evidence items, stopping at the row limit
// or the byte budget, whichever comes first. The bound is enforced here
// because a valid SELECT can return millions of rows.
func scanRows(rows *sql.Rows, columns []string, maxRows, maxBytes int) ([]EvidenceItem, bool, error) {
	items := make([]EvidenceItem, 0, 64)
	totalBytes := 0

	for rows.Next() {
		if len(items) >= maxRows {
			return items, true, nil
		}

		holders := make([]any, len(columns))
		for i := range holders {
			holders[i] = new(sql.RawBytes)
		}
		if err := rows.Scan(holders...); err != nil {
			return nil, false, newConnectorError("scan_failed", err.Error())
		}

		fields := make(map[string]string, len(columns))
		for i, column := range columns {
			raw := *(holders[i].(*sql.RawBytes))
			value := string(raw)
			if raw == nil {
				value = ""
			}
			if len(value) > pegasusMaxCellBytes {
				value = value[:pegasusMaxCellBytes] + "…"
			}
			fields[column] = value
			totalBytes += len(column) + len(value)
		}

		items = append(items, EvidenceItem{
			ID:     strconv.Itoa(len(items)),
			Fields: fields,
		})

		if totalBytes >= maxBytes {
			return items, true, nil
		}
	}
	if err := rows.Err(); err != nil {
		// A statement killed by max_statement_time surfaces here, not at query
		// time, so name it.
		if strings.Contains(err.Error(), "max_statement_time") {
			return nil, false, newConnectorError("query_timeout", "query exceeded the configured statement time limit")
		}
		return nil, false, newConnectorError("query_failed", err.Error())
	}
	return items, false, nil
}

// dialectHint appends the fix for a MariaDB syntax error whose message doesn't
// explain itself: PERCENTILE_CONT or PERCENTILE_DISC without WITHIN GROUP
// (ORDER BY ...). Without it the model spent its turns on syntax, then
// substituted a wrong calculation and presented it as a percentile.
//
// It fires only on error 1064, only for those two functions, and only when
// WITHIN GROUP is absent, so it can't mislead a query that failed otherwise.
func dialectHint(query, failure string) string {
	if !strings.Contains(failure, "1064") {
		return ""
	}
	upper := strings.ToUpper(query)
	if !strings.Contains(upper, "PERCENTILE_CONT") && !strings.Contains(upper, "PERCENTILE_DISC") {
		return ""
	}
	if strings.Contains(upper, "WITHIN GROUP") {
		return ""
	}
	return " -- this is MariaDB: PERCENTILE_CONT and PERCENTILE_DISC are " +
		"ordered-set functions and require WITHIN GROUP (ORDER BY <expr>) " +
		"before OVER (). For example: PERCENTILE_CONT(0.9) WITHIN GROUP " +
		"(ORDER BY EndTime - StartTime) OVER () AS p90. Several percentiles " +
		"may be selected in one statement; add LIMIT 1 since OVER () repeats " +
		"the value on every row."
}
