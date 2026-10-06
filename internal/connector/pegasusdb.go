package connector

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

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

	return Evidence{
		Source:         string(broker.SourcePegasusDB),
		Action:         step.Action,
		Endpoint:       c.endpoint,
		Query:          step.Query,
		Notes:          accountingNotes(step.Query, requestedAt),
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
	if strings.Contains(lower, "runtbl2") {
		notes = append(notes, "as of "+requestedAt.Format(time.RFC3339)+": totals for a past window can still "+
			"grow until every job submitted in it has finished and been ingested, so quote this time with the figures")
	}
	return notes
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
