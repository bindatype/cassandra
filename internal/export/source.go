package export

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Source opens a read snapshot of the job records.
type Source interface {
	Snapshot(ctx context.Context) (Snapshot, error)
}

// Snapshot counts and reads one window from a single consistent view of the
// data. The exporter counts before and after reading; a source that cannot
// hold a snapshot still cannot produce a complete export that is silently
// short, because the counts and the rows written must all agree.
type Snapshot interface {
	AsOf() time.Time
	Describe() SourceInfo
	Query() string
	Count(ctx context.Context, start, end int64) (int64, error)
	Rows(ctx context.Context, start, end int64, each func(SourceRow) error) error
	Close() error
}

// SourceInfo is provenance for the manifest. It never carries a credential.
type SourceInfo struct {
	Endpoint string `json:"endpoint"`
	Database string `json:"database"`
	Relation string `json:"relation"`
	Engine   string `json:"engine"`
	Snapshot string `json:"snapshot"`
}

// exportColumns is the fixed column list. The exporter never takes SQL from
// a caller; every export reads exactly these, from the view.
const exportColumns = "JobID, netid, groupName, SubmitTime, `partition`, State, ReqCPUS, TRESReq_cpu, " +
	"TRESReq_node, TRESReq_gres_gpu, TRESReq_mem, TimelimitRaw, mem_req_gb, timelimit_min, gpus_req, nodes_req"

// RowsQuery is the one query that produces export rows. Ordered, so two
// exports of the same snapshot are byte-identical.
const RowsQuery = "SELECT " + exportColumns + " FROM runTBL2_jobs WHERE SubmitTime >= ? AND SubmitTime < ? ORDER BY SubmitTime, JobID"

// CountQuery counts the same rows.
const CountQuery = "SELECT COUNT(*) FROM runTBL2_jobs WHERE SubmitTime >= ? AND SubmitTime < ?"

// MySQLSource reads pegasusdb with Cassandra's read-only login.
type MySQLSource struct {
	DB               *sql.DB
	Endpoint         string
	Database         string
	StatementTimeout time.Duration
}

// OpenMySQL opens the source from a DSN, recording its endpoint without the
// credential.
func OpenMySQL(dsn string, timeout time.Duration) (*MySQLSource, error) {
	parsed, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pegasus DSN: %w", err)
	}
	if parsed.DBName == "" {
		return nil, fmt.Errorf("pegasus DSN must name a database")
	}
	parsed.Timeout = 30 * time.Second
	parsed.ReadTimeout = timeout
	db, err := sql.Open("mysql", parsed.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("open pegasus: %w", err)
	}
	db.SetMaxOpenConns(1)
	return &MySQLSource{DB: db, Endpoint: parsed.Addr, Database: parsed.DBName, StatementTimeout: timeout - timeout/10}, nil
}

type mysqlSnapshot struct {
	conn *sql.Conn
	info SourceInfo
	asOf time.Time
}

// Snapshot starts a read-only transaction WITH CONSISTENT SNAPSHOT, so the
// count and the rows describe the same instant even while ingestion writes.
// That holds for InnoDB; the engine is recorded so a reader can see whether
// it held, and the exporter's before-and-after counts catch it if not.
func (s *MySQLSource) Snapshot(ctx context.Context) (Snapshot, error) {
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	fail := func(step string, err error) (Snapshot, error) {
		conn.Close()
		return nil, fmt.Errorf("%s: %w", step, err)
	}
	if _, err := conn.ExecContext(ctx, "SET SESSION max_statement_time = ?", s.StatementTimeout.Seconds()); err != nil {
		return fail("set statement time limit", err)
	}
	var engine sql.NullString
	if err := conn.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'runTBL2'").Scan(&engine); err != nil {
		return fail("read storage engine", err)
	}
	if _, err := conn.ExecContext(ctx, "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ"); err != nil {
		return fail("set isolation", err)
	}
	if _, err := conn.ExecContext(ctx, "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"); err != nil {
		return fail("start snapshot", err)
	}
	var asOf string
	if err := conn.QueryRowContext(ctx, "SELECT DATE_FORMAT(UTC_TIMESTAMP(6), '%Y-%m-%dT%H:%i:%s.%fZ')").Scan(&asOf); err != nil {
		return fail("read as-of time", err)
	}
	at, err := time.Parse("2006-01-02T15:04:05.000000Z", asOf)
	if err != nil {
		return fail("parse as-of time", err)
	}
	snapshot := "consistent (InnoDB)"
	if engine.String != "InnoDB" {
		snapshot = "not guaranteed (engine " + engine.String + "); checked by counting before and after"
	}
	return &mysqlSnapshot{conn: conn, asOf: at, info: SourceInfo{
		Endpoint: s.Endpoint, Database: s.Database, Relation: "runTBL2_jobs", Engine: engine.String, Snapshot: snapshot,
	}}, nil
}

func (m *mysqlSnapshot) AsOf() time.Time      { return m.asOf }
func (m *mysqlSnapshot) Describe() SourceInfo { return m.info }
func (m *mysqlSnapshot) Query() string        { return RowsQuery }
func (m *mysqlSnapshot) Close() error {
	m.conn.ExecContext(context.Background(), "COMMIT")
	return m.conn.Close()
}

func (m *mysqlSnapshot) Count(ctx context.Context, start, end int64) (int64, error) {
	var n int64
	err := m.conn.QueryRowContext(ctx, CountQuery, start, end).Scan(&n)
	return n, err
}

func (m *mysqlSnapshot) Rows(ctx context.Context, start, end int64, each func(SourceRow) error) error {
	rows, err := m.conn.QueryContext(ctx, RowsQuery, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			jobID, netid, group, partition, state, tresCPU, tresNode, tresGPU, tresMem, limit, memGB sql.NullString
			submit                                                                                   int64
			reqCPUs, viewLimit, viewGPUs, viewNodes                                                  sql.NullInt64
		)
		if err := rows.Scan(&jobID, &netid, &group, &submit, &partition, &state, &reqCPUs, &tresCPU,
			&tresNode, &tresGPU, &tresMem, &limit, &memGB, &viewLimit, &viewGPUs, &viewNodes); err != nil {
			return err
		}
		if err := each(SourceRow{
			JobID: text(jobID), Netid: text(netid), GroupName: text(group), SubmitTime: submit,
			Partition: text(partition), State: text(state), ReqCPUS: integer(reqCPUs), TRESReqCPU: text(tresCPU),
			TRESReqNode: text(tresNode), TRESReqGresGPU: text(tresGPU), TRESReqMem: text(tresMem), TimelimitRaw: text(limit),
			ViewMemReqGB: text(memGB), ViewTimelimitMin: integer(viewLimit), ViewGpusReq: integer(viewGPUs), ViewNodesReq: integer(viewNodes),
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func text(s sql.NullString) Text  { return Text{Value: s.String, Valid: s.Valid} }
func integer(i sql.NullInt64) Int { return Int{Value: i.Int64, Valid: i.Valid} }
