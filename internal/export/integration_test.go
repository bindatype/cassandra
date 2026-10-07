//go:build integration

package export

// Phase B: the incident's cases against the live runTBL2_jobs view. They
// need the view created on lucee and Cassandra's read-only login:
//
//	set -a; . ~/.config/cass/env; set +a
//	go test -tags integration -run Live -v -timeout 30m ./internal/export/
//
// (make test-export-live). They read only; exports go to a temporary
// directory that the test removes.

import (
	"context"
	"os"
	"testing"
	"time"
)

func liveSource(t *testing.T) *MySQLSource {
	t.Helper()
	dsn := os.Getenv("CASS_PEGASUS_DSN")
	if dsn == "" {
		t.Skip("CASS_PEGASUS_DSN is not set")
	}
	source, err := OpenMySQL(dsn, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.DB.Close() })
	var n int
	if err := source.DB.QueryRow("SELECT COUNT(*) FROM information_schema.views WHERE table_schema = DATABASE() AND table_name = 'runTBL2_jobs'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("runTBL2_jobs is not in the database (err %v); create it from configs/pegasusdb/runTBL2_jobs.sql first", err)
	}
	return source
}

func liveOptions(t *testing.T, source Source) Options {
	t.Helper()
	opts := testOptions(t, source, nil)
	opts.MaxRows = 2_000_000
	opts.NewID = NewExportID
	return opts
}

// The incident request, end to end: every job in June-September 2026,
// normalized, agreeing with the view on every row, verified by the shipped
// verifier.
func TestLiveIncidentExport(t *testing.T) {
	source := liveSource(t)
	started := time.Now()
	m, dir, err := Run(context.Background(), incidentRequest(DeliverNormalized), liveOptions(t, source))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("as of %s: %d rows in %s; raw %s, normalization %s, fulfillment %s; source %s, snapshot %s",
		m.AsOf.Format(time.RFC3339), m.Raw.RowsWritten, time.Since(started).Round(time.Second),
		m.Raw.State, m.Normalization.State, m.Fulfillment.State, m.Source.Engine, m.Source.Snapshot)
	for _, c := range append(m.Raw.Checks, m.Normalization.Checks...) {
		t.Logf("  %v %s: %s", c.Passed, c.Name, c.Detail)
	}
	if m.Window.StartEpoch != juneStart || m.Window.EndEpoch != octStart {
		t.Errorf("window [%d, %d)", m.Window.StartEpoch, m.Window.EndEpoch)
	}
	if m.Raw.State != RawComplete || m.Normalization.State != NormValidated || m.Fulfillment.State != Fulfilled {
		t.Fatalf("raw %s (%s), normalization %s (%s), fulfillment %s", m.Raw.State, m.Raw.Reason,
			m.Normalization.State, m.Normalization.Reason, m.Fulfillment.State)
	}
	if code, verdict, failed := runVerifier(t, dir); code != 0 {
		t.Errorf("verifier exit %d, verdict %v, failures:\n%s", code, verdict, failed)
	}
}

// Requested and allocated nodes are different numbers; the export reads the
// requested one. Reported, not asserted equal.
func TestLiveRequestedAndAllocatedNodesDiffer(t *testing.T) {
	source := liveSource(t)
	var differ, total int64
	err := source.DB.QueryRow("SELECT SUM(nodes_req <> NNodes), COUNT(*) FROM runTBL2_jobs WHERE SubmitTime >= ? AND SubmitTime < ? AND nodes_req IS NOT NULL",
		juneStart, octStart).Scan(&differ, &total)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d of %d jobs with a recorded node request were allocated a different number of nodes", differ, total)
}

// A window starting before TRES was recorded: raw completes, nulls carry
// tres_unrecorded, and the manifest warns.
func TestLivePreTRESWindowKeepsUnknownsNull(t *testing.T) {
	source := liveSource(t)
	req := incidentRequest(DeliverNormalized)
	req.Window.Start, req.Window.End = "2026-01-15", "2026-01-29"
	m, dir, err := Run(context.Background(), req, liveOptions(t, source))
	if err != nil {
		t.Fatal(err)
	}
	if m.Normalization.State != NormValidated || !containsWarning(m.Warnings, "before 22 January 2026") {
		t.Errorf("normalization %s (%s), warnings %v", m.Normalization.State, m.Normalization.Reason, m.Warnings)
	}
	if code, verdict, failed := runVerifier(t, dir); code != 0 {
		t.Errorf("verifier exit %d, verdict %v, failures:\n%s", code, verdict, failed)
	}
}

// The view must merge into runTBL2, or every query against it materializes
// the whole table first. Merging makes runTBL2's indexes available; whether
// the optimizer uses one is its choice: for June-September 2026 it chose a
// full scan (EXPLAIN by Glen on lucee, 2026-10-07; this login cannot EXPLAIN a
// view without SHOW VIEW, Error 1345). MariaDB records MERGE, and marks a view
// updatable, only when it merges; an unmergeable edit is downgraded to
// UNDEFINED with only a warning, so this is the check that catches one.
func TestLiveViewMergesIntoRunTBL2(t *testing.T) {
	source := liveSource(t)
	var algorithm, updatable string
	err := source.DB.QueryRow("SELECT algorithm, is_updatable FROM information_schema.views WHERE table_schema = DATABASE() AND table_name = 'runTBL2_jobs'").Scan(&algorithm, &updatable)
	if err != nil {
		t.Fatal(err)
	}
	if algorithm != "MERGE" || updatable != "YES" {
		t.Errorf("runTBL2_jobs has algorithm %s, updatable %s; want MERGE and YES, or every query materializes runTBL2 first", algorithm, updatable)
	}
}
