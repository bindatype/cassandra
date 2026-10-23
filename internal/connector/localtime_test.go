package connector

import (
	"strings"
	"testing"
	"time"
)

// Times either side of the 2026-11-01 change carry their own abbreviation;
// a relative window and a non-time field are left alone.
func TestLocalizeTimesAcrossDaylightSaving(t *testing.T) {
	zone, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no zone database: ", err)
	}
	evidence := Evidence{
		Since: "2026-10-21T15:00:00Z",
		Until: "24h",
		Items: []EvidenceItem{
			{Fields: map[string]string{"occurred": "2026-10-22T02:08:44Z", "pid": "812"}},
			{Fields: map[string]string{"occurred": "2026-11-02T02:08:44Z"}},
		},
	}
	LocalizeTimes(&evidence, zone)
	if evidence.SinceLocal != "2026-10-21 11:00:00 EDT" || evidence.UntilLocal != "" || evidence.LocalZone != "America/New_York" {
		t.Errorf("window = %q to %q in %q", evidence.SinceLocal, evidence.UntilLocal, evidence.LocalZone)
	}
	if got := evidence.Items[0].Fields["occurred_local"]; got != "2026-10-21 22:08:44 EDT" {
		t.Errorf("before the change: %q, want 2026-10-21 22:08:44 EDT", got)
	}
	if got := evidence.Items[1].Fields["occurred_local"]; got != "2026-11-01 21:08:44 EST" {
		t.Errorf("after the change: %q, want 2026-11-01 21:08:44 EST", got)
	}
	if _, ok := evidence.Items[0].Fields["pid_local"]; ok {
		t.Error("a field that is not a time gained a local twin")
	}
}

func TestLocalizeTimesWithoutAZoneChangesNothing(t *testing.T) {
	evidence := Evidence{Since: "2026-10-21T15:00:00Z", Items: []EvidenceItem{{Fields: map[string]string{"occurred": "2026-10-22T02:08:44Z"}}}}
	LocalizeTimes(&evidence, nil)
	if evidence.SinceLocal != "" || len(evidence.Items[0].Fields) != 1 {
		t.Errorf("evidence changed without a zone: %+v", evidence)
	}
}

// The final-attempt caveat goes with a runTBL2 count by state, and only there.
func TestFinalAttemptNoteGoesWithRunTBL2States(t *testing.T) {
	at := time.Date(2026, 10, 23, 13, 0, 0, 0, time.UTC)
	for query, want := range map[string]bool{
		"SELECT State, COUNT(*) FROM runTBL2 WHERE EndTime >= 1792633800 GROUP BY State":          true,
		"SELECT State, COUNT(*) FROM runTBL2_workload WHERE EndTime >= 1792633800 GROUP BY State": true,
		"SELECT COUNT(*) FROM runTBL2 WHERE EndTime >= 1792633800":                                false,
		"SELECT State, COUNT(*) FROM FY2025 GROUP BY State":                                       false,
	} {
		got := strings.Contains(strings.Join(accountingNotes(query, at), " "), "final attempt only")
		if got != want {
			t.Errorf("%s: final-attempt note = %v, want %v", query, got, want)
		}
	}
}

func TestLocalTimeFunctionsAreRecognised(t *testing.T) {
	for query, want := range map[string]bool{
		"SELECT FROM_UNIXTIME(EndTime) FROM runTBL2":                                          true,
		"SELECT COUNT(*) FROM runTBL2 WHERE SubmitTime >= UNIX_TIMESTAMP('2026-10-21')":       true,
		"SELECT COUNT(*) FROM runTBL2 WHERE EndTime > UNIX_TIMESTAMP(NOW() - INTERVAL 1 DAY)": true,
		"SELECT COUNT(*) FROM runTBL2 WHERE EndTime >= 1792633800":                            false,
	} {
		if got := localTimeFunction.MatchString(query); got != want {
			t.Errorf("%s: %v, want %v", query, got, want)
		}
	}
}
