package env

import (
	"strings"
	"testing"
)

func TestNewNameWins(t *testing.T) {
	resetForTest()
	t.Setenv("CASS_THING", "new")
	t.Setenv("SROIAAA_THING", "old")
	if got := Get("CASS_THING"); got != "new" {
		t.Errorf("Get = %q, want the CASS_ value", got)
	}
	var out strings.Builder
	if ReportLegacy(&out) {
		t.Errorf("warned about the old name when the new one was set: %q", out.String())
	}
}

func TestOldNameStillWorksAndSaysSo(t *testing.T) {
	resetForTest()
	t.Setenv("SROIAAA_THING", "old")
	if got := Get("CASS_THING"); got != "old" {
		t.Errorf("Get = %q; an unmigrated environment must keep working", got)
	}
	var out strings.Builder
	if !ReportLegacy(&out) {
		t.Fatal("read a legacy variable and said nothing; the rename would never finish")
	}
	for _, want := range []string{"SROIAAA_THING", "CASS_THING"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("warning does not mention %q: %q", want, out.String())
		}
	}
}

// An empty CASS_ variable must not mask a populated SROIAAA_ one: that is the
// case where a half-migrated env file reads as "unset" and the fallback that
// exists to prevent an outage does not fire.
func TestEmptyNewNameDoesNotMaskTheOld(t *testing.T) {
	resetForTest()
	t.Setenv("CASS_THING", "")
	t.Setenv("SROIAAA_THING", "old")
	if got := Get("CASS_THING"); got != "old" {
		t.Errorf("Get = %q, want the old value to show through an empty new one", got)
	}
}

func TestUnsetIsUnset(t *testing.T) {
	resetForTest()
	if value, ok := Lookup("CASS_ABSENT"); ok || value != "" {
		t.Errorf("Lookup = (%q, %v), want empty and false", value, ok)
	}
}

// Names this package does not own have no legacy spelling; inventing
// SROIAAA_HOME would be nonsense and would read a variable nobody set.
func TestForeignNamesHaveNoLegacySpelling(t *testing.T) {
	if got := LegacyName("HOME"); got != "" {
		t.Errorf("LegacyName(HOME) = %q, want empty", got)
	}
	if got := LegacyName("CASS_RT_ENDPOINT"); got != "SROIAAA_RT_ENDPOINT" {
		t.Errorf("LegacyName = %q", got)
	}
}

// One line for a whole run, not one per lookup: a warning repeated five times
// for one command teaches people to silence stderr, and the next real warning
// goes with it.
func TestWarningIsOneLineForTheWholeRun(t *testing.T) {
	resetForTest()
	t.Setenv("SROIAAA_ONE", "a")
	t.Setenv("SROIAAA_TWO", "b")
	for i := 0; i < 3; i++ {
		Get("CASS_ONE")
		Get("CASS_TWO")
	}
	var out strings.Builder
	ReportLegacy(&out)
	if lines := strings.Count(strings.TrimSpace(out.String()), "\n"); lines != 0 {
		t.Errorf("warning spans %d extra line(s): %q", lines, out.String())
	}
	if !strings.Contains(out.String(), "SROIAAA_ONE") || !strings.Contains(out.String(), "SROIAAA_TWO") {
		t.Errorf("warning lost a variable: %q", out.String())
	}
}
