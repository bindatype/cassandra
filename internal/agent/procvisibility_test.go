package agent

import (
	"strings"
	"testing"
)

// Measured on sgtstubby, 2026-09-18: the deployed unit mounts /proc with
// hidepid=invisible and the agent runs as a DynamicUser owning almost nothing.
// process.list then returns the agent's own two or three processes -- correctly
// formed, plausibly short, and describing nothing about the machine. A caller
// cannot tell that from a quiet host, so it must not be returned as an answer.
func TestProcessViewIsRefusedWhenOnlyOwnProcessesAreVisible(t *testing.T) {
	// What a DynamicUser sees under hidepid=invisible: itself, nothing else.
	own := []processRecord{{PID: 41231, Name: "cassd"}, {PID: 41232, Name: "cassd"}}

	restricted, reason := procVisibilityRestricted("/proc", own)
	if !restricted {
		t.Fatal("a view containing only the agent's own processes was accepted as the host's")
	}
	for _, want := range []string{"PID 1", "ProtectProc=invisible", "hidepid"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason does not mention %q, so a reader cannot act on it: %s", want, reason)
		}
	}
	// The grant has a cost and the refusal should say so, or it reads as a
	// recommendation to drop the protection.
	if !strings.Contains(reason, "command line") {
		t.Error("the refusal names the grant without naming what it exposes")
	}
}

func TestProcessViewIsAcceptedWhenPIDOneIsVisible(t *testing.T) {
	full := []processRecord{{PID: 1, Name: "systemd"}, {PID: 2, Name: "kthreadd"}, {PID: 41231, Name: "cassd"}}
	if restricted, reason := procVisibilityRestricted("/proc", full); restricted {
		t.Errorf("an unrestricted view was refused: %s", reason)
	}
}

// An empty scan is a different failure from a filtered one and must not be
// folded into it: nothing readable at all points at the proc root, not at
// hidepid.
func TestAnEmptyProcScanIsItsOwnFailure(t *testing.T) {
	restricted, reason := procVisibilityRestricted("/proc", nil)
	if !restricted {
		t.Fatal("an empty process scan was accepted")
	}
	if strings.Contains(reason, "hidepid") {
		t.Errorf("an empty scan was diagnosed as a hidepid restriction: %s", reason)
	}
	if !strings.Contains(reason, "unreadable or empty") {
		t.Errorf("reason = %q, want it to point at the proc root", reason)
	}
}
