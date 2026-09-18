package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withCommandOperations(t *testing.T, table map[string][]commandStep) {
	t.Helper()
	original := commandOperations
	commandOperations = table
	t.Cleanup(func() { commandOperations = original })
}

func newCommandService() *Service {
	return NewService(Config{
		EnabledOperations: []string{operationHostUptime, operationHostDiskFree, operationHostNetwork},
	}, nil)
}

// Every step is reported, including one that failed. A failing step dropped
// from the list would leave a response that reads as complete.
func TestCommandOperationReportsEveryStepIncludingFailures(t *testing.T) {
	withCommandOperations(t, map[string][]commandStep{
		operationHostDiskFree: {
			{Label: "space", Path: "/bin/echo", Args: []string{"filesystem output"}},
			{Label: "inodes", Path: "/bin/echo", Args: []string{"inode output"}},
		},
	})

	data, _, apiErr := newCommandService().runCommandOperation(context.Background(), operationHostDiskFree)
	if apiErr != nil {
		t.Fatalf("runCommandOperation() error = %+v", apiErr)
	}
	steps, ok := data.(map[string]any)["steps"].([]commandResult)
	if !ok {
		t.Fatalf("steps missing from %#v", data)
	}
	if len(steps) != 2 {
		t.Fatalf("got %d steps, want 2 -- both invocations must be reported", len(steps))
	}
	if steps[0].Label != "space" || !strings.Contains(steps[0].Stdout, "filesystem output") {
		t.Errorf("step 0 = %+v", steps[0])
	}
	if steps[1].Label != "inodes" || !strings.Contains(steps[1].Stdout, "inode output") {
		t.Errorf("step 1 = %+v", steps[1])
	}
	// The command is echoed back so a reader can tell what produced the output.
	if !strings.Contains(steps[0].Command, "/bin/echo") {
		t.Errorf("step 0 command = %q, want it to name the program", steps[0].Command)
	}
}

// A missing program is refused by name before anything runs. Left to the shell
// it would surface as "command not found" inside a step's stderr, which reads
// as the machine having nothing to say.
func TestCommandOperationRefusesMissingBinaryByName(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "definitely-not-here")
	withCommandOperations(t, map[string][]commandStep{
		operationHostNetwork: {
			{Label: "addresses", Path: "/bin/echo", Args: []string{"this must not run"}},
			{Label: "routes", Path: missing},
		},
	})

	_, _, apiErr := newCommandService().runCommandOperation(context.Background(), operationHostNetwork)
	if apiErr == nil {
		t.Fatal("a missing program was not refused")
	}
	if apiErr.Code != "command_unavailable" {
		t.Errorf("code = %q, want command_unavailable", apiErr.Code)
	}
	if !strings.Contains(apiErr.Message, missing) {
		t.Errorf("message = %q, want it to name the missing path", apiErr.Message)
	}
}

// An operation whose steps all succeed but produce nothing is an error, not an
// empty success. This is the project's recurring failure shape: a reader cannot
// tell "nothing to report" from "could not look".
func TestCommandOperationRefusesSilentEmptySuccess(t *testing.T) {
	withCommandOperations(t, map[string][]commandStep{
		operationHostUptime: {
			{Label: "uptime", Path: "/bin/echo", Args: []string{""}},
		},
	})

	_, _, apiErr := newCommandService().runCommandOperation(context.Background(), operationHostUptime)
	if apiErr == nil {
		t.Fatal("an operation that produced no output was reported as success")
	}
	if apiErr.Code != "command_produced_nothing" {
		t.Errorf("code = %q, want command_produced_nothing", apiErr.Code)
	}
}

func TestCommandStepCapsOutputAndSaysSo(t *testing.T) {
	big := strings.Repeat("x", commandMaxOutput*2)
	result := newCommandService().runCommandStep(context.Background(), commandStep{
		Label: "flood", Path: "/bin/echo", Args: []string{big},
	})
	if !result.Truncated {
		t.Error("oversized output was not marked truncated")
	}
	if len(result.Stdout) > commandMaxOutput {
		t.Errorf("stdout is %d bytes, over the %d cap", len(result.Stdout), commandMaxOutput)
	}
}

func TestCommandStepReportsTimeoutAsFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)

	result := newCommandService().runCommandStep(ctx, commandStep{
		Label: "slow", Path: "/bin/echo", Args: []string{"never gets here"},
	})
	if !result.Failed {
		t.Error("an expired context produced a result not marked failed")
	}
	if result.Failure == "" {
		t.Error("a failed step must say why")
	}
}

// Structural checks on the real table, which cannot be exercised on a dev
// machine that has no /usr/sbin/ip.
func TestRealCommandTableIsAbsoluteAndTakesNoCallerInput(t *testing.T) {
	for operation, steps := range commandOperations {
		if len(steps) == 0 {
			t.Errorf("%s has no steps", operation)
		}
		for _, step := range steps {
			if !filepath.IsAbs(step.Path) {
				t.Errorf("%s step %q path %q is not absolute; a relative path is a PATH lookup",
					operation, step.Label, step.Path)
			}
			if step.Label == "" {
				t.Errorf("%s has an unlabelled step; a reader could not tell which output is which", operation)
			}
		}
	}
}

// df -h and df -i answer different questions and a filesystem can exhaust
// either alone: 40% full and out of inodes still fails writes. Asking for one
// is a parameter the model would get wrong, so the operation asks for both.
func TestDiskFreeAsksForSpaceAndInodesBoth(t *testing.T) {
	steps := commandOperations[operationHostDiskFree]
	var space, inodes bool
	for _, step := range steps {
		for _, arg := range step.Args {
			if arg == "-h" {
				space = true
			}
			if arg == "-i" {
				inodes = true
			}
		}
	}
	if !space || !inodes {
		t.Errorf("host.diskfree asks space=%v inodes=%v; it must ask both, or an inode-exhausted "+
			"filesystem reports as healthy", space, inodes)
	}
}

func TestNetworkAsksForAddressesAndRoutesBoth(t *testing.T) {
	var addr, route bool
	for _, step := range commandOperations[operationHostNetwork] {
		if len(step.Args) > 0 && step.Args[0] == "addr" {
			addr = true
		}
		if len(step.Args) > 0 && step.Args[0] == "route" {
			route = true
		}
	}
	if !addr || !route {
		t.Errorf("host.network asks addr=%v route=%v; an address without its route explains nothing", addr, route)
	}
}

// Commands needing a privilege grant must not be shipped in a state where they
// can only return empty or partial output. This was one blanket rule; the
// grants turned out to differ, so it is now three specific ones.
func TestGrantRequiringCommandsAreNotShippedBlind(t *testing.T) {
	// journalctl needs SupplementaryGroups=systemd-journal, and ps needs
	// ProtectProc dropped. Neither grant has been made, and both would exit 0
	// while describing almost nothing.
	for operation, steps := range commandOperations {
		for _, step := range steps {
			for _, forbidden := range []string{"journalctl", "/ps"} {
				if strings.Contains(step.Path, forbidden) {
					t.Errorf("%s runs %q, which needs a privilege grant that has not been made; "+
						"it would exit 0 describing almost nothing", operation, step.Path)
				}
			}
		}
	}

	// ss may ship, but never with -p: attribution is reported only for the
	// caller's own sockets, and this agent owns almost none, so -p yields a
	// blank process column on a list that otherwise looks complete.
	for operation, steps := range commandOperations {
		for _, step := range steps {
			if !strings.Contains(step.Path, "/ss") {
				continue
			}
			for _, arg := range step.Args {
				if strings.Contains(arg, "p") && strings.HasPrefix(arg, "-") {
					t.Errorf("%s runs ss with %q; -p attributes only the caller's own sockets, "+
						"so it returns a blank process column rather than an absent one", operation, arg)
				}
			}
		}
	}

	// dmesg may be implemented, but must not be enabled by default: the
	// shipped unit sets ProtectKernelLogs=yes, so a default-on kernel.messages
	// could only ever refuse.
	for _, name := range defaultEnabledOperations() {
		if name == operationKernelMessages {
			t.Errorf("%s is enabled by default, but ProtectKernelLogs=yes in the shipped unit "+
				"means it can only refuse until that grant is made", name)
		}
	}
}

// Every command-backed operation that ships enabled must be one the sandbox
// actually permits, or the default configuration advertises what it cannot do.
func TestDefaultEnabledCommandOperationsNeedNoGrant(t *testing.T) {
	grantFree := map[string]bool{
		operationHostUptime:    true,
		operationHostDiskFree:  true,
		operationHostNetwork:   true,
		operationHostListeners: true,
	}
	for _, name := range defaultEnabledOperations() {
		if _, isCommand := commandOperations[name]; !isCommand {
			continue
		}
		if !grantFree[name] {
			t.Errorf("%s runs a program and is enabled by default, but is not on the "+
				"grant-free list; either it needs no grant and belongs there, or it "+
				"must not ship enabled", name)
		}
	}
}

// A limit a reader would otherwise have to discover must travel with the
// result. A socket list with no process column looks complete.
func TestOperationsWithHiddenLimitsCarryNotes(t *testing.T) {
	for _, operation := range []string{operationHostListeners, operationKernelMessages} {
		if len(operationNotes[operation]) == 0 {
			t.Errorf("%s has a limit that is invisible in its output but carries no note", operation)
		}
	}
}
