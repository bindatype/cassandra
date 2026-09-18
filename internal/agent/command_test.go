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

// The commands that need a privilege grant must not be present. Shipping one
// under the current sandbox means exit 0 and a well-formed answer describing
// almost nothing.
func TestSandboxBlockedCommandsAreNotShipped(t *testing.T) {
	blocked := []string{"journalctl", "dmesg", "/ps", "/ss"}
	for operation, steps := range commandOperations {
		for _, step := range steps {
			for _, name := range blocked {
				if strings.Contains(step.Path, name) {
					t.Errorf("%s runs %q, which returns empty or partial output under cassd's "+
						"sandbox (ProtectKernelLogs, ProtectProc=invisible, no SupplementaryGroups). "+
						"It needs a deliberate privilege grant first.", operation, step.Path)
				}
			}
		}
	}
}
