package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Running a program is a different security posture from reading a file, so
// the surface is drawn as narrowly as it can be and still be useful:
//
//   - Every argument below is a compile-time constant. Nothing a model sends
//     reaches a command line, so there is no parameter to validate and no
//     injection class to defend against. This is the whole reason these
//     operations take no target.
//   - No shell. exec.CommandContext with an absolute path means `;`, `&&`,
//     `|` and backticks are inert bytes, not syntax.
//   - The environment is emptied rather than inherited, so nothing in cassd's
//     environment steers a child's behaviour.
//   - Output is capped at the agent. A command that floods is cut here, not at
//     the reader.
//
// A binary here must be labelled bin_t. Anything else carries an SELinux domain
// transition, and DynamicUser=yes implies NoNewPrivileges=yes, which forbids a
// transition that is not bounded -- the exec is denied and the service exits
// 203 before the program runs. /usr/sbin/ip (ifconfig_exec_t) and /usr/bin/dmesg
// (dmesg_exec_t) both do this; uptime, df and ss are bin_t and do not.
//
// host.network was shipped running `ip` and was broken under enforcing from the
// moment it landed. It passed because it was tested with the agent run as an
// ordinary user rather than as a hardened unit, which is the one difference
// that decided it. It is now native netlink; see network.go.
//
// Deliberately absent: journalctl, dmesg, ps and ss. Each returns empty or
// partial output under cassd's current sandbox -- ProtectKernelLogs blocks the
// ring buffer, ProtectProc=invisible hides other processes, and an empty
// SupplementaryGroups excludes systemd-journal. Shipping them would mean
// exit code 0 with a well-formed answer describing almost nothing, which is
// worse than not having them. They wait on a deliberate privilege grant.
const (
	commandTimeout   = 10 * time.Second
	commandMaxOutput = 64 * 1024
)

// commandStep is one program invocation. A single operation may run several,
// because the alternative is a parameter the model can get wrong: asking only
// `df -h` misses a filesystem that is out of inodes at 40% capacity, and
// asking only `ip addr` misses the route that explains why a reachable-looking
// interface answers nothing.
// operationNotes are limits a reader would otherwise have to discover. They
// travel with the result, because a socket list with no process column looks
// complete rather than partial.
var operationNotes = map[string][]string{
	operationHostListeners: {
		"process attribution is NOT included: ss -p reports only sockets owned by the calling " +
			"user, and this agent owns almost none, so a process column would be blank rather " +
			"than absent. Do not conclude a port has no owner.",
	},
	operationKernelMessages: {
		"only error and warning level entries are returned, and the ring buffer holds a bounded " +
			"window: an event older than the buffer is absent, not non-existent.",
	},
}

type commandStep struct {
	// Label names the step in the response, so a reader can tell which output
	// came from which invocation without parsing argv.
	Label string
	Path  string
	Args  []string
}

var commandOperations = map[string][]commandStep{
	operationHostUptime: {
		{Label: "uptime", Path: "/usr/bin/uptime", Args: nil},
	},
	operationHostDiskFree: {
		{Label: "space", Path: "/usr/bin/df", Args: []string{"-h"}},
		{Label: "inodes", Path: "/usr/bin/df", Args: []string{"-i"}},
	},
	// -p is deliberately absent. It attributes sockets to processes, but only
	// for the calling user's own, and this agent owns almost none -- so -p
	// would return a blank process column on a list that otherwise looks
	// complete. Attribution needs a privilege grant; until then, saying
	// nothing beats saying nothing convincingly.
	operationHostListeners: {
		{Label: "listeners", Path: "/usr/sbin/ss", Args: []string{"-tuln"}},
	},
	// Blocked by ProtectKernelLogs=yes in the shipped unit, and by
	// kernel.dmesg_restrict=1 on hosts that set it. Both failures are refusals
	// with stderr, not empty successes, so the operation reports why.
	operationKernelMessages: {
		{Label: "kernel", Path: "/usr/bin/dmesg", Args: []string{"-T", "--level=err,warn"}},
	},
}

// commandResult is one step's outcome. Every field is reported, including the
// unhappy ones: a step that failed says so next to the steps that did not,
// rather than being dropped from a list that then reads as complete.
type commandResult struct {
	Label      string `json:"label"`
	Command    string `json:"command"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Failed     bool   `json:"failed,omitempty"`
	Failure    string `json:"failure,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// runCommandOperation executes every step of an operation and reports all of
// them. If no step produced output the whole operation is an error, because an
// empty success is the failure this project keeps finding: a reader cannot
// distinguish "the machine has nothing to report" from "cassd could not look".
func (s *Service) runCommandOperation(ctx context.Context, operation string) (any, bool, *APIError) {
	steps, known := commandOperations[operation]
	if !known {
		return nil, false, newAPIError(400, "unknown_operation", "operation is not supported")
	}

	// A missing binary is refused before anything runs, and the refusal names
	// the path. "command not found" buried in a step's stderr would read as
	// the machine having nothing to say.
	for _, step := range steps {
		if _, err := os.Stat(step.Path); err != nil {
			return nil, false, newAPIError(503, "command_unavailable",
				"required program is not present at "+step.Path)
		}
	}

	results := make([]commandResult, 0, len(steps))
	anyOutput := false
	for _, step := range steps {
		result := s.runCommandStep(ctx, step)
		if result.Stdout != "" {
			anyOutput = true
		}
		results = append(results, result)
	}

	if !anyOutput {
		// Name the cause rather than only the symptom. dmesg refused by
		// ProtectKernelLogs and dmesg on a quiet machine both produce no
		// output, and the stderr is the only thing that tells them apart.
		detail := "every step ran and none produced output"
		for _, result := range results {
			if result.Failure != "" || result.Stderr != "" {
				detail = fmt.Sprintf("%s: %s", result.Label,
					strings.TrimSpace(result.Failure+" "+result.Stderr))
				break
			}
		}
		return nil, false, newAPIError(502, "command_produced_nothing",
			detail+"; reported as a failure rather than an empty result, because an empty "+
				"result would read as the machine having nothing to report")
	}

	truncated := false
	for _, result := range results {
		if result.Truncated {
			truncated = true
		}
	}
	payload := map[string]any{"steps": results}
	if notes := operationNotes[operation]; len(notes) > 0 {
		payload["notes"] = notes
	}
	return payload, truncated, nil
}

func (s *Service) runCommandStep(ctx context.Context, step commandStep) commandResult {
	started := time.Now()
	result := commandResult{Label: step.Label, Command: commandLine(step)}

	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, step.Path, step.Args...)
	// Empty, not inherited. A child's behaviour must not depend on what was in
	// cassd's environment.
	cmd.Env = []string{}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result.DurationMS = time.Since(started).Milliseconds()

	result.Stdout, result.Truncated = capOutput(stdout.Bytes())
	stderrText, stderrTruncated := capOutput(stderr.Bytes())
	result.Stderr = stderrText
	result.Truncated = result.Truncated || stderrTruncated

	switch {
	case err == nil:
		result.ExitCode = cmd.ProcessState.ExitCode()
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		result.Failed = true
		result.ExitCode = -1
		result.Failure = "timed out after " + commandTimeout.String()
	default:
		result.Failed = true
		result.ExitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		}
		result.Failure = err.Error()
	}
	return result
}

func commandLine(step commandStep) string {
	line := step.Path
	for _, arg := range step.Args {
		line += " " + arg
	}
	return line
}

// capOutput bounds one stream and says whether it was cut. Trimming to a byte
// count can split a UTF-8 rune, so the cut is reported rather than hidden.
func capOutput(raw []byte) (string, bool) {
	if len(raw) <= commandMaxOutput {
		return string(bytes.TrimRight(raw, "\n")), false
	}
	return string(bytes.TrimRight(raw[:commandMaxOutput], "\n")), true
}
