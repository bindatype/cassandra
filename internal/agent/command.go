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
// the surface is drawn narrowly:
//
//   - Every argument is a compile-time constant. Nothing a model sends reaches
//     a command line, which is why these operations take no target.
//   - No shell: exec with an absolute path, so `;`, `|` and backticks are inert.
//   - The environment is emptied, not inherited.
//   - Output is capped here, not at the reader.
//
// cassd's sandbox decides what actually works, and only the hardened unit
// shows it; tests running the agent as an ordinary user won't:
//
//   - A binary must be labelled bin_t. Any other label needs an SELinux domain
//     transition, which NoNewPrivileges (implied by DynamicUser=yes) forbids,
//     and the service exits 203. /usr/sbin/ip and /usr/bin/dmesg are not
//     bin_t; uptime, df and ss are. (host.network therefore uses netlink; see
//     network.go.)
//   - kernel.messages needs the ring buffer, so the shipped unit sets
//     ProtectKernelLogs=no. kernel.dmesg_restrict=1 still blocks it.
//   - host.gpu needs /dev/nvidia*, which PrivateDevices=yes hides. Enabling it
//     means BindPaths= plus DevicePolicy=closed and a DeviceAllow= line per
//     node, with the node set checked on the target host (ls -la
//     /dev/nvidia*), not PrivateDevices=no.
//   - ProtectProc=invisible hides other users' processes, so ss has no -p and
//     process.list refuses a filtered view.
//
// kernel.messages and host.gpu are implemented but not enabled by default.
// journalctl is absent: an empty SupplementaryGroups excludes
// systemd-journal, and a well-formed empty answer is worse than none.
const (
	commandTimeout   = 10 * time.Second
	commandMaxOutput = 64 * 1024
)

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
	operationHostGPU: {
		"one row per physical GPU as nvidia-smi enumerates it; a GPU made invisible to this host " +
			"by a hypervisor or MIG partitioning is absent from the count, not reported as zero.",
	},
}

// commandStep is one program invocation. An operation may run several rather
// than take a parameter the model could get wrong: `df -h` alone misses a
// filesystem out of inodes at 40% capacity.
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
	// No -p: it attributes only the calling user's sockets, and this agent
	// owns almost none, so the process column would be blank on a list that
	// looks complete.
	operationHostListeners: {
		{Label: "listeners", Path: "/usr/sbin/ss", Args: []string{"-tuln"}},
	},
	// Needs ProtectKernelLogs=no (as shipped) and kernel.dmesg_restrict=0. A
	// blocked read fails with stderr, which the operation reports.
	operationKernelMessages: {
		{Label: "kernel", Path: "/usr/bin/dmesg", Args: []string{"-T", "--level=err,warn"}},
	},
	// Blocked by PrivateDevices=yes in the shipped unit; see the top of this
	// file. Unit-free CSV, one row per GPU, so "8000" isn't ambiguous.
	operationHostGPU: {
		{Label: "gpu", Path: "/usr/bin/nvidia-smi", Args: []string{
			"--query-gpu=index,name,memory.total,memory.used,memory.free,utilization.gpu,utilization.memory,temperature.gpu",
			"--format=csv,noheader,nounits",
		}},
	},
}

// commandResult is one step's outcome. A failed step is reported beside the
// others, not dropped.
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
// them. If no step produced output the operation is an error: an empty
// success can't be told from "cassd could not look".
func (s *Service) runCommandOperation(ctx context.Context, operation string) (any, bool, *APIError) {
	steps, known := commandOperations[operation]
	if !known {
		return nil, false, newAPIError(400, "unknown_operation", "operation is not supported")
	}

	// A missing binary is refused up front, naming the path.
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
		// Keep stderr: a blocked dmesg and a quiet machine both produce no
		// output, and stderr tells them apart.
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
	// Empty, not inherited.
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
