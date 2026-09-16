package main

import (
	"bytes"
	"strings"
	"testing"
)

const testSecret = "s3cret-not-in-any-output"

func configure(t *testing.T) {
	t.Helper()
	t.Setenv(urlEnv, "https://zoom.invalid/webhook")
	t.Setenv(tokenEnv, "")
	t.Setenv(secretEnv, testSecret)
	t.Setenv(variantEnv, "")
}

func TestRunRejectsBadInvocations(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		stdin     string
		configure bool
		status    int
		says      string
	}{
		{
			// An empty message would post a blank line and exit 0, so a silent
			// failure upstream would look like a successful run.
			name: "nothing on stdin", stdin: "   \n", configure: true, status: 2, says: "nothing on stdin",
		},
		{name: "unknown flag", args: []string{"-nonsense"}, status: 2},
		{
			name: "no webhook configured", stdin: "19 hosts have the agent down", status: 2, says: urlEnv,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.configure {
				configure(t)
			} else {
				t.Setenv(urlEnv, "")
				t.Setenv(tokenEnv, "")
				t.Setenv(secretEnv, "")
				t.Setenv(variantEnv, "")
			}
			var stdout, stderr bytes.Buffer
			status := run(test.args, strings.NewReader(test.stdin), &stdout, &stderr)
			if status != test.status {
				t.Fatalf("status = %d, want %d (stderr: %s)", status, test.status, stderr.String())
			}
			if test.says != "" && !strings.Contains(stderr.String(), test.says) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr.String(), test.says)
			}
			if stdout.Len() != 0 {
				t.Fatalf("a failed run wrote to stdout: %q", stdout.String())
			}
		})
	}
}

func TestDryRunDescribesTheRequestWithoutTheSecret(t *testing.T) {
	configure(t)
	var stdout, stderr bytes.Buffer
	status := run([]string{"-dry-run", "-title", "Wazuh"},
		strings.NewReader("19 hosts have the agent down"), &stdout, &stderr)
	if status != 0 {
		t.Fatalf("status = %d, want 0 (stderr: %s)", status, stderr.String())
	}
	out := stdout.String()
	// The signature is derived from the secret and is safe to show; the secret
	// itself is not. This project has already printed one credential into a
	// transcript, and -dry-run is the command most likely to be run in front of
	// someone else.
	if strings.Contains(out, testSecret) {
		t.Fatalf("dry-run printed the webhook secret:\n%s", out)
	}
	for _, want := range []string{"POST https://zoom.invalid/webhook", "**Wazuh**", "19 hosts have the agent down"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dry-run output missing %q:\n%s", want, out)
		}
	}
}

// The input cap is what stops a runaway upstream command from posting a
// megabyte into a chat channel.
func TestInputIsCapped(t *testing.T) {
	configure(t)
	var stdout, stderr bytes.Buffer
	status := run([]string{"-dry-run"}, strings.NewReader(strings.Repeat("x", 4*maxInput)), &stdout, &stderr)
	if status != 0 {
		t.Fatalf("status = %d, want 0 (stderr: %s)", status, stderr.String())
	}
	// Describe echoes the text twice -- once as the signature preimage and
	// once as the body -- so measure the body itself, which is the last block.
	out := stdout.String()
	body := strings.TrimSpace(out[strings.LastIndex(out, "\n\n"):])
	if len(body) != maxInput {
		t.Fatalf("body was %d bytes, want it capped at %d", len(body), maxInput)
	}
}
