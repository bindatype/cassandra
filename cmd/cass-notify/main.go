// Command cass-notify posts text from standard input into a Zoom Team Chat
// channel.
//
// It deliberately does not know how to ask a question. Composing it with the
// thing that does keeps one job in one place:
//
//	cass-chat -policy "$POLICY" "how many agents are disconnected?" |
//	  cass-notify -title "Wazuh"
//
// Credentials come from the environment, as they do for every other source in
// this project, so that a webhook URL never appears in a command line, a shell
// history, or a cron table.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bindatype/cassandra/internal/env"
	"github.com/bindatype/cassandra/internal/zoom"
)

const (
	urlEnv    = "CASS_ZOOM_WEBHOOK_URL"
	tokenEnv  = "CASS_ZOOM_WEBHOOK_TOKEN"
	secretEnv = "CASS_ZOOM_WEBHOOK_SECRET"
	// variantEnv pins the signature construction once -probe has identified it,
	// without a rebuild.
	variantEnv = "CASS_ZOOM_SIGNATURE_VARIANT"

	// maxInput bounds what will be read from a pipe. An answer is a paragraph;
	// anything approaching this size means the upstream command failed in a way
	// that produced volume instead of an error.
	maxInput = 64 * 1024
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("cass-notify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	title := flags.String("title", "", "optional bold first line")
	dryRun := flags.Bool("dry-run", false, "print the exact request instead of sending it")
	probe := flags.Bool("probe", false, "send one test message per signature variant and report which Zoom accepts")
	timeout := flags.Duration("timeout", 30*time.Second, "overall timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	// Said once, after the flags have pulled their defaults from the
	// environment, so a run that still depends on the old variable names says
	// so out loud. This is what makes the compatibility temporary rather than
	// permanent: silence here is how a shim outlives the rename.
	env.ReportLegacy(stderr)

	if *probe {
		return runProbe(stdout, stderr, *timeout)
	}

	raw, err := io.ReadAll(io.LimitReader(stdin, maxInput))
	if err != nil {
		fmt.Fprintf(stderr, "cass-notify: read: %v\n", err)
		return 1
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		// Posting an empty message would put a blank line in a channel and read
		// as a successful run. A silent upstream failure should be loud here.
		fmt.Fprintln(stderr, "cass-notify: nothing on stdin")
		return 2
	}
	if *title != "" {
		text = "**" + *title + "**\n" + text
	}

	client, err := newClient()
	if err != nil {
		fmt.Fprintf(stderr, "cass-notify: %v (set %s and %s)\n", err, urlEnv, secretEnv)
		return 2
	}

	if *dryRun {
		described, err := client.Describe(text)
		if err != nil {
			fmt.Fprintf(stderr, "cass-notify: %v\n", err)
			return 1
		}
		fmt.Fprint(stdout, described)
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := client.Post(ctx, text); err != nil {
		fmt.Fprintf(stderr, "cass-notify: %v\n", err)
		return 1
	}
	return 0
}

func newClient() (*zoom.Client, error) {
	variant, err := zoom.VariantByName(env.Get(variantEnv))
	if err != nil {
		return nil, err
	}
	return zoom.New(zoom.Config{
		URL:     env.Get(urlEnv),
		Token:   env.Get(tokenEnv),
		Secret:  env.Get(secretEnv),
		Variant: variant,
	})
}

// runProbe settles the two things Zoom's documentation states without pinning
// down: what "input message" covers, and which base64 alphabet it means. Each
// distinct signature costs one visible message in the channel, which is why
// this is a flag rather than something Post does on failure.
func runProbe(stdout, stderr io.Writer, timeout time.Duration) int {
	client, err := newClient()
	if err != nil {
		fmt.Fprintf(stderr, "cass-notify: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(len(zoom.Variants)))
	defer cancel()

	results, err := client.Probe(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "cass-notify: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "Sent %d test message(s), one per distinct signature.\n\n", len(results))
	var accepted []zoom.ProbeResult
	for _, result := range results {
		names := strings.Join(result.Variants, ", ")
		if len(result.Variants) > 1 {
			// Not a failure: these constructions produce identical bytes for
			// this payload, so one request tested them all.
			names += "  (identical for this payload)"
		}
		if result.Accepted {
			fmt.Fprintf(stdout, "  ACCEPTED  %s\n", names)
			accepted = append(accepted, result)
			continue
		}
		fmt.Fprintf(stdout, "  rejected  %s\n            %v\n", names, result.Err)
	}

	switch len(accepted) {
	case 0:
		fmt.Fprintln(stdout, "\nNone accepted. The problem is not the signature construction.")
		return 1
	case 1:
		fmt.Fprintf(stdout, "\nUse: export %s=%s\n", variantEnv, accepted[0].Variants[0])
		if len(accepted[0].Variants) > 1 {
			fmt.Fprintf(stdout, "(%s is equivalent here, but may not be for every message.)\n",
				strings.Join(accepted[0].Variants[1:], ", "))
		}
	default:
		// Genuinely alarming: distinct signatures both accepted means the
		// server is not checking the one we send.
		fmt.Fprintf(stdout, "\n%d DIFFERENT signatures were accepted. The endpoint is not verifying them.\n", len(accepted))
	}
	return 0
}
