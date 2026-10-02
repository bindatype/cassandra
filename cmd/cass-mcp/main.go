// Command cass-mcp serves Cassandra to MCP clients -- Hermes, Claude Code,
// Codex -- over HTTPS, so an agent can ask it questions as a tool.
//
//	cass-mcp -cert cert.pem -key key.pem -chat runtime/cass-chat -policy policy.json
//	cass-mcp -hash < key.txt          # print the allowlist line for a MindRouter key
//
// Each caller presents their own MindRouter API key. It must be on the
// allowlist (key hash -> person) and accepted by MindRouter. Every question
// runs the same cass-chat askcass uses, with the caller's key for the model and
// the service's source credentials, and is audited under the caller's name.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("cass-mcp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	home, _ := os.UserHomeDir()
	listen := flags.String("listen", "[::]:8443", "address to serve HTTPS on")
	certFile := flags.String("cert", "", "TLS certificate (PEM)")
	keyFile := flags.String("key", "", "TLS private key (PEM)")
	allowlistPath := flags.String("allowlist", filepath.Join(home, ".config", "cass", "mcp-allowlist"), "key hash -> person file")
	chat := flags.String("chat", "", "built cass-chat binary to answer with")
	policy := flags.String("policy", "", "broker policy file, as for askcass")
	endpoint := flags.String("mindrouter-endpoint", os.Getenv("CASS_MINDROUTER_ENDPOINT"), "MindRouter base URL, used to check keys")
	wazuhInsecure := flags.Bool("wazuh-insecure", false, "pass -wazuh-insecure to cass-chat, as askcass does")
	maxInflight := flags.Int("max-inflight", 4, "questions answered at once, across everyone")
	maxPerUser := flags.Int("max-per-person", 2, "questions answered at once for one person")
	timeout := flags.Duration("timeout", 240*time.Second, "longest one question may take")
	hash := flags.Bool("hash", false, "read a MindRouter key on stdin and print its allowlist line")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if *hash {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		token := strings.TrimSpace(line)
		if token == "" {
			fmt.Fprintln(stderr, "cass-mcp: no key on stdin", err)
			return 2
		}
		fmt.Fprintf(stdout, "%s <person>\n", TokenHash(token))
		return 0
	}

	for _, required := range []struct{ value, flag string }{
		{*certFile, "-cert"}, {*keyFile, "-key"}, {*chat, "-chat"}, {*policy, "-policy"}, {*endpoint, "-mindrouter-endpoint"},
	} {
		if required.value == "" {
			fmt.Fprintf(stderr, "cass-mcp: %s is required\n", required.flag)
			return 2
		}
	}
	allowlist, err := NewAllowlist(*allowlistPath)
	if err != nil {
		fmt.Fprintf(stderr, "cass-mcp: allowlist: %v\n", err)
		return 2
	}

	runner := chatRunner(*chat, *policy, *wazuhInsecure, *timeout)
	validator := MindRouterValidator(*endpoint, &http.Client{Timeout: 10 * time.Second})
	server := NewServer(allowlist, validator, runner, *maxInflight, *maxPerUser, stderr)

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           server,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      *timeout + 30*time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	fmt.Fprintf(stderr, "cass-mcp: serving https://%s/mcp\n", *listen)
	if err := httpServer.ListenAndServeTLS(*certFile, *keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "cass-mcp: %v\n", err)
		return 1
	}
	return 0
}

// chatRunner answers with cass-chat itself, so every guard, retry and audit
// rule askcass has applies here unchanged. The question goes on stdin, never
// argv, so one beginning with "-" cannot be read as a flag.
func chatRunner(chat, policy string, wazuhInsecure bool, timeout time.Duration) Runner {
	return func(ctx context.Context, caller Caller, question string) (Answer, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		args := []string{"-policy", policy, "-json", "-timeout", (timeout - 10*time.Second).String()}
		if wazuhInsecure {
			args = append(args, "-wazuh-insecure")
		}
		cmd := exec.CommandContext(ctx, chat, args...)
		cmd.Stdin = strings.NewReader(question)
		cmd.Env = append(withoutKey(os.Environ()),
			"MINDROUTER_API_KEY="+caller.Token,
			"CASS_CALLER="+caller.Person,
			"CASS_CLIENT="+caller.Client,
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		runErr := cmd.Run()

		var out struct {
			Answer   string          `json:"answer"`
			Error    string          `json:"error"`
			Evidence json.RawMessage `json:"evidence"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			detail := strings.TrimSpace(stderr.String())
			if detail == "" && runErr != nil {
				detail = runErr.Error()
			}
			return Answer{}, fmt.Errorf("cassandra could not answer: %s", lastLine(detail))
		}
		if out.Error != "" {
			return Answer{}, errors.New(out.Error)
		}
		return Answer{Text: out.Answer, Evidence: out.Evidence}, nil
	}
}

// withoutKey drops the service's own MindRouter key, so a question is never
// answered on anyone's key but the caller's.
func withoutKey(environ []string) []string {
	out := environ[:0:0]
	for _, kv := range environ {
		if !strings.HasPrefix(kv, "MINDROUTER_API_KEY=") && !strings.HasPrefix(kv, "SROIAAA_MINDROUTER_API_KEY=") {
			out = append(out, kv)
		}
	}
	return out
}

func lastLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return lines[len(lines)-1]
}
