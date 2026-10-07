// Command cass-export extracts Pegasus job requests to a verifiable export
// directory. No model is involved: the request names logical fields and whole
// dates, and the exporter computes everything else.
//
//	cass-export -request req.json -caller glen [-identify] [-out DIR]
//
// It reads CASS_PEGASUS_DSN (Cassandra's read-only login) and the salt for
// pseudonymous identities from -salt-file. It prints a JSON summary and
// exits 0 when the request was fulfilled, 3 when the export completed but the
// request was not fully met, 1 when the export failed, and 2 when the
// request was refused or the command was misused. cass-mcp runs the same
// code for agents.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/bindatype/cassandra/internal/export"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("cass-export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	home, _ := os.UserHomeDir()
	requestPath := flags.String("request", "", "export request JSON file (required)")
	out := flags.String("out", filepath.Join(home, ".local", "share", "cass-export"), "directory exports are written under")
	caller := flags.String("caller", "", "who the export is for, recorded in the manifest (required)")
	identify := flags.Bool("identify", false, "allow identity \"netid\" (raw usernames)")
	saltFile := flags.String("salt-file", filepath.Join(home, ".config", "cass", "export-salt"), "salt for pseudonymous identities")
	maxRows := flags.Int64("max-rows", 2_000_000, "refuse a window holding more jobs than this")
	timeout := flags.Duration("timeout", 30*time.Minute, "longest the export may take")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *requestPath == "" || *caller == "" {
		fmt.Fprintln(stderr, "cass-export: -request and -caller are required")
		return 2
	}
	raw, err := os.ReadFile(*requestPath)
	if err != nil {
		fmt.Fprintf(stderr, "cass-export: %v\n", err)
		return 2
	}
	req, err := export.DecodeRequest(raw)
	if err != nil {
		return report(stdout, map[string]any{"refused": err}, 2)
	}
	defs, err := export.LoadDefinitions()
	if err != nil {
		fmt.Fprintf(stderr, "cass-export: %v\n", err)
		return 1
	}
	// Refuse a bad request before touching the database.
	if _, err := defs.Validate(req, *identify); err != nil {
		return report(stdout, map[string]any{"refused": err}, 2)
	}
	salt, _ := os.ReadFile(*saltFile) // a missing salt is refused by Run, with the reason

	dsn := os.Getenv("CASS_PEGASUS_DSN")
	if dsn == "" {
		fmt.Fprintln(stderr, "cass-export: CASS_PEGASUS_DSN must be set (source ~/.config/cass/env)")
		return 2
	}
	source, err := export.OpenMySQL(dsn, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "cass-export: %v\n", err)
		return 1
	}
	defer source.DB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	m, dir, err := export.Run(ctx, req, export.Options{
		Definitions: defs, Source: source, FS: export.OSFS{}, Root: *out, Caller: *caller,
		CanIdentify: *identify, Salt: salt, MaxRows: *maxRows, ToolVersion: Version(),
		Progress: func(rows int64) { fmt.Fprintf(stderr, "cass-export: %d rows\n", rows) },
	})
	var refused *export.RequestError
	switch {
	case errors.As(err, &refused):
		return report(stdout, map[string]any{"refused": refused}, 2)
	case err != nil:
		return report(stdout, map[string]any{"failed": err.Error()}, 1)
	}
	code := 3
	if m.Fulfillment.State == export.Fulfilled {
		code = 0
	}
	return report(stdout, export.Summarize(m, dir), code)
}

func report(w io.Writer, body any, code int) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(body)
	return code
}

// Version is the commit the binary was built from.
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	revision, dirty := "unknown", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if dirty {
		revision += "+modified"
	}
	return revision
}
