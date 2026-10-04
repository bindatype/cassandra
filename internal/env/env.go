// Package env reads this program's environment variables during the rename
// from SROIAAA to Cassandra.
//
// Every variable is CASS_-prefixed. The old SROIAAA_ spelling still works,
// because the names live in env files and crontabs on hosts this repo can't
// update, and a missed rename fails silently (the morning digest just doesn't
// post). Both spellings are read, the new one wins, and using the old one
// says so on stderr. When no legacy read has been reported for a while,
// delete this package and call os.Getenv directly.
package env

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

const (
	prefix       = "CASS_"
	legacyPrefix = "SROIAAA_"
)

var (
	mu   sync.Mutex
	used = map[string]string{} // legacy name -> the name that should be used
)

// Get returns the value of name, falling back to its SROIAAA_ spelling.
//
// An empty value counts as unset, so an empty CASS_ variable can't mask a
// populated SROIAAA_ one. For endpoints, credentials, paths and limits the
// two mean the same anyway.
func Get(name string) string {
	value, _ := Lookup(name)
	return value
}

// Lookup reports the value and whether either spelling was set.
func Lookup(name string) (string, bool) {
	if value := os.Getenv(name); value != "" {
		return value, true
	}
	legacy := LegacyName(name)
	if legacy == "" {
		return "", false
	}
	value := os.Getenv(legacy)
	if value == "" {
		return "", false
	}
	mu.Lock()
	used[legacy] = name
	mu.Unlock()
	return value, true
}

// LegacyName returns the SROIAAA_ spelling of a CASS_ variable, or "" for a
// name this package does not own (HOME and PATH are read through here too).
func LegacyName(name string) string {
	if !strings.HasPrefix(name, prefix) {
		return ""
	}
	return legacyPrefix + strings.TrimPrefix(name, prefix)
}

// ReportLegacy writes one line naming every old variable that was read, and
// reports whether it wrote anything.
//
// One line per run, not per lookup, so it doesn't train people to discard
// stderr.
func ReportLegacy(w io.Writer) bool {
	mu.Lock()
	defer mu.Unlock()
	if len(used) == 0 {
		return false
	}
	names := make([]string, 0, len(used))
	for legacy := range used {
		names = append(names, legacy)
	}
	sort.Strings(names)

	pairs := make([]string, 0, len(names))
	for _, legacy := range names {
		pairs = append(pairs, legacy+" -> "+used[legacy])
	}
	fmt.Fprintf(w, "warning: reading %d variable(s) by their old SROIAAA_ names; rename them: %s\n",
		len(names), strings.Join(pairs, ", "))
	return true
}

// resetForTest clears what has been observed.
func resetForTest() {
	mu.Lock()
	used = map[string]string{}
	mu.Unlock()
}
