// Package env reads this program's environment variables during the rename
// from SROIAAA to Cassandra.
//
// Every variable is CASS_-prefixed now. The old SROIAAA_ spelling still works,
// because the names are not only ours: they live in ~/.config/cassandra/env on
// every host that runs this, in the crontab that posts the morning digest at
// 04:45, and in environment files belonging to contributors whose machines
// nobody else can reach. A rename that renames those in the same instant
// breaks a scheduled job and two people's setups, and does it silently -- the
// digest's failure mode is that nothing is posted.
//
// So both spellings are read, the new one wins, and using the old one says so
// on stderr. When nothing has reported a legacy read for a while, delete this
// package and call os.Getenv directly.
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
// An empty value counts as unset. That is not strictly what the shell means,
// but every variable here is an endpoint, a credential, a path or a limit, and
// for all of them "set to empty" and "not set" call for the same behaviour --
// while treating them differently would mean an empty CASS_ variable silently
// masking a populated SROIAAA_ one, which is the confusing direction.
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
// name this package does not own -- HOME and PATH are read through here too in
// places, and inventing SROIAAA_HOME for them would be nonsense.
func LegacyName(name string) string {
	if !strings.HasPrefix(name, prefix) {
		return ""
	}
	return legacyPrefix + strings.TrimPrefix(name, prefix)
}

// ReportLegacy writes one line naming every old variable that was read, and
// reports whether it wrote anything.
//
// One line rather than one per variable, and only at the end: a warning per
// lookup would print the same thing five times for a single run and train
// people to pipe stderr to /dev/null, which is where the next real warning
// would go too.
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
