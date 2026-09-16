#!/bin/sh
# The contributor-facing path, checked the way the Go code is checked.
#
# `go test ./...` covers the packages and now the commands, but the first thing
# a new contributor touches is none of those: it is `make install` and then
# typing `askcass`. That path has broken twice -- a dangling symlink after bin/askcass
# moved, and a `make uninstall` recipe with an unterminated quote that removed
# the file and then failed -- and neither showed up in any test.
#
# Needs no credentials and no network.
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PREFIX=$(mktemp -d "${TMPDIR:-/tmp}/cass-entrypoints.XXXXXX")
ENVDIR=$(mktemp -d "${TMPDIR:-/tmp}/cass-env.XXXXXX")
trap 'rm -rf "$PREFIX" "$ENVDIR"' EXIT INT TERM

failures=0

# Every check runs inside `if`, so a failing one is recorded rather than
# aborting the run. The first version of this script used `set -e` and stopped
# at the first failure, reporting nothing about it -- which is the same defect
# it exists to catch, in the checker itself.
check() {
	description=$1
	shift
	if "$@" >/dev/null 2>&1; then
		printf 'ok    %s\n' "$description"
	else
		printf 'FAIL  %s\n' "$description"
		failures=$((failures + 1))
	fi
}

# A shell entry point with a syntax error is discovered by whoever runs it
# next, which for one of these is cron at 04:45.
parses() {
	if head -n 1 "$1" | grep -q bash; then
		bash -n "$1"
	else
		sh -n "$1"
	fi
}

# Run askcass with a scrubbed environment.
#
# These checks assert that askcass reports what is missing. A caller who has
# sourced ~/.config/cass/env already has those variables exported, so askcass
# finds them and reports nothing, and the check fails -- not because the
# behaviour is wrong but because the probe was measuring the caller's shell.
# The result flipped on whether an operator had run `source` first: red for
# anyone doing real work, green in CI, which is the least useful arrangement a
# gate can have.
#
# env -i keeps only what the build needs, so the probe answers the same
# question wherever it runs.
says() {
	env -i PATH="$PATH" HOME="$HOME" CASS_ENV="$1" "$PREFIX/askcass" test 2>&1 | grep -q -- "$2"
}

for script in "$ROOT"/bin/* "$ROOT"/scripts/*.sh; do
	[ -f "$script" ] || continue
	head -n 1 "$script" | grep -q '^#!' || continue
	name=${script#"$ROOT"/}
	check "parses: $name" parses "$script"
	check "executable: $name" test -x "$script"
done

check "make install succeeds" make -C "$ROOT" install PREFIX="$PREFIX"
check "install leaves a working symlink, not a dangling one" test -x "$PREFIX/askcass"

# The operator-facing refusals must name what to fix, rather than failing
# somewhere inside Go's module resolution.
: > "$ENVDIR/empty"
check "missing env file is reported by name" says "$ENVDIR/absent" "no environment file"
check "an env file missing exports names the variables" says "$ENVDIR/empty" CASS_MINDROUTER_ENDPOINT

check "make uninstall succeeds" make -C "$ROOT" uninstall PREFIX="$PREFIX"
check "uninstall removes the symlink" test ! -e "$PREFIX/askcass"

printf '\n'
if [ "$failures" -eq 0 ]; then
	printf 'entry points: all checks passed\n'
else
	printf 'entry points: %d check(s) failed\n' "$failures"
	exit 1
fi
