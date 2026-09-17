#!/bin/sh
# Everything that must pass before anything reaches main, and nothing that
# needs a credential or a network.
#
#   make verify
#
# There is no CI. No hook, no workflow, nothing on GitHub runs a test: a green
# pull request page means only that nobody has looked. This script is the gate,
# and it is only a gate if somebody runs it.
#
# Every check runs inside `if` so a failure is recorded rather than aborting the
# run. scripts/check_entrypoints.sh shipped with `set -e` and stopped at its
# first failure, reporting nothing about the checks after it -- found only by
# breaking something on purpose. A gate that hides most of its own output on
# the first problem makes the second problem invisible.
#
# What this deliberately does NOT cover: whether a model behaves, and whether a
# connector agrees with the service behind it. Those need credentials and live
# data, and they are `make test-rt-live` and `make eval-rt-shape`. A tree that
# passes everything here can still be wrong about RT.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

pass=0
fail=0

ok()   { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; [ -n "$2" ] && printf '      %s\n' "$2"; }

unformatted=$(gofmt -l ./cmd ./internal 2>/dev/null)
if [ -z "$unformatted" ]; then
	ok "gofmt: every file formatted"
else
	bad "gofmt: unformatted files" "$(echo "$unformatted" | tr '\n' ' ')"
fi

if go build ./... >/dev/null 2>&1; then
	ok "go build"
else
	bad "go build" "$(go build ./... 2>&1 | head -3)"
fi

if go vet ./... >/dev/null 2>&1; then
	ok "go vet"
else
	bad "go vet" "$(go vet ./... 2>&1 | head -3)"
fi

if go test -count=1 ./... >/dev/null 2>&1; then
	ok "go test (all packages, uncached)"
else
	bad "go test" "$(go test -count=1 ./... 2>&1 | grep -E '^(---|FAIL|ok.*FAIL)' | head -5)"
fi

# Build-tagged code is compiled by nothing in the default path, so it rots in
# silence: a rename three packages away leaves it uncompilable for weeks and
# the first person to need it discovers that instead of the answer they wanted.
if go vet -tags rtlive ./internal/connector/ >/dev/null 2>&1; then
	ok "go vet -tags rtlive (live tests still compile)"
else
	bad "go vet -tags rtlive" "$(go vet -tags rtlive ./internal/connector/ 2>&1 | head -3)"
fi

# The live tests reach the network with real credentials. They must never join
# the default run, on any machine, including one with an environment sourced.
leaked=$(go test ./internal/connector/ -list '.*' 2>/dev/null | grep -c RTLive)
if [ "$leaked" = "0" ]; then
	ok "live tests excluded from the default run"
else
	bad "live tests leak into the default run" "$leaked RTLive test(s) would run without being asked for"
fi

if sh ./scripts/check_entrypoints.sh >/dev/null 2>&1; then
	ok "entry points (install, uninstall, ask startup)"
else
	bad "entry points" "$(sh ./scripts/check_entrypoints.sh 2>&1 | grep -i fail | head -3)"
fi

# Import rather than parse. Parsing catches a syntax error and nothing else:
# six of these scripts once referred to an undefined name at module level --
# every one of them died on its first line -- and this check reported them all
# green, because the file parsed. Importing runs the module top level, which is
# where a harness keeps the names it resolves before it does any work. Nothing
# here touches the network: every script defers that to main().
badpy=""
for script in scripts/*.py; do
	name=$(basename "$script" .py)
	err=$(cd scripts && python3 -c "import $name" 2>&1) || badpy="$badpy
  $script: $(printf '%s' "$err" | tail -1)"
done
if [ -z "$badpy" ]; then
	ok "evaluation harnesses import"
else
	bad "evaluation harnesses do not import" "$badpy"
fi

# Nothing may be defined after the __main__ guard.
#
# Importing a module runs its top level but not main(), so the import check
# above cannot see a function that main() calls and that is defined below the
# guard -- the module imports cleanly and fails with NameError the moment it is
# run. Both audit readers shipped that way for one commit: verify passed, and
# they raised on the first real invocation.
#
# Checked statically rather than by running each script, because running them
# needs credentials, a network, and in some cases writes a report.
badguard=""
for script in scripts/*.py; do
	err=$(python3 - "$script" <<'PYEOF'
import ast, sys

source = open(sys.argv[1]).read()
tree = ast.parse(source)
guard = None
for node in tree.body:
    if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
            and getattr(node.test.left, "id", "") == "__name__"):
        guard = node.lineno
if guard is None:
    sys.exit(0)
late = [n.name if hasattr(n, "name") else type(n).__name__
        for n in tree.body
        if n.lineno > guard and isinstance(n, (ast.FunctionDef, ast.ClassDef, ast.Assign))]
if late:
    print("defined after the __main__ guard: " + ", ".join(str(x) for x in late))
    sys.exit(1)
PYEOF
	) || badguard="$badguard
  $script: $err"
done
if [ -z "$badguard" ]; then
	ok "nothing defined after the __main__ guard"
else
	bad "python defined after its entry point" "$badguard"
fi

# Shell scripts are checked for syntax the way the Python ones are checked for
# import. Nothing else runs them: bin/zoom-digest.sh fires from cron at 04:45,
# and a typo in it surfaces as a line in a log nobody reads -- which is exactly
# how it went six days without posting.
badsh=""
for script in bin/*.sh scripts/*.sh; do
	[ -e "$script" ] || continue
	err=$(sh -n "$script" 2>&1) || badsh="$badsh
  $script: $(printf '%s' "$err" | head -1)"
done
if [ -z "$badsh" ]; then
	ok "shell scripts parse"
else
	bad "shell scripts do not parse" "$badsh"
fi

# Nothing but discipline has kept credentials and the Zoom endpoint out of the
# repository. The endpoint is not merely a location: /inc connect mints it per
# channel, so it names which channel messages land in and is as sensitive as
# the token beside it.
#
# Two checks. The first is a pattern scan that works with no credentials at
# all. The second only runs when the environment happens to be sourced, and is
# the one that would actually catch a paste: it looks for the literal values
# this host holds. Neither ever prints a matched value -- a check that echoes
# the secret it found has published it to the terminal, the CI log, and
# whatever scrolled past.
#
# Reserved names are excluded rather than special-cased. RFC 2606 sets aside
# .invalid, .example and example.com so that documentation and tests can show
# a realistic URL that can never resolve, and the zoom tests use exactly that.
# A scanner that cannot tell a fixture from a leak gets switched off.
badsecret=""
for pattern in 'zoom\.us' 'hooks\.slack\.com' 'incomingwebhook/[A-Za-z0-9_-]\{16,\}'; do
	hits=$(git ls-files -z 2>/dev/null |
		xargs -0 grep -nE "$pattern" 2>/dev/null |
		grep -vE '\.invalid|\.example|example\.(com|org|net)|localhost' |
		grep -v '^scripts/verify.sh:' |
		cut -d: -f1,2 || true)
	[ -z "$hits" ] || badsecret="$badsecret
  pattern /$pattern/ at:$(printf ' %s' $hits)"
done

for var in SROIAAA_ZOOM_WEBHOOK_URL SROIAAA_ZOOM_WEBHOOK_SECRET \
	SROIAAA_ZOOM_WEBHOOK_TOKEN RT_API_TOKEN ZABBIX_RO_TOKEN \
	WAZUH_API_PASSWORD MINDROUTER_API_KEY SROIAAA_PEGASUS_DSN; do
	eval "value=\${$var:-}"
	# Short values match everywhere and would only produce noise; a real
	# credential is not eight characters.
	[ ${#value} -ge 12 ] || continue
	hits=$(git ls-files -z 2>/dev/null | xargs -0 grep -lF "$value" 2>/dev/null || true)
	[ -z "$hits" ] || badsecret="$badsecret
  the value of $var appears in:$(printf ' %s' $hits)"
done

if [ -z "$badsecret" ]; then
	ok "no credential or webhook endpoint in tracked files"
else
	bad "a credential or webhook endpoint is in tracked files" "$badsecret"
fi

# The rename from SROIAAA to Cassandra leaves two deliberate survivors: the
# SROIAAA_ variable names, still read so an unmigrated host keeps working, and
# ~/.config/sroiaaa, still searched for the same reason. Everything else should
# be gone, and a half-finished rename is worse than either name -- it is the
# state where a script looks right and points somewhere that does not exist.
#
# This fails on any OTHER spelling of the old name, so the compatibility shims
# stay visible and deliberate while typos and leftovers do not.
#
# Nothing is excused by SPELLING any more, only by file. The variable names
# were excused by spelling first and the README taught them for a whole rename;
# the config paths were excused by spelling second, and the README went on
# telling people to run `source ~/.config/sroiaaa/env` -- alongside two
# evaluation harnesses naming ~/.config/sroiaaa/policy.json outright, which
# stopped existing the morning the host was migrated. The same gap twice, so
# the rule is now that only the files implementing a fallback may mention the
# old name at all.
#
# The SROIAAA_ variable names are NOT globally excused. They were, and the
# README went on teaching an operator to export SROIAAA_BIND_ADDR and
# SROIAAA_AUTH_TOKEN for the whole of the rename -- each one matched an
# exclusion written for the three files that implement the fallback. Reading
# those names belongs in those files; printing them as instructions belongs
# nowhere, and the exemption is now by file rather than by spelling.
#
# The three files that implement the compatibility are exempted by name rather
# than by pattern. They are where the old name belongs, and a pattern loose
# enough to spare their prose would spare a genuine leftover somewhere else.
# Naming them also means deleting them finishes the rename: the exemption list
# goes empty and this check covers the whole tree.
oldname=$(git ls-files -z 2>/dev/null |
	xargs -0 grep -inE "sroiaaa" 2>/dev/null |
	grep -vE "^(scripts/verify\.sh|internal/env/env(_test)?\.go|bin/lib/config\.sh|bin/askcass|bin/netbox-probe\.sh|bin/zabbix-probe\.sh|scripts/ctx_marker_probe\.py|scripts/eval_common\.py):" |
	cut -d: -f1,2 || true)
if [ -z "$oldname" ]; then
	ok "no stray SROIAAA references (compatibility shims excepted)"
else
	bad "the old name survives outside the compatibility shims" "$(printf '%s' "$oldname" | head -8)"
fi

# The entry point is askcass. The docs said `ask` for a whole rename, including
# a runnable example on the page a new contributor is told to follow first --
# found by a reader, not by anything here, which is the third time today that
# documentation was the last place the rename reached.
#
# Only two forms are checked, because both are unambiguously the command and
# neither can be the English verb: backtick-quoted, and at the start of a line
# inside a shell block. "ask for one explicitly" and "make probe # ask the
# Zabbix trap questions" are left alone, which is the point of being narrow.
staleask=$(git ls-files -z '*.md' 2>/dev/null |
	xargs -0 grep -nE '`ask`|^[[:space:]]*ask[[:space:]]+["-]' 2>/dev/null |
	cut -d: -f1,2 || true)
if [ -z "$staleask" ]; then
	ok "docs name the entry point askcass"
else
	bad "docs still call the entry point ask" "$(printf '%s' "$staleask" | head -6)"
fi

# The unit file is the only part of this project that nothing compiles and no
# test exercises. A typo in it surfaces as a service that will not start on a
# host somebody is already waiting on, so it is at least parsed here.
#
# Skipped where systemd is absent, which includes every macOS checkout -- a
# check that cannot run must say so rather than quietly passing.
if [ -f deploy/cassd.service ]; then
	if ! command -v systemd-analyze >/dev/null 2>&1; then
		ok "cassd unit (skipped: no systemd on this host)"
	elif systemd-analyze verify deploy/cassd.service 2>&1 |
		grep -v "is not executable" | grep -q .; then
		bad "cassd unit does not parse" \
			"$(systemd-analyze verify deploy/cassd.service 2>&1 | grep -v "is not executable" | head -3)"
	else
		ok "cassd unit parses"
	fi
fi

# The grader decides what every RT shape result means, and nothing in a run
# notices when a grader is wrong: the numbers come out and look like results.
if python3 ./scripts/eval_rt_shape.py --self-test >/dev/null 2>&1; then
	ok "RT shape grader self-test"
else
	bad "RT shape grader self-test" "$(python3 ./scripts/eval_rt_shape.py --self-test 2>&1 | head -3)"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
	printf 'verify: NOT ready for main\n'
	exit 1
fi
printf 'verify: credential-free checks pass. Live behaviour is not covered:\n'
printf '        make test-rt-live   RT invariants against the live instance\n'
printf '        make eval-rt-shape  whether the model bounds a ticket-age question\n'
