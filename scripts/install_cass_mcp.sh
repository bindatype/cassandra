#!/bin/bash
# install_cass_mcp.sh -- deploy this checkout to the host's cass-mcp service:
# test, build, swap the binaries in, restart, and check that the service
# answers. The previous build is kept, and put back if the check fails.
#
#   make install-cass-mcp        test, build, swap, restart, check
#   make rollback-cass-mcp       swap the previous build back in
#
# Run it on the host that serves cass-mcp (sgtstubby), as the user who owns
# the service, from the checkout being deployed. It is the routine the
# 2026-10-03 deploy did by hand, which began by reading the running process to
# find which cass-chat it used.
#
# It manages, in ~/.local/share/cass-mcp/bin: cass-mcp, cass-chat, a snapshot
# of the broker policy, and BUILD, naming the commit they came from; each with
# a .prev copy of the build before. It also installs the unit from
# deploy/cass-mcp.user.service. It never touches the TLS files, the source
# credentials in ~/.config/cass/env, the allowlist, or the flags file.
#
# The policy is a snapshot because cass-chat reads it on every question: a
# unit pointing into the checkout changed the live policy on every `git pull`.
# CASS_MCP_POLICY chooses another policy file.
#
# The check is that an unauthenticated request gets 401. That proves TLS is
# served, the handler is up, and the gate is shut; 200 would mean it is open.
# It does not exercise a question: ask one after installing.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
share=$HOME/.local/share/cass-mcp
bin=$share/bin
tls=$share/tls
unit=$HOME/.config/systemd/user/cass-mcp.service
flags=$HOME/.config/cass/cass-mcp.flags
policy=${CASS_MCP_POLICY:-$root/configs/broker-policy.example.json}
url=${CASS_MCP_CHECK_URL:-https://localhost:8443/mcp}
managed="$bin/cass-mcp $bin/cass-chat $bin/broker-policy.json $bin/BUILD $unit"

say() { echo "install-cass-mcp: $*"; }
die() { echo "install-cass-mcp: $*" >&2; exit 1; }

# check waits up to 15 s for the restarted service to answer 401.
check() {
	local code i
	for i in $(seq 15); do
		code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
			--cacert "$tls/ca.pem" -X POST "$url" 2>/dev/null) || code=000
		if [ "$code" = 401 ]; then
			say "unauthenticated request got 401: serving, gate shut"
			return 0
		fi
		sleep 1
	done
	echo "install-cass-mcp: unauthenticated request got $code, want 401" >&2
	return 1
}

# swap exchanges each managed file with its .prev, so a rollback can itself be
# rolled back. A file with no .prev is left alone.
swap() {
	local f
	for f in $managed; do
		[ -e "$f.prev" ] || continue
		if [ -e "$f" ]; then
			mv "$f" "$f.swap"
			mv "$f.prev" "$f"
			mv "$f.swap" "$f.prev"
		else
			mv "$f.prev" "$f"
		fi
	done
}

restart() {
	systemctl --user daemon-reload
	systemctl --user restart cass-mcp
}

command -v systemctl >/dev/null || die "no systemctl here; run this on the host that serves cass-mcp (sgtstubby)"
for f in "$tls/ca.pem" "$tls/cert.pem" "$tls/key.pem" "$HOME/.config/cass/env"; do
	[ -r "$f" ] || die "$f is missing; this script installs code, not TLS files or credentials"
done

if [ "${1:-}" = "-r" ]; then
	[ -e "$bin/cass-mcp.prev" ] || die "no previous build to roll back to"
	swap
	restart
	check || die "the rolled-back build fails its check too; the service needs a person"
	say "now running: $(head -1 "$bin/BUILD" 2>/dev/null || echo 'a build from before BUILD files')"
	exit 0
fi
[ $# -eq 0 ] || die "usage: $0 [-r]"

commit=$(git -C "$root" rev-parse --short HEAD)
branch=$(git -C "$root" rev-parse --abbrev-ref HEAD)
dirty=""
if [ -n "$(git -C "$root" status --porcelain)" ]; then
	dirty=" with uncommitted changes"
	say "WARNING: the checkout has uncommitted changes; BUILD will say so"
fi

say "testing $branch at $commit"
if ! out=$(cd "$root" && go test ./... 2>&1); then
	echo "$out" >&2
	die "tests fail; nothing was changed"
fi

# Built beside the live files, so the swap is a rename on one filesystem.
mkdir -p "$bin"
stage=$(mktemp -d "$share/stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT
say "building"
(cd "$root" && go build -o "$stage/cass-mcp" ./cmd/cass-mcp && go build -o "$stage/cass-chat" ./cmd/cass-chat) ||
	die "build failed; nothing was changed"
cp "$policy" "$stage/broker-policy.json"
printf '%s %s%s\nbuilt %s on %s from %s, policy %s\n' "$branch" "$commit" "$dirty" \
	"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(hostname -s)" "$root" "$policy" >"$stage/BUILD"

# A unit replaced by this one keeps the old copy as .prev; an unchanged unit
# drops any old .prev, so a later rollback cannot swap in a stale unit.
mkdir -p "$(dirname "$unit")"
if [ -e "$unit" ] && cmp -s "$root/deploy/cass-mcp.user.service" "$unit"; then
	rm -f "$unit.prev"
else
	if [ -e "$unit" ]; then
		# Flags set in an older unit move to the flags file, which this unit reads.
		old=$(sed -n 's/^Environment=CASS_MCP_EXTRA_FLAGS=//p' "$unit")
		if [ -n "$old" ] && [ ! -e "$flags" ]; then
			printf 'CASS_MCP_EXTRA_FLAGS=%s\n' "$old" >"$flags"
			say "moved CASS_MCP_EXTRA_FLAGS from the old unit to $flags"
		fi
		cp -p "$unit" "$unit.prev"
	fi
	cp "$root/deploy/cass-mcp.user.service" "$unit"
	say "installed the unit from deploy/cass-mcp.user.service"
fi

# A build from before this script has no BUILD; label it, so a rollback to it
# does not leave the new build's label on the old binaries.
if [ -e "$bin/cass-mcp" ] && [ ! -e "$bin/BUILD" ]; then
	echo "unknown: built by hand, before install_cass_mcp.sh" >"$bin/BUILD"
fi
for f in cass-mcp cass-chat broker-policy.json BUILD; do
	if [ -e "$bin/$f" ]; then
		mv "$bin/$f" "$bin/$f.prev"
	else
		rm -f "$bin/$f.prev"
	fi
	mv "$stage/$f" "$bin/$f"
done

say "restarting cass-mcp"
restart
if ! check; then
	say "putting the previous build back"
	swap
	restart
	check || die "the previous build fails its check too; the service needs a person"
	die "the new build failed its check and was rolled back; it is kept as .prev files"
fi

if ! openssl x509 -checkend $((30 * 86400)) -noout -in "$tls/cert.pem" >/dev/null 2>&1; then
	say "WARNING: $tls/cert.pem expires within 30 days ($(openssl x509 -enddate -noout -in "$tls/cert.pem"))"
fi
say "deployed: $(head -1 "$bin/BUILD")"
