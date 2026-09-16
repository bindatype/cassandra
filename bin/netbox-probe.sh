#!/bin/sh
# Reconnaissance against the NetBox REST API, before any connector exists.
#
# This is not zabbix-probe.sh. That one asks Cass questions end to end and
# judges the answers. This one talks to the API directly, because the empirical
# method here is to learn what a source actually returns before deciding what
# the broker should be allowed to ask it. Every trap in the Zabbix guide was
# found this way and none of them were in the vendor documentation.
#
# Usage:
#   . $HOME/.config/sroiaaa/env
#   bin/netbox-probe.sh              # everything
#   bin/netbox-probe.sh reach        # only reachability and TLS, no token needed
#
# Environment:
#   CASS_NETBOX_ENDPOINT   e.g. https://netbox.arc.gwu.edu
#   NETBOX_RO_TOKEN           read-only API token
#   CASS_NETBOX_CACERT     optional: PEM holding the issuing intermediate
#   CASS_NETBOX_INSECURE   optional: set to 1 to skip verification entirely
set -eu

ENDPOINT=${CASS_NETBOX_ENDPOINT:-${SROIAAA_NETBOX_ENDPOINT:-}}
TOKEN=${NETBOX_RO_TOKEN:-}
ONLY=${1:-all}

if [ -z "$ENDPOINT" ]; then
	echo "netbox-probe: CASS_NETBOX_ENDPOINT is not set" >&2
	echo "netbox-probe: see docs/onboarding.md, and note that every line in the" >&2
	echo "netbox-probe: env file needs 'export' or the value is not inherited" >&2
	exit 2
fi
ENDPOINT=${ENDPOINT%/}

# TLS posture, chosen explicitly rather than defaulted to insecure. A named
# CA file is a different security claim from -k and the two must not be
# spelled the same way.
TLS=""
TLS_NOTE="system trust store"
CACERT=${CASS_NETBOX_CACERT:-${SROIAAA_NETBOX_CACERT:-}}
if [ -n "$CACERT" ]; then
	TLS="--cacert $CACERT"
	TLS_NOTE="pinned CA: $CACERT"
elif [ "${CASS_NETBOX_INSECURE:-0}" = "1" ]; then
	TLS="-k"
	TLS_NOTE="VERIFICATION DISABLED (CASS_NETBOX_INSECURE=1)"
fi

hr() { printf '\n== %s ==\n' "$1"; }

# Both helpers print exactly one status code. curl already writes 000 through
# -w when it cannot connect, so a `|| echo 000` fallback appends a second one
# and prints "000000" -- which is what the first version of this script did, on
# the very TLS failure it exists to diagnose.
anon() {
	code=$(curl -s $TLS --max-time 20 -o "$BODY" -w '%{http_code}' "$ENDPOINT$1" 2>/dev/null) || true
	echo "${code:-000}"
}
auth() {
	code=$(curl -s $TLS --max-time 30 -o "$BODY" -w '%{http_code}' \
		-H "Authorization: Token $TOKEN" \
		-H 'Accept: application/json' "$ENDPOINT$1" 2>/dev/null) || true
	echo "${code:-000}"
}

BODY=$(mktemp "${TMPDIR:-/tmp}/netbox-probe.XXXXXX")
trap 'rm -f "$BODY"' EXIT INT TERM

# count reads NetBox's envelope, which reports the FULL match count in "count"
# regardless of how many results the page carries. That distinction is the
# whole reason this project computes censuses in code.
count() { python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("count","?"))
except Exception: print("?")' "$BODY"; }

keys() { python3 -c 'import json,sys
try:
    d=json.load(open(sys.argv[1])); r=d.get("results") or []
    print(", ".join(sorted(r[0].keys())) if r else "(no rows)")
except Exception as e: print("(unparseable: %s)" % e)' "$BODY"; }

hr "reachability and TLS"
printf 'endpoint    %s\n' "$ENDPOINT"
printf 'tls         %s\n' "$TLS_NOTE"

# /api/status/ is readable without a credential on this deployment, which makes
# it the reachability probe: it separates "the network path is broken" from
# "the token is wrong". Zabbix has apiinfo.version for the same purpose.
code=$(anon /api/status/)
printf 'status      http=%s' "$code"
if [ "$code" = "200" ]; then
	python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print("  netbox=%s django=%s python=%s plugins=%s"
      % (d.get("netbox-version"), d.get("django-version"),
         d.get("python-version"), ",".join(d.get("plugins",{})) or "none"))' "$BODY"
else
	echo
	echo 'netbox-probe: cannot reach the API unauthenticated.' >&2
	echo 'netbox-probe: http=000 is a TLS or network failure, NOT a bad token.' >&2
	echo 'netbox-probe: this deployment serves only its leaf certificate, so the' >&2
	echo 'netbox-probe: chain cannot be built from the system trust store. Supply' >&2
	echo 'netbox-probe: the issuing intermediate rather than disabling verification:' >&2
	echo 'netbox-probe:' >&2
	echo 'netbox-probe:   curl -so /tmp/i.crt http://crt.sectigo.com/InCommonRSAOVSSLCA3.crt' >&2
	echo 'netbox-probe:   openssl x509 -inform DER -in /tmp/i.crt -out ~/.config/sroiaaa/netbox-ca.pem' >&2
	echo 'netbox-probe:   export CASS_NETBOX_CACERT=$HOME/.config/sroiaaa/netbox-ca.pem' >&2
	exit 1
fi

# Anonymous read must stay denied. If this ever returns 200, NetBox is serving
# the estate inventory to anyone who can reach it and that is the finding.
code=$(anon /api/dcim/devices/?limit=1)
if [ "$code" = "403" ]; then
	printf 'anon read   denied (403), as it should be\n'
else
	printf 'anon read   *** http=%s -- ANONYMOUS READ IS OPEN, investigate ***\n' "$code"
fi

[ "$ONLY" = "reach" ] && exit 0

if [ -z "$TOKEN" ]; then
	echo
	echo 'netbox-probe: NETBOX_RO_TOKEN is not set; stopping after the checks' >&2
	echo 'netbox-probe: that do not need it. Re-run with the token exported to' >&2
	echo 'netbox-probe: sample devices, addresses, racks and cabling.' >&2
	exit 2
fi

hr "token scope"
code=$(auth /api/users/tokens/provision/)
printf 'token       reachable with Authorization: Token (http=%s on provision probe)\n' "$code"

# A read-only token must be read-only at the API permission layer, not merely
# by convention. Zabbix refuses host.update with an explicit permission error;
# NetBox should refuse a write the same way. This sends no body, so it cannot
# create anything even if the permission check were wrong.
code=$(curl -s $TLS --max-time 20 -o "$BODY" -w '%{http_code}' \
	-X POST -H "Authorization: Token $TOKEN" \
	-H 'Content-Type: application/json' --data '{}' \
	"$ENDPOINT/api/dcim/sites/" 2>/dev/null) || true
code=${code:-000}
case $code in
403) printf 'write       refused (403) at the permission layer -- correct\n' ;;
400) printf 'write       *** http=400: the token was ALLOWED to attempt a write ***\n' ;;
*)   printf 'write       http=%s (inspect: %s)\n' "$code" "$(head -c 120 "$BODY")" ;;
esac

hr "scope: devices and status"
for path in \
	"/api/dcim/devices/?limit=1" \
	"/api/dcim/sites/?limit=1" \
	"/api/dcim/device-roles/?limit=1" \
	"/api/virtualization/virtual-machines/?limit=1"
do
	code=$(auth "$path")
	printf '%-46s http=%s count=%s\n' "$path" "$code" "$(count)"
done
code=$(auth "/api/dcim/devices/?limit=1")
printf 'device fields: %s\n' "$(keys)"

hr "scope: IP addressing"
for path in \
	"/api/ipam/ip-addresses/?limit=1" \
	"/api/ipam/prefixes/?limit=1" \
	"/api/ipam/vlans/?limit=1"
do
	code=$(auth "$path")
	printf '%-46s http=%s count=%s\n' "$path" "$code" "$(count)"
done

hr "scope: racks, power, physical layout"
for path in \
	"/api/dcim/racks/?limit=1" \
	"/api/dcim/power-feeds/?limit=1" \
	"/api/dcim/power-panels/?limit=1" \
	"/api/dcim/locations/?limit=1"
do
	code=$(auth "$path")
	printf '%-46s http=%s count=%s\n' "$path" "$code" "$(count)"
done

hr "scope: cabling and circuits"
for path in \
	"/api/dcim/cables/?limit=1" \
	"/api/dcim/interfaces/?limit=1" \
	"/api/circuits/circuits/?limit=1" \
	"/api/circuits/providers/?limit=1"
do
	code=$(auth "$path")
	printf '%-46s http=%s count=%s\n' "$path" "$code" "$(count)"
done

hr "naming reconciliation"
# Zabbix and Wazuh disagree about host names -- log001 versus
# log001.pegasus.arc.gwu.edu -- and the nbxsync plugin means NetBox may be
# upstream of the Zabbix names. Whether NetBox names match either one decides
# how much translation a connector has to do.
code=$(auth "/api/dcim/devices/?limit=5&brief=true")
python3 -c 'import json,sys
try:
    for r in (json.load(open(sys.argv[1])).get("results") or []):
        print("   %s" % r.get("name"))
except Exception as e: print("   (unparseable: %s)" % e)' "$BODY"

hr "graphql"
# GraphQL and REST disagree about what an ANONYMOUS caller gets. Measured
# 2026-08-31:
#
#   no Authorization header   REST 403        GraphQL 200 {"device_list":[]}
#   invalid token             REST 403        GraphQL 403
#
# So GraphQL does reject a bad credential. What it does not reject is the
# absence of one: it answers successfully with an empty set, which is
# indistinguishable from an estate containing nothing. The realistic bug is
# therefore a connector that never attaches the header at all -- an unset
# environment variable, which this project has already been bitten by once --
# and it would look like a clean answer rather than a failure.
#
# A token must therefore be checked POSITIVELY, by requiring a row back.
gql() {
	curl -s $TLS --max-time 30 -o "$BODY" -w '%{http_code}' \
		-H "Content-Type: application/json" ${1:+-H "Authorization: Token $TOKEN"} \
		--data '{"query":"{ device_list(pagination:{limit:1}) { name } }"}' \
		"$ENDPOINT/graphql/" 2>/dev/null || true
}

rows() { python3 -c 'import json,sys
try:
	d=json.load(open(sys.argv[1]))
	if d.get("errors"): print("errors")
	else: print(len((d.get("data") or {}).get("device_list") or []))
except Exception: print("nonjson")' "$BODY"; }

acode=$(gql "")
arows=$(rows)
printf 'anonymous   http=%s rows=%s\n' "$acode" "$arows"
if [ "$acode" = "200" ] && [ "$arows" = "0" ]; then
	echo '  note: anonymous GraphQL answers 200 with an empty set, not 403.'
	echo '  An empty result here is NOT evidence that the estate is empty.'
fi

tcode=$(gql yes)
trows=$(rows)
printf 'with token  http=%s rows=%s\n' "$tcode" "$trows"
case "$tcode/$trows" in
403/*)
	echo '  the token was REJECTED for GraphQL (403). It may still work over'
	echo '  REST -- compare the counts above -- or it may be invalid entirely.' ;;
200/0)
	echo '  *** ambiguous: authenticated, but zero devices returned. That is the'
	echo '  *** same answer an unauthenticated caller gets. Compare the REST'
	echo '  *** device count above before concluding the estate is empty.' ;;
200/errors)
	echo '  the endpoint reported a query error; the schema may differ by version' ;;
200/*)
	echo '  positive result: the token returns data over GraphQL' ;;
*)
	echo "  unexpected: http=$tcode rows=$trows" ;;
esac

hr "pagination ceiling"
# NetBox caps page size server-side (MAX_PAGE_SIZE, 1000 by default). A caller
# that asks for more gets the cap silently, which is exactly how a page becomes
# mistaken for a population.
code=$(auth "/api/dcim/devices/?limit=100000")
python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print("   asked for 100000, server returned %s rows of %s total"
      % (len(d.get("results") or []), d.get("count")))' "$BODY" 2>/dev/null \
  || echo "   (could not read the envelope)"

printf '\nRecord anything surprising in the NetBox Interaction Guide.\n'
