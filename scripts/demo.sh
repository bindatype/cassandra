#!/bin/sh
# A short walkthrough of the Cass evidence loop, for showing someone.
#
#   source ~/.config/sroiaaa/env
#   sh scripts/demo.sh
#
# Read-only throughout. Nothing here modifies any system.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POLICY=${CASS_POLICY:-"$ROOT/configs/broker-policy.example.json"}
BIN=${CASS_BIN:-"$ROOT/runtime"}

mkdir -p "$BIN"
go build -o "$BIN/cass-chat" "$ROOT/cmd/cass-chat"
go build -o "$BIN/cass-broker-plan" "$ROOT/cmd/cass-broker-plan"
go build -o "$BIN/cass-broker-exec" "$ROOT/cmd/cass-broker-exec"

AUDIT=$(mktemp "${TMPDIR:-/tmp}/cass-demo-audit.XXXXXX")
ask() { "$BIN/cass-chat" -policy "$POLICY" -wazuh-insecure -audit "$AUDIT" "$@"; }

rule() { printf '\n\033[1m%s\033[0m\n%s\n' "$1" "----------------------------------------------------------------"; }

rule "1. A question in English, answered from the live scheduler database"
ask -trace "how many jobs failed in the last 7 days, and how many completed?"

rule "2. Verify it independently"
echo "The same counts, straight from MariaDB:"
mysql -e "SELECT SUM(State='FAILED') AS failed, SUM(State='COMPLETED') AS completed
          FROM pegasusdb.runTBL2
          WHERE SubmitTime >= UNIX_TIMESTAMP(NOW() - INTERVAL 7 DAY);"

rule "3. The model gets three fields, and policy resolves the rest"
echo "It proposed only an intent and a query. It cannot choose a host, a"
echo "connection string, a credential, or a table it was not told about."
echo "Everything else in the plan came from policy."

rule "4. A question with no data source behind it"
echo "Nothing in the catalog reports vulnerabilities. Watch it decline rather"
echo "than answer from the nearest source it does have:"
ask -trace "are there any critical CVEs on the login nodes?" || true

rule "5. The broker cannot be bypassed by writing your own plan"
echo "A hand-written plan asking for a file no policy authorizes:"
printf '%s\n' '{"version":1,"intent":"live.evidence","steps":[{"source":"cass-agent","action":"operations.execute","host":"docker-harness","operation":"filesystem.read","target":{"path":"/etc/shadow"},"params":{"max_bytes":8192}}]}' \
  | "$BIN/cass-broker-exec" -policy "$POLICY" || true
echo
echo "The executor reconstructs every plan policy could have produced and"
echo "requires a match. A substituted path, an inflated limit, or an extra"
echo "step all fail before anything runs."

rule "6. Every question leaves an audit record"
echo "Question, the model's verbatim proposal, the policy decision, and the"
echo "SQL that actually ran:"
python3 - "$AUDIT" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line)
    print("  %s  %-12s  %s" % (e["request_id"], e["decision"], e["question"][:52]))
    for c in e.get("calls", []):
        print("      %s %s  %dms  %d items" % (c["source"], c["action"], c["duration_ms"], c["item_count"]))
        if c.get("query"):
            print("      SQL: %s" % " ".join(c["query"].split())[:96])
    print("      status=%s answer_chars=%d" % (e["status"], e.get("answer_chars", 0)))
PY

rule "What this is not"
cat <<'EOF'
  - Not production. No TLS, no per-person identity, no rate limiting.
  - The model composes SQL for the database source. That is bounded by a
    read-only single-schema grant, a statement timeout and a 50-row cap,
    but roughly one question in six still returns a wrong count or an
    error. The fixed-intent sources do not have that problem.
  - Four sources only: Wazuh agents, Zabbix problems, the accounting
    database, and a filesystem read that has no connector yet.
EOF

rm -f "$AUDIT"
