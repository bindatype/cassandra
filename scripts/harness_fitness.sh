#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REPORT_PATH=${1:-"$ROOT_DIR/runtime/harness-fitness.md"}

mkdir -p "$(dirname "$REPORT_PATH")"

tmp_file=$(mktemp "${TMPDIR:-/tmp}/cass-fitness.XXXXXX")
trap 'rm -f "$tmp_file"' EXIT INT TERM

# Run the survey inside the live harness so the report reflects the
# actual operator surface, not the host machine.
docker compose exec -T cass sh <<'EOF' > "$tmp_file"
set -eu

busybox_path=$(command -v busybox 2>/dev/null || true)

required_total=0
required_missing=0
recommended_total=0
recommended_missing=0
optional_total=0
optional_present=0
contextual_total=0
contextual_present=0

record() {
	tier=$1
	expectation=$2
	tool=$3
	status=absent
	note=-

	if path=$(command -v "$tool" 2>/dev/null); then
		status=present
		note=$path
	elif [ -n "$busybox_path" ] && busybox --list 2>/dev/null | grep -qx "$tool"; then
		status=busybox-applet
		note=$busybox_path
	fi

	case "$expectation" in
		required)
			required_total=$((required_total + 1))
			if [ "$status" = "absent" ]; then
				required_missing=$((required_missing + 1))
			fi
			;;
		recommended)
			recommended_total=$((recommended_total + 1))
			if [ "$status" = "absent" ]; then
				recommended_missing=$((recommended_missing + 1))
			fi
			;;
		optional)
			optional_total=$((optional_total + 1))
			if [ "$status" != "absent" ]; then
				optional_present=$((optional_present + 1))
			fi
			;;
		contextual)
			contextual_total=$((contextual_total + 1))
			if [ "$status" != "absent" ]; then
				contextual_present=$((contextual_present + 1))
			fi
			;;
	esac

	printf '| %s | %s | %s | %s | %s |\n' "$tier" "$expectation" "$tool" "$status" "$note"
}

generated_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date)
cap_eff=$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null || echo unknown)
pretty_name=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/, "", $2); print $2}' /etc/os-release 2>/dev/null || echo unknown)

printf '# Cass Harness Fitness Report\n\n'
printf -- '- Generated from harness: %s\n' "$generated_at"
printf -- '- Identity: %s\n' "$(id)"
printf -- '- OS: %s\n' "$pretty_name"
printf -- '- Effective capabilities: %s\n\n' "$cap_eff"
printf -- '- DNS utility family note: RPM-style `bind-utils` usually maps to `host` and `dig`, which are checked below as binaries.\n\n'

printf '## Tool Matrix\n\n'
printf '| Tier | Expectation | Tool | Status | Note |\n'
printf '| --- | --- | --- | --- | --- |\n'

record core-readonly required sh
record core-readonly required cat
record core-readonly required ls
record core-readonly required find
record core-readonly required grep
record core-readonly required sed
record core-readonly required awk
record core-readonly required head
record core-readonly required tail
record core-readonly required wc
record core-readonly required cut
record core-readonly required sort
record core-readonly required uniq
record core-readonly required stat
record core-readonly required readlink
record core-readonly required ps
record core-readonly required id
record core-readonly required uname
record core-readonly required df
record core-readonly required mount

record network-readonly recommended ip
record network-readonly recommended netstat
record network-readonly recommended ss
record network-readonly recommended ping
record network-readonly recommended traceroute
record network-readonly recommended nslookup
record network-readonly recommended showmount
record network-readonly recommended curl

record network-optional optional telnet
record network-optional optional host
record network-optional optional dig
record network-optional optional ethtool
record network-optional optional tcpdump
record network-optional optional tshark
record network-optional optional nuttcp

record host-service contextual systemctl
record host-service contextual journalctl
record host-service contextual nmcli
record host-service contextual dbus-send

record scheduler-hpc contextual scontrol
record scheduler-hpc contextual sinfo
record scheduler-hpc contextual squeue
record scheduler-hpc contextual sacct
record scheduler-hpc contextual nvidia-smi

record deep-probe contextual python3
record deep-probe contextual jq

core_present=$((required_total - required_missing))
recommended_present=$((recommended_total - recommended_missing))

printf '\n## Fitness Summary\n\n'
if [ "$required_missing" -eq 0 ]; then
	printf -- '- Core read-only baseline: pass (%s/%s present or busybox-backed)\n' "$core_present" "$required_total"
else
	printf -- '- Core read-only baseline: degraded (%s/%s present or busybox-backed)\n' "$core_present" "$required_total"
fi
printf -- '- Recommended network/operator tools: %s/%s present or busybox-backed\n' "$recommended_present" "$recommended_total"
printf -- '- Optional network diagnostics: %s/%s present or busybox-backed\n' "$optional_present" "$optional_total"
printf -- '- Contextual host or HPC tools present: %s/%s\n' "$contextual_present" "$contextual_total"
if [ "$required_missing" -eq 0 ]; then
	printf -- '- Interpretation: the harness is fit for bounded read-only investigations, but richer host-style diagnostics still depend on extra packages or a different environment.\n'
else
	printf -- '- Interpretation: fill the missing core tools before treating this image as a general-purpose read-only diagnostic harness.\n'
fi
EOF

mv "$tmp_file" "$REPORT_PATH"
printf 'wrote %s\n' "$REPORT_PATH"
