#!/bin/sh
# rt_oldest_open.sh -- ask Request Tracker directly, with no Cassandra code in
# the path, for active tickets created more than N days ago: a count per queue,
# the total, and the oldest few.
#
#   RT_API_TOKEN=...  scripts/rt_oldest_open.sh [-d DAYS] [-n COUNT] [-a | QUEUE ...]
#
#   scripts/rt_oldest_open.sh rtshelp hpchelp          # Clark's two queues
#   scripts/rt_oldest_open.sh hpchelp rtshelp change redcaphelp alerts lustrepurge
#   scripts/rt_oldest_open.sh -a                       # every queue the token can see
#
# Needs RT_API_TOKEN (an RT auth token, not the Zabbix key) in the environment.
# The endpoint defaults to CASS_RT_ENDPOINT, else https://tickets.arc.gwu.edu.
# "Active" is RT's own Status = '__Active__', which follows each queue's
# lifecycle, as Cassandra's status: active does. It is not new/open/stalled:
# queues with their own lifecycles count differently. Dates are sent in this
# machine's local time, which is how RT reads a bare date literal.
set -eu

days=30
count=5
all=0
while getopts "d:n:a" opt; do
	case $opt in
	d) days=$OPTARG ;;
	n) count=$OPTARG ;;
	a) all=1 ;;
	*) echo "usage: $0 [-d DAYS] [-n COUNT] [-a | QUEUE ...]" >&2; exit 2 ;;
	esac
done
shift $((OPTIND - 1))

if [ -z "${RT_API_TOKEN:-}" ]; then
	echo "RT_API_TOKEN is not set" >&2
	exit 2
fi
endpoint=${CASS_RT_ENDPOINT:-https://tickets.arc.gwu.edu}
cutoff=$(python3 -c "import datetime,sys; print((datetime.datetime.now()-datetime.timedelta(days=int(sys.argv[1]))).strftime('%Y-%m-%d %H:%M:%S'))" "$days")
active="Status = '__Active__'"

rt() { # rt QUERY PER_PAGE
	curl -sS --fail -m 60 -G "$endpoint/REST/2.0/tickets" \
		-H "Authorization: token $RT_API_TOKEN" \
		--data-urlencode "query=$1" --data-urlencode "per_page=$2" \
		--data-urlencode "fields=Subject,Queue,Owner,Status,Created" \
		--data-urlencode "fields[Queue]=Name" \
		--data-urlencode "orderby=Created" --data-urlencode "order=ASC"
}

# Queue names may contain spaces ("office hours"), so the list is carried one
# name per line and read back with IFS set to a newline.
nl='
'
if [ "$all" = 1 ]; then
	# Every queue the token can see.
	names=$(curl -sS --fail -m 60 -G "$endpoint/REST/2.0/queues/all" \
		-H "Authorization: token $RT_API_TOKEN" \
		--data-urlencode "per_page=100" --data-urlencode "fields=Name" |
		python3 -c 'import sys,json; [print(q["Name"]) for q in json.load(sys.stdin)["items"]]')
elif [ $# -gt 0 ]; then
	names=$(printf '%s\n' "$@")
else
	names="rtshelp${nl}hpchelp"
fi

echo "Active tickets created before $cutoff (more than $days days ago), from $endpoint"
echo
clause=""
oldifs=$IFS
IFS=$nl
for queue in $names; do
	IFS=$oldifs
	n=$(rt "$active AND Queue = '$queue' AND Created < '$cutoff'" 1 |
		python3 -c 'import sys,json; print(json.load(sys.stdin)["total"])')
	printf '  %-14s %5s\n' "$queue" "$n"
	clause="${clause:+$clause OR }Queue = '$queue'"
	IFS=$nl
done
IFS=$oldifs

query="$active AND ($clause) AND Created < '$cutoff'"
if [ "$all" = 1 ]; then
	# No queue clause at all, so a queue the listing missed still counts.
	query="$active AND Created < '$cutoff'"
fi
echo
echo "TicketSQL: $query"
rt "$query" "$count" | python3 -c '
import sys, json, datetime
data = json.load(sys.stdin)
print("Total:", data["total"])
print()
now = datetime.datetime.now(datetime.timezone.utc)
for t in data["items"]:
    created = datetime.datetime.fromisoformat(t["Created"].replace("Z", "+00:00"))
    queue = t["Queue"].get("Name", t["Queue"]["id"]) if isinstance(t["Queue"], dict) else t["Queue"]
    owner = t["Owner"]["id"] if isinstance(t["Owner"], dict) else t["Owner"]
    ident, subject = t["id"], t["Subject"][:60]
    print(f"{ident:>7}  {queue:<11} {owner:<22} {created:%Y-%m-%d}  {(now - created).days:>5}d  {subject}")
'
