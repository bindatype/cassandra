# Locate Cassandra's configuration during the rename from SROIAAA.
#
# Sourced, not executed. Every script that reads ~/.config/cass needs the same
# fallback, and four copies of it would drift -- the last thing this project
# needs is two scripts disagreeing about where the credentials live.
#
# Config moved from ~/.config/sroiaaa to ~/.config/cass. The old location is
# still read, because it holds the credentials for a cron job that posts at
# 04:45 and for contributors whose machines nobody here can reach. Using it
# says so on stderr, which is what stops the compatibility becoming permanent.

# cass_config_path NAME [VAR]
#
# Prints the path to a configuration file. VAR, when given, names an
# environment variable that overrides the search entirely -- CASS_ENV and
# CASS_POLICY exist so a caller can point at a file anywhere.
#
# Returns the NEW path when neither location has the file, so a "no such file"
# message names where the file should be created rather than where it used to
# live.
cass_config_path() {
	_name=$1
	_override_var=${2:-}
	if [ -n "$_override_var" ]; then
		eval "_override=\${$_override_var:-}"
		if [ -z "$_override" ]; then
			# The old spelling of the override, for the same reason as the
			# directory itself.
			eval "_override=\${SROIAAA_${_override_var#CASS_}:-}"
			[ -z "$_override" ] || cass_warn_legacy "SROIAAA_${_override_var#CASS_}" "$_override_var"
		fi
		if [ -n "$_override" ]; then
			printf '%s' "$_override"
			return 0
		fi
	fi

	if [ -r "$HOME/.config/cass/$_name" ]; then
		printf '%s' "$HOME/.config/cass/$_name"
		return 0
	fi
	if [ -r "$HOME/.config/sroiaaa/$_name" ]; then
		cass_warn_legacy "~/.config/sroiaaa/$_name" "~/.config/cass/$_name"
		printf '%s' "$HOME/.config/sroiaaa/$_name"
		return 0
	fi
	printf '%s' "$HOME/.config/cass/$_name"
}

# cass_state_path NAME -- the same treatment for ~/.local/state.
cass_state_path() {
	if [ -r "$HOME/.local/state/cass/$1" ]; then
		printf '%s' "$HOME/.local/state/cass/$1"
		return 0
	fi
	if [ -r "$HOME/.local/state/sroiaaa/$1" ]; then
		cass_warn_legacy "~/.local/state/sroiaaa/$1" "~/.local/state/cass/$1"
		printf '%s' "$HOME/.local/state/sroiaaa/$1"
		return 0
	fi
	printf '%s' "$HOME/.local/state/cass/$1"
}

# cass_warn_legacy OLD NEW -- said once per name, so a script that resolves the
# same path twice does not print the same sentence twice and train the reader
# to ignore it.
cass_warn_legacy() {
	case " ${_cass_warned:-} " in
	*" $1 "*) return 0 ;;
	esac
	_cass_warned="${_cass_warned:-} $1"
	echo "warning: using $1; rename it to $2" >&2
}

# cass_value NAME -- the value of a CASS_ variable, falling back to its
# SROIAAA_ spelling and saying so.
#
# This exists because a shell precheck that only knows the new names refuses
# before the Go program -- which does know both -- ever runs. zoom-digest.sh
# had exactly that defect for the length of one commit: its required-variable
# list was renamed, the fallback was not, and the 04:45 job would have exited 2
# with "not set in this environment" against an environment that was fine.
cass_value() {
	eval "_v=\${$1:-}"
	if [ -z "$_v" ]; then
		_legacy="SROIAAA_${1#CASS_}"
		eval "_v=\${$_legacy:-}"
		[ -z "$_v" ] || cass_warn_legacy "$_legacy" "$1"
	fi
	printf '%s' "$_v"
}
