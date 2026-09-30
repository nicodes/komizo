#!/bin/sh
# cli/scripts/preview-run.sh - run the komizo-box preview primitive as root.
#
# Installed on the box as /usr/local/bin/komizo-preview for apps that have
# previews, and reachable from the deploy account through doas.
#
# WHY A WRAPPER RATHER THAN A DOAS RULE ON komizo-box. komizo-box does
# everything on this server; granting it would grant all of it. This narrows
# the account to four preview subcommands and locks every one of them to the
# caller's own app.
#
# POSIX sh, not bash. The version this replaces began `#!/bin/bash` and used
# arrays, which is a dependency on a shell Alpine does not install by default
# -- and every other script komizo puts on a box is sh.
#
# Registry credentials for up's image pull, mirroring what deploy does:
#   --registry-user <user>  a flag; the ghcr user (e.g. github-actions[bot])
#   the token on STDIN      never an argument -- argv is visible in ps
# The login runs in an isolated DOCKER_CONFIG so a concurrent deploy's own
# docker login/logout on /root/.docker cannot race the pull, and no credential
# outlives the run. A failed login aborts before any pull. down/ls/gc pull
# nothing and carry no credentials. The registry host is fixed: ghcr.io.
set -eu

sub="${1:-}"
case "$sub" in
	up|down|ls|gc) : ;;
	*) echo "komizo-preview: refused (preview up|down|ls|gc only)" >&2; exit 2 ;;
esac

# One account, one app: komizo names every deploy account komizo-<app>, so the
# app this caller may touch is derivable and does not have to be trusted from
# the arguments. Unset DOAS_USER means root ran it directly.
want_app=""
[ -z "${DOAS_USER:-}" ] || want_app="${DOAS_USER#komizo-}"

refuse_app() {
	echo "komizo-preview: refused (${DOAS_USER:-?} may not preview app '$1')" >&2
	exit 2
}

# Rebuild the argument list, dropping --registry-user (which is ours, not
# komizo-box's) and checking every --app against the caller's own.
#
# Pop from the front, push the keepers onto the back, exactly as many times as
# there were arguments to begin with. An array would read better; POSIX sh has
# one list and this is how you filter it without leaving the shell.
reguser=""
remaining=$#
while [ "$remaining" -gt 0 ]; do
	remaining=$((remaining - 1))
	arg="$1"
	shift
	case "$arg" in
		--registry-user)
			# $remaining, not $#: keepers are pushed onto the back of the
			# same list, so $# counts arguments already dealt with and would
			# happily hand back a rotated one as this flag's value.
			[ "$remaining" -gt 0 ] || { echo "komizo-preview: --registry-user needs a value" >&2; exit 1; }
			reguser="$1"
			shift
			remaining=$((remaining - 1))
			;;
		--registry-user=*)
			reguser="${arg#*=}"
			;;
		--app|-app)
			[ "$remaining" -gt 0 ] || { echo "komizo-preview: $arg needs a value" >&2; exit 1; }
			[ -z "$want_app" ] || [ "$1" = "$want_app" ] || refuse_app "$1"
			set -- "$@" "$arg" "$1"
			shift
			remaining=$((remaining - 1))
			;;
		--app=*|-app=*)
			value="${arg#*=}"
			[ -z "$want_app" ] || [ "$value" = "$want_app" ] || refuse_app "$value"
			set -- "$@" "$arg"
			;;
		*)
			set -- "$@" "$arg"
			;;
	esac
done

if [ "$sub" = "up" ] && [ -n "$reguser" ]; then
	# ghcr user alphabet: letters, digits, . _ @ - and [ ] for
	# github-actions[bot].
	case "$(printf '%s' "$reguser" | tr -d 'A-Za-z0-9._@[]-')" in
		'') : ;;
		*) echo "komizo-preview: refusing registry user '$reguser'" >&2; exit 1 ;;
	esac
	# Piped, never typed at a terminal: a token somebody types is a token in
	# a scrollback.
	[ ! -t 0 ] || { echo "komizo-preview: the registry token must arrive on stdin (piped)" >&2; exit 1; }
	token="$(cat)"
	[ -n "$token" ] || { echo "komizo-preview: up with --registry-user needs the registry token on stdin" >&2; exit 1; }
	DOCKER_CONFIG="$(mktemp -d)"
	export DOCKER_CONFIG
	# shellcheck disable=SC2329 # invoked by the traps below.
	cleanup() { rm -rf "${DOCKER_CONFIG:-}" 2>/dev/null || true; }
	# The signal handlers exit rather than returning: a handler that returns
	# resumes the script, which would carry on with the credential directory
	# already removed.
	trap cleanup EXIT
	trap 'cleanup; exit 129' INT TERM HUP PIPE
	if ! printf '%s' "$token" | docker login ghcr.io -u "$reguser" --password-stdin >/dev/null 2>&1; then
		echo "komizo-preview: could not authenticate to ghcr.io as $reguser" >&2
		exit 1
	fi
	unset token
	# A CHILD, not exec, so the EXIT trap still drops DOCKER_CONFIG however
	# komizo-box exits.
	rc=0
	/usr/local/bin/komizo-box preview "$@" </dev/null || rc=$?
	exit "$rc"
fi

exec /usr/local/bin/komizo-box preview "$@" </dev/null
