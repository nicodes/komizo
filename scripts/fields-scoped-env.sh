#!/bin/sh
# Root-only fields-postgres-v2 provision. Not reachable through doas.
# Generates four database passwords and WS_SECRET on this host, reads four
# Clerk values from a root-local file or the terminal, and derives the two
# postgres URLs. CLERK_SECRET_KEY is a production sk_live_ value and is written
# only to api.env. Terminal entry turns echo off for all four reads and restores
# the previous settings on success, refusal, and signal. It does not read a CI
# batch, accept the secret as an argument, print a value, or rotate an
# initialized database.
set -eu

APP_NAME="__APP_NAME__"
STATE_FILE="__STATE_FILE__"
LOCK_FILE="__LOCK_FILE__"
PROFILE="fields-postgres-v2"

hex32() {
	awk -v s="$1" 'BEGIN { exit (s ~ /^[0-9a-f]{32}$/) ? 0 : 1 }'
}

facts_tmp=""
tty_saved=""
provenance_tmp=""
restore_tty() {
	[ -n "$tty_saved" ] || return 0
	saved=$tty_saved
	# shellcheck disable=SC2086 # stty -g output is arguments for a later stty
	stty $saved < /dev/tty || return 1
	tty_saved=""
	return 0
}
cleanup() {
	restore_tty || true
	if [ -n "$facts_tmp" ]; then
		rm -f "$facts_tmp"
	fi
	if [ -n "$provenance_tmp" ]; then
		rm -f "$provenance_tmp"
	fi
}
trap cleanup EXIT
trap 'cleanup; exit 129' INT TERM HUP PIPE

fail() {
	echo "provision-scoped-env: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"

for leaked in POSTGRES_PASSWORD REVIK_MIGRATOR_PASSWORD REVIK_APP_PASSWORD REVIK_BACKUP_PASSWORD DATABASE_URL DATABASE_MIGRATION_URL WS_SECRET CLERK_ISSUER CLERK_JWKS_URL CLERK_AUTHORIZED_PARTIES CLERK_SECRET_KEY; do
	# A value already in the environment would be copied into a file from a
	# channel this command does not accept. Refuse before reading it back.
	if eval "[ -n \"\${$leaked+x}\" ]"; then
		fail "refusing: $leaked is set in the environment"
	fi
done

check_compose=""
clerk_file=""
compose_file=""
while [ "$#" -gt 0 ]; do
	case "$1" in
		--check-compose)
			[ "$#" -ge 2 ] || fail "refusing: --check-compose needs one path"
			[ -z "$check_compose" ] || fail "refusing: unexpected arguments"
			check_compose=$2
			shift 2
			;;
		--clerk-file)
			[ "$#" -ge 2 ] || fail "refusing: --clerk-file needs one path"
			[ -z "$clerk_file" ] || fail "refusing: unexpected arguments"
			clerk_file=$2
			shift 2
			;;
		--compose-file)
			[ "$#" -ge 2 ] || fail "refusing: --compose-file needs one path"
			[ -z "$compose_file" ] || fail "refusing: unexpected arguments"
			compose_file=$2
			shift 2
			;;
		*) fail "refusing: unexpected arguments" ;;
	esac
done
if [ -n "$check_compose" ] && { [ -n "$clerk_file" ] || [ -n "$compose_file" ]; }; then
	fail "refusing: unexpected arguments"
fi

state_get() {
	key=$1
	sed -n "s/^$key=//p" "$STATE_FILE" | tr -d '\r' | head -n 1
}

[ -f "$STATE_FILE" ] || fail "refusing: app record is missing"
[ "$(state_get APP_NAME)" = "$APP_NAME" ] || fail "refusing: app record is not $APP_NAME"
[ "$(state_get SCOPED_ENV)" = "$PROFILE" ] || fail "refusing: profile is not $PROFILE"
APP_DIR=$(state_get APP_DIR)
case "$APP_DIR" in
	/*) ;;
	*) fail "refusing: app record APP_DIR is not absolute" ;;
esac
case "$APP_DIR" in
	*/secrets|*/secrets/*) fail "refusing: app record APP_DIR is inside secrets" ;;
esac

scoped_facts() {
	src=$1
	facts_tmp=$(mktemp)
	chmod 600 "$facts_tmp"
	if ! docker compose -f "$src" --project-directory "$APP_DIR" config --no-interpolate --no-env-resolution --format json 2>"$facts_tmp.err" | awk '
function qval(s,   t) {
	t = s
	sub(/,$/, "", t)
	gsub(/^[ \t]+|[ \t]+$/, "", t)
	if (t !~ /^"[^"\\]*"$/) return ""
	return substr(t, 2, length(t) - 2)
}
BEGIN { bad = 0; pg = 0; project = ""; in_vol = 0; volkey = "" }
{
	if ($0 ~ /"aliases":/) bad = 1
	if ($0 ~ /^  "name": /) {
		v = qval(substr($0, 10))
		if (v == "" || project != "") bad = 1
		else project = v
	}
	if ($0 ~ /^  "volumes": \{$/) { in_vol = 1; in_svc = 0; svc = "" }
	if (in_vol && $0 ~ /^  \}$/) { in_vol = 0; volkey = "" }
	if ($0 ~ /^  "services": \{$/) { in_svc = 1; in_vol = 0; svc = "" }
	if (in_svc && $0 ~ /^  \}$/) { in_svc = 0; svc = "" }
	if (in_svc && $0 ~ /^    "[A-Za-z0-9_-]+": \{$/) {
		svc = $0
		sub(/^    "/, "", svc)
		sub(/": \{$/, "", svc)
		print "service " svc
	}
	if (in_svc && $0 ~ /^    \},?$/) svc = ""
	if (in_vol && $0 ~ /^    "[A-Za-z0-9_-]+": \{$/) {
		volkey = $0
		sub(/^    "/, "", volkey)
		sub(/": \{$/, "", volkey)
	}
	if (in_vol && volkey != "" && $0 ~ /^      "name": /) {
		v = qval(substr($0, 14))
		if (v == "") bad = 1
		else print "volume-key " volkey " " v
		volkey = ""
	}
	if (in_svc && $0 ~ /^          "path": /) {
		v = qval(substr($0, 18))
		if (v == "" || svc == "") bad = 1
		else print "service-env " svc " " v
	}
	if (in_svc && $0 ~ /^          "source": /) {
		last_source = qval(substr($0, 20))
		if (last_source == "") bad = 1
	}
	if (in_svc && $0 ~ /^          "target": "\/var\/lib\/postgresql\/data",?$/) {
		if (svc == "" || last_source == "") bad = 1
		pg++
		pg_source = last_source
		pg_service = svc
	}
}
END {
	if (bad || project == "" || project !~ /^[a-z0-9][a-z0-9_-]*$/) exit 1
	print "project " project
	print "pg-count " pg
	if (pg == 1) {
		print "pg-source " pg_source
		print "pg-service " pg_service
	}
}
' > "$facts_tmp"; then
		rm -f "$facts_tmp.err"
		return 1
	fi
	rm -f "$facts_tmp.err"
	return 0
}

compose_map_ok() {
	src=$1
	[ -f "$src" ] && [ ! -L "$src" ] || return 1
	scoped_facts "$src" || return 1
	pg=$(sed -n 's/^pg-count //p' "$facts_tmp" | head -n 1)
	[ "$pg" = "1" ] || return 1
	src_key=$(sed -n 's/^pg-source //p' "$facts_tmp" | head -n 1)
	pg_service=$(sed -n 's/^pg-service //p' "$facts_tmp" | head -n 1)
	[ "$src_key" = "pg_data" ] || return 1
	[ "$pg_service" = "postgres" ] || return 1
	grep -q "^volume-key pg_data " "$facts_tmp" || return 1
	# Per service, not a sorted set. postgres must not receive migrate.env,
	# and no other service may carry an env file, including secrets.env.
	got=$(sed -n 's/^service-env //p' "$facts_tmp" | sort)
	need=$(printf '%s\n' \
		"api $APP_DIR/secrets/current/api.env" \
		"godot-api $APP_DIR/secrets/current/godot-api.env" \
		"migrate $APP_DIR/secrets/current/migrate.env" \
		"postgres $APP_DIR/secrets/current/postgres.env" | sort)
	[ "$got" = "$need" ] || return 1
	for svc in postgres migrate api godot-api; do
		n=$(grep -c "^service $svc\$" "$facts_tmp" || true)
		[ "$n" = "1" ] || return 1
	done
	return 0
}

candidate_ok() {
	f=$1
	case "$f" in
		/*) ;;
		*) return 1 ;;
	esac
	case "$f" in
		*..*) return 1 ;;
	esac
	[ -f "$f" ] && [ ! -L "$f" ] || return 1
	owner=$(stat -c %u "$f")
	mode=$(stat -c %a "$f")
	[ "$owner" = "0" ] || return 1
	case "$mode" in
		600|644) ;;
		*) return 1 ;;
	esac
	return 0
}

if [ -n "$check_compose" ]; then
	if ! compose_map_ok "$check_compose"; then
		fail "refusing: compose file is not the fields-postgres-v2 map"
	fi
	recorded_vol=$(state_get SCOPED_PG_VOLUME || true)
	got_vol=$(sed -n 's/^volume-key pg_data //p' "$facts_tmp" | head -n 1)
	recorded_project=$(state_get SCOPED_COMPOSE_PROJECT || true)
	got_project=$(sed -n 's/^project //p' "$facts_tmp" | head -n 1)
	if [ -z "$recorded_vol" ] || [ "$got_vol" != "$recorded_vol" ] || [ "$got_project" != "$recorded_project" ]; then
		fail "refusing: compose project or postgres volume does not match the provisioned identity"
	fi
	exit 0
fi
if [ -z "$compose_file" ]; then
	fail "refusing: a validated postgres compose candidate is required"
fi
if ! candidate_ok "$compose_file"; then
	fail "refusing: compose candidate must be a root-owned regular file, mode 600 or 644, not a symlink"
fi

# The rest writes secrets. One provision at a time, same lock as deploy.
if ! command -v flock >/dev/null 2>&1; then
	fail "refusing: flock is required"
fi
mkdir -p "$(dirname "$LOCK_FILE")"
: > "$LOCK_FILE"
exec 9>"$LOCK_FILE"
if ! flock -w 300 9; then
	echo "provision-scoped-env: lock timeout" >&2
	exit 75
fi

secrets="$APP_DIR/secrets"
if [ -L "$secrets" ]; then
	fail "refusing: secrets is a symlink"
fi
if [ -e "$secrets/current" ] || [ -L "$secrets/current" ]; then
	fail "refusing: a generation already exists"
fi
recorded=$(state_get SCOPED_GENERATION || true)
if [ -n "$recorded" ]; then
	fail "refusing: a generation is already recorded"
fi

charset_ok() {
	# Environment, not argv: argv is world-readable on this box.
	SCOPED_CHECK=$1 awk 'BEGIN {
		s = ENVIRON["SCOPED_CHECK"]
		if (s == "" || length(s) > 4096) exit 1
		n = length(s)
		for (i = 1; i <= n; i++) {
			c = substr(s, i, 1)
			if (c ~ /[ "#$'\''\\`]/) exit 1
			if (c < "!" || c > "~") exit 1
		}
		exit 0
	}'
}

production_secret() {
	# sk_live_ only. sk_test_, empty, and the short env_file charset/length
	# are refused. The value is not an argument to awk and is not printed.
	printf '%s\n' "$1" | awk 'BEGIN {
		if ((getline s) != 1) exit 1
		if ((getline extra) != 0) exit 1
		if (length(s) < 9 || length(s) > 4096) exit 1
		if (substr(s, 1, 8) == "sk_test_") exit 1
		if (substr(s, 1, 8) != "sk_live_") exit 1
		n = length(s)
		for (i = 1; i <= n; i++) {
			c = substr(s, i, 1)
			if (c ~ /[ "#$'\''\\`]/) exit 1
			if (c < "!" || c > "~") exit 1
		}
		exit 0
	}'
}

https_ok() {
	SCOPED_CHECK=$1 SCOPED_ALLOW=$2 awk 'BEGIN {
		s = ENVIRON["SCOPED_CHECK"]
		allow = ENVIRON["SCOPED_ALLOW"]
		if (substr(s, 1, 8) != "https://") exit 1
		if (index(s, "@") != 0 || index(s, "?") != 0 || index(s, "#") != 0) exit 1
		rest = substr(s, 9)
		if (rest == "") exit 1
		slash = index(rest, "/")
		host = rest
		if (slash != 0) {
			if (allow != "1") exit 1
			host = substr(rest, 1, slash - 1)
			path = substr(rest, slash)
			if (path ~ /[\\[:space:]]/) exit 1
		}
		if (host !~ /^[A-Za-z0-9.-]+(:[0-9]+)?$/) exit 1
		if (host ~ /^\./ || host ~ /\.$/ || host ~ /\.\./) exit 1
		exit 0
	}'
}

read_clerk() {
	file=$1
	[ -f "$file" ] && [ ! -L "$file" ] || fail "refusing: clerk file is missing or a symlink"
	owner=$(stat -c %u "$file")
	mode=$(stat -c %a "$file")
	[ "$owner" = "0" ] && [ "$mode" = "600" ] || fail "refusing: clerk file must be root mode 600"
	n=0
	seen_issuer=0
	seen_jwks=0
	seen_parties=0
	seen_secret=0
	while IFS= read -r line || [ -n "$line" ]; do
		n=$((n + 1))
		[ "$n" -le 4 ] || fail "refusing: clerk file has extra lines"
		case "$line" in
			CLERK_ISSUER=*)
				[ "$seen_issuer" = 0 ] || fail "refusing: clerk file repeats a key"
				seen_issuer=1
				CLERK_ISSUER=${line#CLERK_ISSUER=}
				;;
			CLERK_JWKS_URL=*)
				[ "$seen_jwks" = 0 ] || fail "refusing: clerk file repeats a key"
				seen_jwks=1
				CLERK_JWKS_URL=${line#CLERK_JWKS_URL=}
				;;
			CLERK_AUTHORIZED_PARTIES=*)
				[ "$seen_parties" = 0 ] || fail "refusing: clerk file repeats a key"
				seen_parties=1
				CLERK_AUTHORIZED_PARTIES=${line#CLERK_AUTHORIZED_PARTIES=}
				;;
			CLERK_SECRET_KEY=*)
				[ "$seen_secret" = 0 ] || fail "refusing: clerk file repeats a key"
				seen_secret=1
				CLERK_SECRET_KEY=${line#CLERK_SECRET_KEY=}
				;;
			*) fail "refusing: clerk file line is not a fixed Clerk key" ;;
		esac
	done < "$file"
	[ "$n" -eq 4 ] || fail "refusing: clerk file must have exactly four lines"
	[ "$seen_issuer$seen_jwks$seen_parties$seen_secret" = "1111" ] || fail "refusing: clerk file is missing a fixed Clerk key"
}

if [ -n "$clerk_file" ]; then
	case "$clerk_file" in
		/*) ;;
		*) fail "refusing: clerk file path must be absolute" ;;
	esac
	read_clerk "$clerk_file"
else
	if [ ! -r /dev/tty ]; then
		fail "refusing: no clerk file and no terminal"
	fi
	command -v stty >/dev/null 2>&1 || fail "refusing: stty is required to hide clerk input"
	tty_saved=$(stty -g < /dev/tty) || fail "refusing: cannot read terminal settings"
	[ -n "$tty_saved" ] || fail "refusing: cannot read terminal settings"
	stty -echo < /dev/tty || fail "refusing: cannot hide clerk input"
	printf 'CLERK_ISSUER: ' >&2
	IFS= read -r CLERK_ISSUER < /dev/tty || fail "refusing: clerk input ended early"
	printf '\n' >&2
	printf 'CLERK_JWKS_URL: ' >&2
	IFS= read -r CLERK_JWKS_URL < /dev/tty || fail "refusing: clerk input ended early"
	printf '\n' >&2
	printf 'CLERK_AUTHORIZED_PARTIES: ' >&2
	IFS= read -r CLERK_AUTHORIZED_PARTIES < /dev/tty || fail "refusing: clerk input ended early"
	printf '\n' >&2
	printf 'CLERK_SECRET_KEY: ' >&2
	IFS= read -r CLERK_SECRET_KEY < /dev/tty || fail "refusing: clerk input ended early"
	printf '\n' >&2
	restore_tty || fail "refusing: cannot restore terminal echo"
fi

charset_ok "$CLERK_ISSUER" || fail "refusing: CLERK_ISSUER is not a single-line env value"
charset_ok "$CLERK_JWKS_URL" || fail "refusing: CLERK_JWKS_URL is not a single-line env value"
charset_ok "$CLERK_AUTHORIZED_PARTIES" || fail "refusing: CLERK_AUTHORIZED_PARTIES is not a single-line env value"
production_secret "$CLERK_SECRET_KEY" || fail "refusing: CLERK_SECRET_KEY is not a production key"
https_ok "$CLERK_ISSUER" 1 || fail "refusing: CLERK_ISSUER is not an https URL"
https_ok "$CLERK_JWKS_URL" 1 || fail "refusing: CLERK_JWKS_URL is not an https URL"
rest=$CLERK_AUTHORIZED_PARTIES
[ -n "$rest" ] || fail "refusing: CLERK_AUTHORIZED_PARTIES is empty"
while [ -n "$rest" ]; do
	origin=${rest%%,*}
	case "$rest" in
		*,*) rest=${rest#*,} ;;
		*) rest="" ;;
	esac
	https_ok "$origin" 0 || fail "refusing: CLERK_AUTHORIZED_PARTIES is not comma-separated https origins"
done

# The live compose.yml is not the candidate and is not modified. A placeholder
# or PocketBase file cannot prove the postgres volume, so it is not fresh.
if ! compose_map_ok "$compose_file"; then
	fail "refusing: compose candidate is not the fields-postgres-v2 map"
fi
project=$(sed -n 's/^project //p' "$facts_tmp" | head -n 1)
pg_volume=$(sed -n 's/^volume-key pg_data //p' "$facts_tmp" | head -n 1)
[ -n "$project" ] && [ -n "$pg_volume" ] || fail "refusing: postgres volume identity is missing"
if ! command -v docker >/dev/null 2>&1; then
	fail "refusing: docker is required to prove the data volume is fresh"
fi
if ! running=$(docker ps -q --filter "label=com.docker.compose.project=$project"); then
	fail "refusing: cannot tell whether the compose project is running"
fi
if [ -n "$running" ]; then
	fail "refusing: compose project has a running container"
fi

pg_markers() {
	dir=$1
	if [ -L "$dir" ] || [ ! -d "$dir" ]; then
		return 2
	fi
	if [ -e "$dir/PG_VERSION" ] || [ -e "$dir/postgresql.conf" ] || [ -e "$dir/pg_hba.conf" ] || [ -d "$dir/global" ]; then
		return 1
	fi
	return 0
}

volume_state() {
	name=$1
	# 0 fresh or absent, 1 initialized, 2 uncertain, 3 non-empty and not postgres
	inspect=$(docker volume inspect --format '{{.Driver}} {{.Mountpoint}}' "$name" 2>"$facts_tmp.verr" || true)
	if [ -z "$inspect" ]; then
		if grep -q 'no such volume' "$facts_tmp.verr" 2>/dev/null; then
			rm -f "$facts_tmp.verr"
			return 0
		fi
		rm -f "$facts_tmp.verr"
		return 2
	fi
	rm -f "$facts_tmp.verr"
	driver=${inspect%% *}
	mount=${inspect#* }
	if [ "$driver" != "local" ] || [ -z "$mount" ] || [ "$mount" = "$inspect" ]; then
		return 2
	fi
	if [ ! -d "$mount" ] && [ ! -e "$mount" ]; then
		return 0
	fi
	mark=0
	pg_markers "$mount" || mark=$?
	if [ "$mark" -eq 1 ]; then
		return 1
	fi
	if [ "$mark" -eq 2 ]; then
		return 2
	fi
	listing=$(ls -A "$mount" 2>/dev/null) || return 2
	if [ -n "$listing" ]; then
		return 3
	fi
	return 0
}

if ! labeled=$(docker volume ls -q --filter "label=com.docker.compose.project=$project"); then
	fail "refusing: cannot list compose volumes"
fi
names=$(sed -n 's/^volume-key [^ ]* //p' "$facts_tmp")
all=$(printf '%s\n%s\n' "$names" "$labeled" | awk 'NF && !seen[$0]++')
for vol in $all; do
	case "$vol" in
		*[!A-Za-z0-9_.-]*) fail "refusing: volume name is not a docker name" ;;
	esac
	st=0
	volume_state "$vol" || st=$?
	if [ "$st" -eq 1 ]; then
		fail "refusing: postgres data is already initialized"
	fi
	if [ "$st" -eq 2 ]; then
		fail "refusing: postgres volume state is uncertain"
	fi
	if [ "$st" -eq 3 ] && [ "$vol" = "$pg_volume" ]; then
		fail "refusing: declared postgres volume is not empty"
	fi
done

alnum() {
	out=""
	tries=0
	while [ "${#out}" -lt 32 ]; do
		tries=$((tries + 1))
		[ "$tries" -le 20 ] || return 1
		chunk=$(dd if=/dev/urandom bs=96 count=1 2>/dev/null | tr -dc 'A-Za-z0-9' || true)
		out="$out$chunk"
	done
	printf '%s' "$out" | cut -c 1-32
}

POSTGRES_PASSWORD=$(alnum) || fail "refusing: could not generate a password"
REVIK_MIGRATOR_PASSWORD=$(alnum) || fail "refusing: could not generate a password"
REVIK_APP_PASSWORD=$(alnum) || fail "refusing: could not generate a password"
REVIK_BACKUP_PASSWORD=$(alnum) || fail "refusing: could not generate a password"
WS_SECRET=$(alnum) || fail "refusing: could not generate WS_SECRET"
case "$POSTGRES_PASSWORD$REVIK_MIGRATOR_PASSWORD$REVIK_APP_PASSWORD$REVIK_BACKUP_PASSWORD$WS_SECRET" in
	*[!A-Za-z0-9]*) fail "refusing: generated value is not alnum" ;;
esac
[ "${#POSTGRES_PASSWORD}" -eq 32 ] || fail "refusing: generated password is short"
# Alnum needs no percent-encoding. The shape is the profile constant.
DATABASE_MIGRATION_URL="postgres://revik_migrator:${REVIK_MIGRATOR_PASSWORD}@postgres/revik?sslmode=disable"
DATABASE_URL="postgres://revik_app:${REVIK_APP_PASSWORD}@postgres/revik?sslmode=disable"

id=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n' | tr 'A-F' 'a-f')
hex32 "$id" || fail "refusing: could not generate an id"

# Drop an unfinished generation only after freshness is proven and current is
# absent. This does not touch secrets.env or any docker volume.
if [ -d "$secrets/generations" ] && [ ! -L "$secrets/generations" ]; then
	for d in "$secrets/generations"/*; do
		[ -e "$d" ] || continue
		base=${d##*/}
		hex32 "$base" || fail "refusing: unexpected file under secrets/generations"
		[ -L "$d" ] && fail "refusing: a generation directory is a symlink"
		rm -rf "$d"
	done
fi

umask 077
mkdir -p "$secrets/generations/$id"
chmod 700 "$secrets" "$secrets/generations" "$secrets/generations/$id"
chown root:root "$secrets" "$secrets/generations" "$secrets/generations/$id"

write_file() {
	dest=$1
	body=$2
	tmp="$dest.tmp.$$"
	printf '%s' "$body" > "$tmp" || fail "refusing: cannot write a generation file"
	chown root:root "$tmp"
	chmod 600 "$tmp"
	mv -f "$tmp" "$dest" || fail "refusing: cannot commit a generation file"
}

write_file "$secrets/generations/$id/postgres.env" "POSTGRES_PASSWORD=$POSTGRES_PASSWORD
REVIK_MIGRATOR_PASSWORD=$REVIK_MIGRATOR_PASSWORD
REVIK_APP_PASSWORD=$REVIK_APP_PASSWORD
REVIK_BACKUP_PASSWORD=$REVIK_BACKUP_PASSWORD
"
write_file "$secrets/generations/$id/migrate.env" "DATABASE_MIGRATION_URL=$DATABASE_MIGRATION_URL
"
write_file "$secrets/generations/$id/api.env" "DATABASE_URL=$DATABASE_URL
WS_SECRET=$WS_SECRET
CLERK_ISSUER=$CLERK_ISSUER
CLERK_JWKS_URL=$CLERK_JWKS_URL
CLERK_AUTHORIZED_PARTIES=$CLERK_AUTHORIZED_PARTIES
CLERK_SECRET_KEY=$CLERK_SECRET_KEY
"
write_file "$secrets/generations/$id/godot-api.env" "WS_SECRET=$WS_SECRET
"

provenance_tmp="$secrets/generations/$id/provenance.tmp.$$"
printf 'profile=fields-postgres-v2\nschema=11\ngeneration=%s\n' "$id" > "$provenance_tmp" || fail "refusing: cannot write provenance"
chown root:root "$provenance_tmp"
chmod 400 "$provenance_tmp"
mv -f "$provenance_tmp" "$secrets/generations/$id/provenance" || fail "refusing: cannot commit provenance"
provenance_tmp=""

ln -s "generations/$id" "$secrets/current.new.$$"
mv -T "$secrets/current.new.$$" "$secrets/current" || fail "refusing: cannot switch current"

state_tmp="$STATE_FILE.tmp.$$"
if grep -q '^SCOPED_GENERATION=' "$STATE_FILE"; then
	fail "refusing: a generation is already recorded"
fi
cp -a "$STATE_FILE" "$state_tmp"
{
	printf 'SCOPED_GENERATION=%s\n' "$id"
	printf 'SCOPED_COMPOSE_PROJECT=%s\n' "$project"
	printf 'SCOPED_PG_VOLUME=%s\n' "$pg_volume"
} >> "$state_tmp"
chown root:root "$state_tmp"
chmod 640 "$state_tmp"
mv -f "$state_tmp" "$STATE_FILE"

if [ -n "$clerk_file" ]; then
	rm -f "$clerk_file" || fail "refusing: clerk file could not be removed"
fi

# The id is not a secret. Values are not printed.
printf 'generation=%s\n' "$id"
