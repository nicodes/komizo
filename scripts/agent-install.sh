set -eu
log() { printf '\n==> %s\n' "$*"; }

# Installs komizo-box: the report on a timer, and the account that will read it.
#
# The binary itself is NOT here. It arrives on its own connection, written to
# __STAGED__ before this runs, because it is several megabytes of ELF and
# nothing good comes of trying to carry that through a shell heredoc.
#
# Replaces the sampler and its per-minute crontab entry. Everything the sampler
# measured, komizo-box measures; what changes is that a Go binary does it in one
# process instead of a shell script spawning several hundred.

log "Installing the komizo agent"

[ -f __STAGED__ ] || { echo "error: __STAGED__ was never staged -- this is a komizo bug" >&2; exit 1; }

mkdir -p /var/lib/komizo /var/lib/komizo/pending
chmod 750 /var/lib/komizo /var/lib/komizo/pending

# The reporting account.
#
# No SSH, no doas, no docker group, no privileges at all -- see
# design/appify.md §3. It does not exist to run anything; it exists so that the
# process which will one day POST the report is not root, and the file it reads
# is the entire boundary between them.
#
# The underscore is load-bearing. Apps get komizo-<name>, komizo's own accounts
# get komizo_<name>, so character seven differs and the two namespaces cannot
# collide for any app name whatsoever -- including an app called "monitor".
if ! id komizo_monitor >/dev/null 2>&1; then
	# -D no password, -H no home to log into, -s /sbin/nologin no shell.
	adduser -D -H -s /sbin/nologin komizo_monitor 2>/dev/null ||
		adduser --system --no-create-home --shell /sbin/nologin komizo_monitor
	log "Created komizo_monitor (no shell, no privileges)"
fi

# Installed by rename, so a running rootd is replaced rather than written
# through. Overwriting a busy executable in place is ETXTBSY at best and a
# half-written binary at worst.
chmod 755 __STAGED__
mv -f __STAGED__ /usr/local/bin/komizo-box

# OpenRC, because the box is Alpine. supervise-daemon rather than start-stop-daemon
# so a crash is restarted rather than silently leaving the box unreported --
# which looks exactly like a box that is down.
cat > /etc/init.d/komizo-rootd <<'KOMIZO_RC_EOF'
#!/sbin/openrc-run
name="komizo-rootd"
description="komizo: writes /var/lib/komizo/report.json"
supervisor="supervise-daemon"
command="/usr/local/bin/komizo-box"
command_args="rootd --interval __INTERVAL__"
respawn_delay=5
respawn_max=0

depend() {
	need net
	after docker
}
KOMIZO_RC_EOF
chmod 755 /etc/init.d/komizo-rootd

if command -v rc-update >/dev/null 2>&1; then
	rc-update add komizo-rootd default >/dev/null 2>&1 || true
	rc-service komizo-rootd restart >/dev/null 2>&1 || rc-service komizo-rootd start >/dev/null 2>&1 || true
fi

# The sampler this replaces. Its crontab line is removed so the box is not
# running both -- they measure the same things and would interleave two answers
# to every question.
#
# The script and its log are LEFT IN PLACE. The log is the only record of what
# happened before the update, and deleting somebody's history as a side effect
# of an upgrade is not a thing to do casually even when nothing is expected to
# read it again.
if [ -f /etc/crontabs/root ]; then
	grep -v 'komizo-sample' /etc/crontabs/root > /etc/crontabs/root.tmp 2>/dev/null || true
	mv /etc/crontabs/root.tmp /etc/crontabs/root
fi

# Written now rather than waiting for the timer, so the first report exists by
# the time anyone looks -- and so an agent that cannot run fails HERE, visibly,
# in the output of the thing that installed it.
/usr/local/bin/komizo-box rootd --once

# Two lines, written together: the komizo VERSION that set this box up, and the
# content STAMP of what it wrote. The version is what the interface shows beside
# the CLI's own -- "which komizo provisioned this box" -- and the stamp is the
# separate, exact answer to "would running the update change anything".
printf '%s\n%s\n' __VERSION__ __STAMP__ > /var/lib/komizo/version

if [ -s /var/lib/komizo/report.json ]; then
	log "Reporting to /var/lib/komizo/report.json every __INTERVAL__"
else
	printf 'warning: the agent wrote no report -- komizo will not be able to read this box\n' >&2
	exit 1
fi
