set -eu
log() { printf '\n==> %s\n' "$*"; }

# Installs komizo-box: the report on a timer, and the account that will read it.
#
# The binary itself is NOT here. It arrives on its own connection, written to
# __STAGED__ before this runs, because it is several megabytes of ELF and
# nothing good comes of trying to carry that through a shell heredoc.

log "Installing the komizo agent"

[ -f __STAGED__ ] || { echo "error: __STAGED__ was never staged -- this is a komizo bug" >&2; exit 1; }

# State: root only. apps/<app>.env names every app's deploy account and
# directory, and root is the only thing that reads them.
mkdir -p __STATE_DIR__ __PENDING_DIR__
chown root:root __STATE_DIR__ __PENDING_DIR__
chmod 750 __STATE_DIR__ __PENDING_DIR__

# The report: the one directory anything unprivileged may enter. On tmpfs, so
# rootd recreates it after every reboot -- this is for the minutes before the
# service first ticks.
mkdir -p __RUN_DIR__
chown root:root __RUN_DIR__
chmod 755 __RUN_DIR__

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
	# -D no password, -H no home directory, -s /sbin/nologin no shell. The home
	# field is pointed at somewhere that does not exist rather than left naming
	# an /home path nothing created.
	adduser -D -H -h /nonexistent -s /sbin/nologin komizo_monitor 2>/dev/null ||
		adduser --system --no-create-home --home-dir /nonexistent \
			--shell /sbin/nologin komizo_monitor
	log "Created komizo_monitor (no shell, no privileges)"
fi

# The agent's credential, when there is one. Root writes it at enrolment; the
# agent reads it and cannot replace it.
#
# The GROUP is the boundary, and it is why this is under /etc rather than in the
# state directory: /etc is world-traversable, /etc/komizo is not, and the state
# directory is closed to everything -- a credential in there would be unreadable
# by the one process that needs it.
mkdir -p __ETC_DIR__
chown root:komizo_monitor __ETC_DIR__
chmod 750 __ETC_DIR__

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
description="komizo: writes __REPORT_PATH__"
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

# The agent, as the account with nothing.
#
# Installed but NOT enabled. A box that has not been enrolled has nothing to
# report to, and the agent says so once and exits -- so starting it here would
# put a service in the "crashed" column of every box that is only ever used
# through the CLI. `komizo enrol` enables it.
cat > /etc/init.d/komizo-agent <<'KOMIZO_AGENT_RC_EOF'
#!/sbin/openrc-run
name="komizo-agent"
description="komizo: posts __REPORT_PATH__ to the komizo service"
supervisor="supervise-daemon"
command="/usr/local/bin/komizo-box"
command_args="agent"
command_user="komizo_monitor:komizo_monitor"
respawn_delay=5
respawn_max=0

depend() {
	need net
	after komizo-rootd
}
KOMIZO_AGENT_RC_EOF
chmod 755 /etc/init.d/komizo-agent

# The read API, as the same account with nothing.
#
# Installed but NOT enabled, for the reason the agent is not: a box with no
# registry key can only refuse every request, so starting it would put a
# service in the "crashed" column of every box that never enrols. `komizo
# enrol` is what makes it startable, because that is when the key arrives.
#
# A socket under __RUN_DIR__, not a port -- see cmd/komizo-box/serve.go. The
# box's proxy reaches it through a bind mount, so nothing new listens on the
# network.
cat > /etc/init.d/komizo-api <<'KOMIZO_API_RC_EOF'
#!/sbin/openrc-run
name="komizo-api"
description="komizo: serves this box's own report and history"
supervisor="supervise-daemon"
command="/usr/local/bin/komizo-box"
command_args="serve"
command_user="komizo_monitor:komizo_monitor"
respawn_delay=5
respawn_max=0

depend() {
	need net
	after komizo-rootd
}
KOMIZO_API_RC_EOF
chmod 755 /etc/init.d/komizo-api

if command -v rc-update >/dev/null 2>&1; then
	rc-update add komizo-rootd default >/dev/null 2>&1 || true
	rc-service komizo-rootd restart >/dev/null 2>&1 || rc-service komizo-rootd start >/dev/null 2>&1 || true

	# Restarted only if it was already running -- which means this box is
	# enrolled and the agent should pick up the new binary. An unenrolled box
	# is left alone.
	if rc-service komizo-agent status >/dev/null 2>&1; then
		rc-service komizo-agent restart >/dev/null 2>&1 || true
	fi
	# Same rule for the read API: restarted onto the new binary if it was
	# already serving, and left alone on a box that has never enrolled.
	if rc-service komizo-api status >/dev/null 2>&1; then
		rc-service komizo-api restart >/dev/null 2>&1 || true
	fi
fi

# Two lines, written together: the komizo VERSION that set this box up, and the
# content STAMP of what it wrote. The version is what the interface shows beside
# the CLI's own -- "which komizo provisioned this box" -- and the stamp is the
# separate, exact answer to "would running the update change anything".
#
# BEFORE the first report, because the report reads this file. Written after, a
# freshly installed box reports itself as having no komizo on it until the timer
# ticks a minute later -- which is the one minute somebody is most likely to be
# looking, having just run the installer.
printf '%s\n%s\n' __VERSION__ __STAMP__ > __STATE_DIR__/version

# Written now rather than waiting for the timer, so the first report exists by
# the time anyone looks -- and so an agent that cannot run fails HERE, visibly,
# in the output of the thing that installed it.
/usr/local/bin/komizo-box rootd --once

if [ ! -s __REPORT_PATH__ ]; then
	printf 'error: the agent wrote no report -- komizo cannot read this box\n' >&2
	exit 1
fi

# The property the whole design rests on, PROVEN on this box rather than
# asserted: root writes the report, and an account with no privileges at all can
# read it. See design/appify.md §3.
#
# Checked by actually reading it as that account, because the mode on the file
# is not the answer -- a 644 file inside a directory nothing may traverse is
# world-readable in name only, which is exactly what this was until a real
# Alpine box said otherwise. Every directory from / down has to permit it, and
# only trying it can say whether they all do.
if ! su komizo_monitor -s /bin/sh -c "cat __REPORT_PATH__ >/dev/null" 2>/dev/null; then
	printf 'error: komizo_monitor cannot read __REPORT_PATH__.\n' >&2
	printf '       The reporting account has to read it without any privileges;\n' >&2
	printf '       check the mode on every directory leading to it.\n' >&2
	exit 1
fi

log "Reporting to __REPORT_PATH__ every __INTERVAL__"
