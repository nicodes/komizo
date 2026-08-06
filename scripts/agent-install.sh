set -eu
log() { printf '\n==> %s\n' "$*"; }

# Installs komizo-box: the report on a timer, and the account that will read it.
#
# The binary itself is NOT here. It arrives on its own connection, written to
# __STAGED__ before this runs, because it is several megabytes of ELF and
# nothing good comes of trying to carry that through a shell heredoc.

log "Installing the komizo agent"

[ -f __STAGED__ ] || { echo "error: __STAGED__ was never staged -- this is a komizo bug" >&2; exit 1; }

# State: closed, but TRAVERSABLE by the account that serves this box.
#
# apps/<app>.env names every app's deploy account and directory, and root is the
# only thing that reads them -- so this stays 0750 and apps/ and pending/ stay
# root:root. But __SERVED_DIR__ lives in here, and the agent has to reach it: a
# directory whose parent cannot be entered is one nothing can reach, whatever
# mode is set beneath it.
#
# The group is given away AFTER the account exists, further down.
mkdir -p __STATE_DIR__ __PENDING_DIR__
chown root:root __STATE_DIR__ __PENDING_DIR__
chmod 750 __STATE_DIR__ __PENDING_DIR__

# The report: the one directory anything unprivileged may enter. On tmpfs, so
# rootd recreates it after every reboot -- this is for the minutes before the
# service first ticks.
mkdir -p __RUN_DIR__ __API_SOCKET_DIR__
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
# The socket directory belongs to the account that opens the socket, and this
# is AFTER the account exists -- __RUN_DIR__ above is root's, so komizo_monitor
# cannot create anything in it, and a chown before adduser would have failed
# quietly and left a service that starts and cannot bind.
#
# Its own directory rather than the socket loose in __RUN_DIR__, because the
# box's proxy has to reach it and mounting __RUN_DIR__ would lend the one
# internet-facing container a writable path beside report.json.
# Owned by the account that binds the socket, GROUPED TO ROOT, and setgid.
#
# The box's proxy connects to that socket and runs with every capability
# dropped but CAP_NET_BIND_SERVICE, so its root is not exempt from permission
# checks: it cannot traverse a directory it does not own or connect to a socket
# it has no write bit on. Setgid makes the socket inherit this directory's
# group rather than the agent's, and root is a group the proxy is in.
#
# chmod AFTER chown, because chown clears the setgid bit.
chown komizo_monitor:root __API_SOCKET_DIR__
chmod 2750 __API_SOCKET_DIR__

chown root:komizo_monitor __ETC_DIR__
chmod 750 __ETC_DIR__

# The state directory, now that komizo_monitor exists to be given it.
#
# Group r-x: traverse and list. Listing shows four directory names and no
# contents, and apps/ and pending/ are root:root so they stay unreachable. This
# is the same boundary __ETC_DIR__ uses -- the group is what decides, not the
# mode alone.
chown root:komizo_monitor __STATE_DIR__
chmod 750 __STATE_DIR__

# What root writes for the read API to hand out.
#
# Owned by ROOT and grouped to komizo_monitor, which is the mirror of the socket
# directory above: there the account creates and root reads, here root creates
# and the account reads. Setgid so a file root appends in here inherits this
# directory's group instead of root's -- without it the readings are 0640
# root:root and the process serving them cannot open one.
#
# This is the fix for a real failure and not a precaution: the history lived in
# __STATE_DIR__, which is closed to everything, so GET /v1/history answered "no
# readings" on every box and said nothing about why.
#
# chmod AFTER chown, because chown clears the setgid bit.
mkdir -p __SERVED_DIR__
chown root:komizo_monitor __SERVED_DIR__
chmod 2750 __SERVED_DIR__

# A box that was installed before this directory existed keeps its readings.
# A rename does NOT take the setgid group -- setgid decides the group of files
# CREATED here -- so both are set by hand.
if [ -f __STATE_DIR__/history.jsonl ] && [ ! -e __HISTORY_PATH__ ]; then
	mv __STATE_DIR__/history.jsonl __HISTORY_PATH__
	chown root:komizo_monitor __HISTORY_PATH__
	chmod 640 __HISTORY_PATH__
	log "Moved this box's readings into __SERVED_DIR__"
fi

# Where a signed command arrives: the account CREATES here and root reads, which
# is the socket directory's shape in the opposite direction. Setgid so a command
# the account drops is born in root's group rather than its own.
#
# Under __RUN_DIR__, which is tmpfs -- a command carries an expiry in minutes and
# one that survived a reboot would be a machine acting, at boot, on something
# somebody asked for before it went down. rootd remakes it on every start; this
# is for the window before the first tick, and so that komizo-api never comes up
# to a directory that is not there.
#
# chmod AFTER chown, because chown clears the setgid bit.
mkdir -p __INBOX_DIR__
chown komizo_monitor:root __INBOX_DIR__
chmod 2750 __INBOX_DIR__

# And the other direction: where root leaves what happened, for the account to
# read back. Inside __SERVED_DIR__, which is already setgid to that account --
# but created here explicitly rather than left to be inferred from that, because
# inferring it is what failed for the history.
mkdir -p __RESULTS_DIR__
chown root:komizo_monitor __RESULTS_DIR__
chmod 2750 __RESULTS_DIR__

# Installed by rename, so a running rootd is replaced rather than written
# through. Overwriting a busy executable in place is ETXTBSY at best and a
# half-written binary at worst.
chmod 755 __STAGED__
mv -f __STAGED__ /usr/local/bin/komizo-box

# OpenRC, because the box is Alpine. supervise-daemon rather than start-stop-daemon
# so a crash is restarted rather than silently leaving the box unreported --
# which looks exactly like a box that is down.
#
# Each of the three service files below carries a `# shellcheck disable=SC2034`,
# and that needs an argument rather than a shrug -- komizo#59.
#
# An OpenRC service file is CONFIGURATION IN SHELL SYNTAX. openrc-run sources it
# and then acts on what it finds: `command` is what supervise-daemon execs,
# `name` is what `rc-service` answers to, `respawn_delay` is how long it waits
# before trying again. Every assignment is read by the framework and none is
# read by the file, so SC2034 fires on all twenty-two of them and every one is
# wrong. There is no rewrite that makes them "used" without inventing a use.
#
# The disable is at FILE scope rather than one per line, because the argument is
# the same argument nine times over and nine copies of it is not nine reasons.
# Say what that costs plainly: a directive before the first command applies to
# the whole file, so SC2034 is off inside depend() too, and it is off for an
# assignment written with a leading space as much as one at column 0.
#
# What makes it honest is that the exemption is CHECKED FROM OUTSIDE, and the
# check is scoped to match what the disable actually covers:
# TestAnOpenRCServiceOnlyAssignsNamesOpenRCReads requires EVERY assignment in
# one of these heredocs -- any indentation, inside a function or not -- to be a
# name openrc-run or supervise-daemon reads. That is the right rule for a file
# which is pure configuration, it catches `comand_args="serve"` wherever it is
# written, and it is checked against OpenRC's own shell rather than against
# whether some other line happens to mention the name, which is all SC2034 does.
#
# The corollary, and the reason this is not a hole: one of these files cannot
# have a local variable. If it ever needs one, that test fails, and the disable
# has to stop being file-scoped before it can be added.
cat > /etc/init.d/komizo-rootd <<'KOMIZO_RC_EOF'
#!/sbin/openrc-run
# Sourced by openrc-run, which reads these; nothing here uses them, so SC2034
# fires on every line. The set of names allowed is pinned by a test -- see
# agent-install.sh above the heredoc.
# shellcheck disable=SC2034
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
# Sourced by openrc-run, which reads these; nothing here uses them, so SC2034
# fires on every line. The set of names allowed is pinned by a test -- see
# agent-install.sh above the first of these heredocs.
# shellcheck disable=SC2034
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
# Sourced by openrc-run, which reads these; nothing here uses them, so SC2034
# fires on every line. The set of names allowed is pinned by a test -- see
# agent-install.sh above the first of these heredocs.
# shellcheck disable=SC2034
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

# The same proof for the readings, and it is here because asserting it is what
# failed last time. The read API serves this box's history as komizo_monitor,
# the history is written by root, and whether the account can open it depends on
# the group and mode of a directory rather than on anything visible in the code
# that reads it.
if ! su komizo_monitor -s /bin/sh -c "cat __HISTORY_PATH__ >/dev/null" 2>/dev/null; then
	printf 'error: komizo_monitor cannot read __HISTORY_PATH__.\n' >&2
	printf '       The read API serves this history as that account, so every\n' >&2
	printf '       request for it would answer with nothing and say no more;\n' >&2
	printf '       check the group and mode on __SERVED_DIR__.\n' >&2
	exit 1
fi

# And the write side of the same boundary, PROVEN rather than asserted.
#
# The account has to CREATE a file in the inbox -- that is the whole of how a
# command reaches root -- and whether it can depends on the owner and mode of a
# directory rather than on anything visible where the writing happens. Every
# previous failure in this shape was found on a real box instead of in review,
# which is why this is a check and not a comment.
if ! su komizo_monitor -s /bin/sh -c "touch __INBOX_DIR__/.probe && rm -f __INBOX_DIR__/.probe" 2>/dev/null; then
	printf 'error: komizo_monitor cannot write to __INBOX_DIR__.\n' >&2
	printf '       That is how a signed command reaches root; without it the app\n' >&2
	printf '       can read this box and never command it.\n' >&2
	exit 1
fi

# And the read side of the results, for the same reason.
#
# The app polls this for the outcome of everything it asks for. If the account
# cannot enter the directory, ReadResult fails silently and every command answers
# 404 forever -- which is indistinguishable from "not applied yet", so the app
# spins on every button with nothing anywhere saying why.
if ! su komizo_monitor -s /bin/sh -c "ls __RESULTS_DIR__ >/dev/null" 2>/dev/null; then
	printf 'error: komizo_monitor cannot read __RESULTS_DIR__.\n' >&2
	printf '       The app reads command outcomes from there; without it every\n' >&2
	printf '       command it sends would appear to hang forever.\n' >&2
	exit 1
fi

# AND A RESULT IN IT, which is a different question from the directory.
#
# Listing a directory needs r-x on the directory; opening a file in it needs the
# FILE's group and mode. The check above passed on a box where every result was
# root:root 0640 -- the account could see the file was there and got permission
# denied reading it, so GET /v1/commands/{id} answered "no result yet" forever
# for every command anyone sent. That was rootd clearing this directory's setgid
# bit on every start; it is fixed, and this is the check that would have caught
# it, so it runs here and not in review.
#
# AFTER `rootd --once` above, deliberately: it is what rootd leaves behind that
# a box lives with, not what this script set a hundred lines ago.
#
# Created by root the way a result is -- born in this directory, not moved in --
# because setgid decides the group of files CREATED here and a rename does not
# take it.
probe=__RESULTS_DIR__/.probe.json
: >"$probe"
chmod 640 "$probe"
if ! su komizo_monitor -s /bin/sh -c "cat $probe >/dev/null" 2>/dev/null; then
	rm -f "$probe"
	printf 'error: komizo_monitor can list __RESULTS_DIR__ and cannot read a file in it.\n' >&2
	printf '       Every command the app sends would be applied and then reported\n' >&2
	printf '       as never answered. Check that the directory is setgid and\n' >&2
	printf '       grouped to komizo_monitor: ls -ld __RESULTS_DIR__\n' >&2
	exit 1
fi
rm -f "$probe"

log "Reporting to __REPORT_PATH__ every __INTERVAL__"
