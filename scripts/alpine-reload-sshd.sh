#!/bin/sh
# Pick up the sshd config every app in this update has already written.
#
# komizo#65. alpine.sh runs once per app and used to reload sshd at the end of
# each run, so an update of N apps reloaded N times -- N windows in which a CI
# deploy dialling this box can fail, growing with the fleet. Each run now
# validates its own edit with `sshd -t` and defers the reload; this applies all
# of them at once.
#
# VALIDATED AGAIN HERE, cheaply, because this runs after the last app and is the
# only thing between a config on disk and the daemon reading it. If some later
# change breaks the file between the last app's check and this, refusing to
# reload leaves the previous rules in force -- which is the safe direction: an
# app whose block has not taken effect cannot deploy, where a broken sshd could
# lock everybody out including the operator.
set -eu

if ! sshd -t; then
	echo "error: /etc/ssh/sshd_config does not validate, so it was NOT reloaded." >&2
	echo "       The rules in force are the ones from before this update." >&2
	exit 1
fi

# `reload` re-execs without dropping the listener, so the connection this is
# running over survives and no window opens. `restart` is the fallback for a
# box whose init script does not implement reload; it stops the listener
# briefly, which is why it is second.
rc-service sshd reload || rc-service sshd restart
echo "komizo: sshd reloaded once for this update"
