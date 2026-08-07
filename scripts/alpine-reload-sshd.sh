#!/bin/sh
# Pick up the sshd config every app in this update has already written.
#
# komizo#65. alpine.sh runs once per app and used to reload sshd at the end of
# each run, so an update of N apps reloaded N times -- N windows in which a CI
# deploy dialling this box can fail, growing with the fleet. Each run now
# validates its own edit -- with the binary that will load it, see below -- and
# defers the reload; this applies all
# of them at once.
#
# VALIDATED AGAIN HERE, cheaply, because this runs after the last app and is the
# only thing between a config on disk and the daemon reading it. If some later
# change breaks the file between the last app's check and this, refusing to
# reload leaves the previous rules in force -- which is the safe direction: an
# app whose block has not taken effect cannot deploy, where a broken sshd could
# lock everybody out including the operator.
set -eu

# komizo: sshd-validation BEGIN
# Is the config valid FOR THE BINARY THAT WILL LOAD IT?
#
# komizo#77. `sshd -t` resolves to /usr/sbin/sshd. Alpine's init script runs
# /usr/sbin/sshd.pam when the config says `UsePAM yes` -- a DIFFERENT binary,
# not a link, that disagrees about which options exist. `UsePAM yes` is Alpine's
# own default, and plain sshd calls it an unsupported option. So on every box
# with openssh-server-pam installed, this check was validating a program that
# was never going to read the file.
#
# Both directions are wrong and only one is safe: a good config rejected merely
# reverts an edit, but a config the running daemon will NOT accept passing this
# check is a reload into a broken sshd -- which is the thing the deferred reload
# exists to prevent.
#
# The init script already selects the binary and exposes `checkconfig`, so this
# ASKS IT instead of reimplementing update_command(). Copying that selection
# would be copying vendor logic that can drift out from under us, and it does
# not just test for the binary's existence -- it tests the config to decide.
#
# Where the action does not exist, `sshd -t` is what there is. That is no worse
# than before this function existed.
#
# NOT SIDE-EFFECT FREE, and worth knowing rather than discovering: Alpine's
# checkconfig runs `ssh-keygen -A` first, which creates any host key type the
# box is missing. On a machine komizo is reaching over SSH they already exist,
# so it is a no-op in practice -- but it is a write on a path named `validate`,
# and it happens during a removal too. Found in review of komizo#77.
komizo_sshd_config_ok() {
	if [ -f /etc/init.d/sshd ] && grep -qE '^extra_commands=.*checkconfig' /etc/init.d/sshd; then
		rc-service sshd checkconfig
	else
		sshd -t
	fi
}
# komizo: sshd-validation END

if ! komizo_sshd_config_ok; then
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
