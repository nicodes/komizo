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
# AND IS IT THE FILE THE DAEMON ACTUALLY READS?
#
# nicodes/komizo-be#164, and the other half of the problem above. Validating the
# right file with the right binary is only correct if komizo is EDITING the file
# the daemon reads -- and Alpine's init script takes `cfgfile` from
# /etc/conf.d/sshd, so an operator can point their daemon anywhere.
#
# komizo wrote to /etc/ssh/sshd_config unconditionally. On a box with cfgfile
# set, every consequence is silent: the deploy account's Match block is not in
# force, so AllowTcpForwarding no and the rest never take effect and a leaked
# deploy key can tunnel TCP through the box; AuthorizedKeysFile still points
# wherever the real config says, so the root-owned key list komizo relies on is
# not the one consulted and the account can authorise a second key for itself;
# and a key rotation rewrites a file nothing loads, so the old key keeps
# working. komizo reports success for all three.
#
# READ THE SAME WAY THE INIT SCRIPT READS IT -- last assignment wins, quotes
# stripped -- rather than grepping for the default. A file that sets it twice
# is a file whose daemon uses the second one.
komizo_sshd_conf() {
	_cf=""
	if [ -r /etc/conf.d/sshd ]; then
		_cf=$(sed -n "s/^[[:space:]]*cfgfile=//p" /etc/conf.d/sshd |
			tail -n 1 | tr -d "\"'" | tr -d "\r")
	fi
	[ -n "$_cf" ] || _cf=/etc/ssh/sshd_config
	printf '%s\n' "$_cf"
}

# REFUSED RATHER THAN FOLLOWED, and that is the deliberate half.
#
# A box with a relocated sshd config is one somebody configured on purpose.
# Silently rewriting their real config is worse than stopping: komizo would be
# editing a file it was never asked to own, on the strength of a variable it
# just discovered. Saying which file this box uses is the whole remedy -- move
# it back, or manage that box's ssh rules yourself.
komizo_sshd_conf_is_ours() {
	_conf=$(komizo_sshd_conf)
	[ "$_conf" = /etc/ssh/sshd_config ] && return 0
	echo "error: this box points sshd at $_conf (cfgfile in /etc/conf.d/sshd)." >&2
	echo "       komizo only manages /etc/ssh/sshd_config, so the deploy account's" >&2
	echo "       restrictions would be written to a file the daemon never reads." >&2
	return 1
}
# komizo: sshd-validation END

# WHICH FILE FIRST, then whether it is valid. Reloading is only meaningful if
# the edits this update deferred went into the file the daemon reads -- and if
# they did not, alpine.sh refused before making any, so there is nothing here to
# pick up. Refusing keeps the three scripts saying one thing about one file.
if ! komizo_sshd_conf_is_ours; then
	echo "       Nothing was reloaded." >&2
	exit 1
fi

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
