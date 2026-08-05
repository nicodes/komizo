package box

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Where a signed command lands, and where its result comes back.
//
// komizo-be design/app-only.md §4: the account that SERVES the box is not the
// account that ACTS. The write route runs as komizo_monitor -- no shell, no
// docker group, no doas -- and it does not apply anything. It drops a signed
// blob here, and rootd verifies and applies it. The serving process cannot
// forge one because it holds no key, which makes this a dropbox rather than a
// privilege.
//
// TWO DIRECTIONS, TWO DIRECTORIES, and each is owned by whoever writes into it:
//
//	InboxDir    monitor writes, root reads     a command arriving
//	ServedDir   root writes, monitor reads     the result going back
//
// NOT PendingDir. That has existed empty on every box since the beginning and
// it is 0750 root:root inside a StateDir that is also 0750 root:root, so the
// serving account cannot traverse to it, let alone create a file in it -- and
// both serving processes describe themselves as having "nothing under the state
// directory". Reusing it would have been the sixth time this shape bit: a
// process handed a path it can read where it needs to write. It was very nearly
// the design, because an empty directory named "pending" reads like an
// invitation.
const InboxDir = RunDir + "/inbox"

// InboxDirMode is 0750 and setgid, the mirror of APISocketDirMode.
//
// There the account creates a socket and root's group has to reach it; here the
// account creates a file and root has to read it. Setgid so a command the
// account drops is born in the directory's group rather than the account's --
// which is not what lets root read it (root reads anything) but is what stops
// anything ELSE that shares the account's group from doing so.
//
// No world bits. A command in flight names an app on this machine.
const InboxDirMode = os.ModeSetgid | 0o750

// On tmpfs, deliberately.
//
// A command is a claim about now: it carries an expiry measured in minutes and
// an id that only means anything until it is applied. One that survived a
// reboot would be a machine acting, at boot, on something somebody asked for
// before it went down -- which is the opposite of what they would want by then.
// The report makes the same argument in paths.go for the same reason.

// StateDirMode is 0750, and the GROUP is the whole of it.
//
// /var/lib/komizo is closed because apps/<app>.env names every app's deploy
// account and directory. But ServedDir lives inside it, and the account that
// serves this box has to reach that -- so the directory has to be TRAVERSABLE
// by that account while its contents stay closed.
//
// It was root:root, so the agent could not enter at all and every mode set on
// anything beneath it was decorative. That is the same confusion paths.go
// records about report.json: "a world-readable file inside a directory nothing
// may traverse is world-readable in name only". This is the other direction of
// it, and it survived review because nothing walked the chain -- the installer
// caught it on the first real box.
//
// Group r-x, which is traverse and list. Listing shows four directory names and
// no contents; apps/ and pending/ are 0750 root:root and stay unreachable. The
// same boundary EtcDir already uses, in its own words: "/etc is
// world-traversable; /etc/komizo is not. The GROUP is the boundary."
const StateDirMode = os.FileMode(0o750)

// PrepareStateDir makes the state directory reachable by the account that
// serves the box, without opening anything in it.
//
// Called before PrepareServedDir, because a directory whose parent cannot be
// entered is a directory nothing can reach.
func PrepareStateDir(path string) error {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	u, err := user.Lookup(AgentUser)
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil
	}
	// Owner ROOT: the agent may pass through and must not write here.
	if err := os.Chown(path, 0, gid); err != nil {
		return fmt.Errorf("could not group %s to %s: %w", path, AgentUser, err)
	}
	return os.Chmod(path, StateDirMode)
}

// PrepareInboxDir makes the directory the write route drops commands into.
//
// Owned by the AGENT account, because that is what creates files here, and
// grouped to root. Called by rootd, which runs as root: the agent cannot chgrp
// to a group it is not in, and root is not one of its groups.
//
// Called on every start as well as by the installer, because RunDir is tmpfs
// and this is simply gone after a reboot -- the same reason the report's
// directory is recreated there.
// The CALLER must have made RunDir first, and rootd does. That ordering is
// load-bearing rather than incidental: the chown and chmod below are
// unconditional, so a directory the agent had pre-created -- or a symlink it
// had left in its place -- would be handed root's blessing. RunDir is 0755
// root:root and made before this runs, so there is no window in which the agent
// could put anything at this path.
func PrepareInboxDir(path string) error {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	u, err := user.Lookup(AgentUser)
	if err != nil {
		// No such account: not a box komizo has set up. Left alone rather than
		// failed, so this works in a test and mid-provisioning.
		return nil
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil
	}
	// Group 0, explicitly, rather than looked up by name: it is the group root
	// is in, not a name that might mean something else on another distribution.
	if err := os.Chown(path, uid, 0); err != nil {
		return fmt.Errorf("could not give %s to %s: %w", path, AgentUser, err)
	}
	// After the chown, because chown clears the setgid bit. Third time this
	// ordering has mattered here, and it is tested each time, because getting it
	// wrong looks exactly like getting it right.
	if err := os.Chmod(path, InboxDirMode); err != nil {
		return fmt.Errorf("could not set the mode on %s: %w", path, err)
	}
	return nil
}
