//go:build unix

package app

import (
	"os/exec"
	"syscall"
)

// detach puts the clipboard helper in its own process group.
//
// This is load-bearing, not tidiness. wl-copy (and xclip, and xsel) do not
// hand the data to a daemon and exit -- they fork a child that OWNS the
// selection and serves it to whoever pastes. That child inherits our process
// group, so anything that signals the group takes the clipboard with it: the
// data is gone the moment komizo is interrupted, and pasting gives nothing.
//
// Detaching means the offer outlives the process that made it, which is the
// only behaviour that makes sense for "copy this so I can paste it into a
// browser".
func detach(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
