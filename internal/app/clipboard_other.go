//go:build !unix

package app

import "os/exec"

// No process groups to escape from.
func detach(c *exec.Cmd) {}
