//go:build !unix

package main

import "os/exec"

// No process groups to escape from.
func detach(c *exec.Cmd) {}
