//go:build !unix

package main

import (
	"errors"
	"os/exec"
)

func workloadTaskProcessGroup(command *exec.Cmd) error {
	return errors.New("bounded named tasks require Unix process groups")
}
