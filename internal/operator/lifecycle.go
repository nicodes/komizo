package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

// Lifecycle applies only the authenticated embedded bundle. Caller input
// supplies the verb and reviewed plan identity, never executable paths or code.
func Lifecycle(parent context.Context, verb, expected string, output, progress io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("operator installation requires the root operator")
	}
	if verb != "plan" && verb != "apply" && verb != "status" && verb != "recover" {
		return errors.New("unsupported operator lifecycle verb")
	}
	script, err := assets.ReadFile("assets/install_operator.py")
	if err != nil {
		return err
	}
	bundle := map[string]string{}
	for _, name := range names {
		body, err := assets.ReadFile("assets/" + name)
		if err != nil {
			return err
		}
		bundle[name] = string(body)
	}
	wire, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 150*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", string(script), verb, "--expected-plan", expected)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	command.Dir = "/"
	command.Stdin = bytes.NewReader(wire)
	command.Stdout = output
	command.Stderr = progress
	command.WaitDelay = 2 * time.Second
	return command.Run()
}
