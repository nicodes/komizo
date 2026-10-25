package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/nicodes/komizo/internal/devenv"
	"github.com/nicodes/komizo/internal/project"
)

// Dependency reconciliation executes only the authenticated bundled client in
// isolated Python. Caller project scripts, tool hooks and PR code are never
// loaded. The client verifies bot signatures, current head/base and CI evidence
// before any explicitly requested mutation.
func RunDependencies(args []string) (err error) {
	validation := localInput(&err)
	defer validation.finish()
	if len(args) == 0 || args[0] != "inspect" && args[0] != "apply" {
		return errors.New("dependencies requires inspect or apply")
	}
	operation := args[0]
	fs := flag.NewFlagSet("dependencies "+operation, flag.ContinueOnError)
	fs.SetOutput(commandFlags())
	pr := fs.Int("pr", 0, "optional exact pull request number")
	output := fs.String("output", "", "optional report destination")
	fs.Usage = func() {
		usageJourney("dependencies "+operation, "komizo dependencies "+operation+" [--pr NUMBER] [--output FILE]", "Inspect verified dependency updates. Apply requires current successful CI and an unchanged signed bot head; it never executes pull-request code.")
		fs.PrintDefaults()
	}
	if err = fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *pr < 0 {
		return errors.New("dependencies accepts a positive PR number and report flags")
	}
	if hasFlag(args[1:], "pr") && *pr == 0 {
		return errors.New("an explicit PR number must be positive")
	}
	directory, err := os.MkdirTemp("", "komizo-dependencies-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	reportPath := filepath.Join(directory, "report.json")
	if *output != "" {
		*output, err = filepath.Abs(*output)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(*output); !errors.Is(err, os.ErrNotExist) {
			return errors.New("report destination must be a new file")
		}
	}
	runtime, err := project.Runtime()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	commandArgs := []string{"-I", filepath.Join(runtime, "helpers", "dependency-reconcile.py"), "--output", reportPath}
	if *pr > 0 {
		commandArgs = append(commandArgs, "--pr", strconv.Itoa(*pr))
	}
	if operation == "apply" {
		commandArgs = append(commandArgs, "--apply")
	}
	validation.complete = true
	ctx, cancel := context.WithTimeout(commandContext(), 10*time.Minute)
	defer cancel()
	command := exec.Command("/usr/bin/python3", commandArgs...)
	command.Env = append(os.Environ(), "KOMIZO_EXECUTABLE="+executable)
	command.Stdout, command.Stderr = commandProgress(), commandProgress()
	runErr := devenv.RunCommand(ctx, command, 2*time.Second)
	if ctx.Err() != nil {
		runErr = ctx.Err()
	}
	if body, readErr := readJourneyFile(reportPath, 1<<20, false); readErr == nil {
		var result struct {
			Version      int               `json:"version"`
			Repository   string            `json:"repository"`
			Base         string            `json:"base"`
			ObservedAt   string            `json:"observed_at"`
			PullRequests []json.RawMessage `json:"pull_requests"`
		}
		if json.Unmarshal(body, &result) != nil || result.Version != 1 || result.Repository != os.Getenv("GITHUB_REPOSITORY") || !exactHex(result.Base, 40) {
			return errors.New("invalid dependency report")
		}

		if err := emitResult(result); err != nil {
			return err
		}
		if *output != "" {
			file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, writeErr := file.Write(body)
			closeErr := file.Close()
			if writeErr != nil {
				return writeErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	} else if runErr == nil {
		return errors.New("dependency client produced no bounded report")
	}
	return runErr
}
