package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Named tasks remain operator-installed code. CI supplies data and authenticated
// source proof, never a program path or replacement executable.
func runWorkloadTask(args []string, owner bool) error {
	fs := flag.NewFlagSet("workload task", flag.ContinueOnError)
	policy := fs.String("policy", "", "protected workload authority")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 || *policy == "" {
		return errors.New("named tasks require the root executor and protected policy")
	}
	p, err := readWorkloadPolicy(*policy)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	input := bufio.NewReaderSize(os.Stdin, (128<<10)+2)
	var proof []byte
	if p.RequireDeliveryAuthorization && !owner {
		line, err := readTaskProof(ctx, input)
		if err != nil || len(line) > 128<<10 {
			return errors.New("named task requires a bounded authenticated release proof line")
		}
		proof = bytes.TrimSuffix(line, []byte("\n"))
		if err := verifyTaskRelease(ctx, p, proof); err != nil {
			return err
		}
	}
	unlock, err := box.LockDeployment(ctx, "", p.App)
	if err != nil {
		return err
	}
	defer unlock()
	// A queued task must still have a live grant and identity at execution time.
	if proof != nil {
		if err := verifyTaskRelease(ctx, p, proof); err != nil {
			return err
		}
	}
	if err := newHostActivation().startupCapacity(p); err != nil {
		return err
	}
	program := filepath.Join("/var/lib/komizo/tasks", p.App+".sh")
	// Check every ancestor and the exact executable; no symlink or writable
	// project file can become a privileged task through this command.
	for path := program; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !workloadRootOwner(info) || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("named task program is not protected")
		}
		if path == program {
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0700 || info.Size() <= 0 || info.Size() > 1<<20 {
				return errors.New("named task needs the operator's private regular executable")
			}
		} else if !info.IsDir() {
			return errors.New("named task ancestry is not a directory")
		}
		if path == "/" {
			break
		}
	}
	command := exec.CommandContext(ctx, program, fs.Args()...)
	if err := workloadTaskProcessGroup(command); err != nil {
		return err
	}
	command.WaitDelay = 2 * time.Second
	command.Dir = p.AppDir
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "LC_ALL=C"}
	command.Stdin = input
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		return errors.New("bounded named task failed; inspect its operation before retrying")
	}
	return nil
}

func verifyTaskRelease(ctx context.Context, p workload.Policy, wire []byte) error {
	const frame = "komizo-release/v1:"
	if !bytes.HasPrefix(wire, []byte(frame)) || len(wire) > 128<<10 {
		return errors.New("invalid named task proof")
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(string(wire), frame))
	if err != nil {
		return errors.New("invalid named task proof")
	}
	var envelope workload.ReleaseEnvelope
	if json.Unmarshal(body, &envelope) != nil {
		return errors.New("invalid named task proof")
	}
	manifestBody, err := base64.StdEncoding.DecodeString(envelope.Manifest)
	if err != nil {
		return errors.New("invalid named task manifest")
	}
	var manifest workload.ReleaseManifest
	if json.Unmarshal(manifestBody, &manifest) != nil {
		return errors.New("invalid named task manifest")
	}
	if err := checkDeliveryAuthorization(p, manifest.Revision, time.Now().UTC()); err != nil {
		return err
	}
	_, err = workload.VerifyRelease(ctx, body, p, manifest.Revision, time.Now().UTC(), workload.GitHubReleaseKey)
	return err
}

// A stalled deploy account cannot hold a root process indefinitely before
// presenting proof. The command owns stdin; returning ends that process.
func readTaskProof(ctx context.Context, reader *bufio.Reader) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	type result struct {
		body []byte
		err  error
	}
	ready := make(chan result, 1)
	go func() { body, err := reader.ReadSlice('\n'); ready <- result{bytes.Clone(body), err} }()
	select {
	case value := <-ready:
		return value.body, value.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
