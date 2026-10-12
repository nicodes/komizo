package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

type backupOperation struct {
	Version  int                       `json:"version"`
	Phase    string                    `json:"phase"`
	Accepted workload.BackupAcceptance `json:"accepted"`
	Deadline time.Time                 `json:"deadline"`
}

func backupProtectedPath(path string, directory bool) error {
	for q := path; ; q = filepath.Dir(q) {
		i, err := os.Lstat(q)
		if err != nil || !workloadRootOwner(i) || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0022 != 0 ||
			((q != path || directory) && !i.IsDir()) || (q == path && !directory && !i.Mode().IsRegular()) {
			return errors.New("backup ancestry and files must be protected root authority")
		}
		if q == "/" {
			return nil
		}
	}
}

func backupDirectory(app string) (string, error) {
	dir := "/var/lib/komizo"
	if err := backupProtectedPath(dir, true); err != nil {
		return "", err
	}
	for _, name := range []string{"backup-operations", app} {
		dir = filepath.Join(dir, name)
		if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
		if err := backupProtectedPath(dir, true); err != nil {
			return "", err
		}
		if i, err := os.Lstat(dir); err != nil || i.Mode().Perm() != 0700 {
			return "", errors.New("backup operation store must be private")
		}
	}
	return dir, nil
}

// The exclusive claim is durable before the exporter starts. A crash retains
// claimed rather than guessing whether an export completed or replaying it.
func claimBackup(path string, operation backupOperation) error {
	body, err := json.Marshal(operation)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("backup run already claimed; inspect before starting a new run")
	}
	_, writeErr := f.Write(append(body, '\n'))
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func runRoutineBackup(args []string) error {
	fs := flag.NewFlagSet("workload "+args[0], flag.ContinueOnError)
	policy := fs.String("policy", "", "protected workload authority")
	run := fs.String("run", "", "claimed workflow run to inspect")
	attempt := fs.String("attempt", "", "claimed attempt to inspect")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if os.Geteuid() != 0 || *policy == "" || fs.NArg() != 0 {
		return errors.New("routine backup requires root, a policy and no program arguments")
	}
	p, err := readWorkloadPolicy(*policy)
	if err != nil {
		return err
	}
	if args[0] == "backup-inspect" {
		return inspectBackup(p.App, *run, *attempt)
	}
	if *run != "" || *attempt != "" || p.RoutineBackup == nil {
		return errors.New("routine backup requires a protected capability and audience-bound proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.RoutineBackup.TimeoutSeconds)*time.Second)
	defer cancel()
	line, err := readTaskProof(ctx, bufio.NewReaderSize(os.Stdin, (128<<10)+2))
	if err != nil || !bytes.HasPrefix(line, []byte("komizo-operation/v1:")) {
		return errors.New("backup requires a bounded authenticated operation proof line")
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(string(line), "komizo-operation/v1:"), "\n"))
	if err != nil {
		return errors.New("invalid backup operation proof encoding")
	}
	verify := func() (workload.BackupAcceptance, error) {
		if err := activationIdle(activationDirectory); err != nil {
			return workload.BackupAcceptance{}, err
		}
		if err := backupProtectedPath(filepath.Join(p.AppDir, ".env"), false); err != nil {
			return workload.BackupAcceptance{}, err
		}
		env, err := protectedActivationBytes(filepath.Join(p.AppDir, ".env"))
		if err != nil {
			return workload.BackupAcceptance{}, err
		}
		operationPath := filepath.Join(releaseDirectory, p.App, "operation.json")
		if err := backupProtectedPath(operationPath, false); err != nil {
			return workload.BackupAcceptance{}, err
		}
		var operation workload.Operation
		if err := readPrivateRelease(operationPath, &operation); err != nil {
			return workload.BackupAcceptance{}, err
		}
		serving, err := backupServingRevision(p.App, env, operation)
		if err != nil {
			return workload.BackupAcceptance{}, err
		}
		return workload.VerifyBackup(ctx, body, p, serving, time.Now().UTC(), workload.GitHubReleaseKey)
	}
	if _, err := verify(); err != nil {
		return err
	}
	unlock, err := box.LockDeployment(ctx, "", p.App)
	if err != nil {
		return err
	}
	defer unlock()
	// A queued request must still match current protected policy and source.
	current, err := readWorkloadPolicy(*policy)
	if err != nil {
		return err
	}
	old, _ := json.Marshal(p)
	next, _ := json.Marshal(current)
	if !bytes.Equal(old, next) {
		return errors.New("backup authority changed while waiting")
	}
	if err := newHostActivation().startupCapacity(p); err != nil {
		return err
	}
	accepted, err := verify()
	if err != nil {
		return err
	}
	program := "/usr/local/bin/export-" + p.App + "-backup"
	if err := backupProtectedPath(program, false); err != nil {
		return err
	}
	info, err := os.Lstat(program)
	if err != nil || (info.Mode().Perm() != 0700 && info.Mode().Perm() != 0755) || info.Size() <= 0 || info.Size() > 1<<20 {
		return errors.New("backup exporter must be a bounded protected executable")
	}
	programBytes, err := protectedActivationBytes(program)
	sum := sha256.Sum256(programBytes)
	if err != nil || hex.EncodeToString(sum[:]) != p.RoutineBackup.ProgramSHA256 {
		return errors.New("backup exporter differs from protected authority")
	}
	dir, err := backupDirectory(p.App)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, accepted.Manifest.RunID+"-"+accepted.Manifest.Attempt+".json")
	deadline, _ := ctx.Deadline()
	op := backupOperation{Version: 1, Phase: "claimed", Accepted: accepted, Deadline: deadline}
	if err := claimBackup(path, op); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, program)
	if err := workloadTaskProcessGroup(command); err != nil {
		return err
	}
	command.Dir = p.AppDir
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "LC_ALL=C"}
	command.WaitDelay = 2 * time.Second
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	err = command.Run()
	op.Phase = "complete"
	if err != nil {
		op.Phase = "ambiguous"
	}
	if writeErr := workload.WritePrivateJSON(path, op); writeErr != nil {
		return errors.New("backup outcome could not be recorded; inspect the durable claim")
	}
	if err != nil {
		return errors.New("bounded backup exporter failed; inspect its operation without replaying")
	}
	return nil
}

// Staging updates APP_VERSION before activation/readiness. That desired
// revision must never be mistaken for an accepted serving revision.
func backupServingRevision(app string, env []byte, operation workload.Operation) (string, error) {
	version, err := deploymentVersion(env)
	if err != nil {
		return "", err
	}
	if operation.Version != 1 || operation.App != app || operation.Phase != "ready" || operation.Candidate != version {
		return "", errors.New("backup requires the accepted ready serving operation")
	}
	return version, nil
}

func inspectBackup(app, run, attempt string) error {
	for _, id := range []string{run, attempt} {
		if len(id) < 1 || len(id) > 20 || id[0] == '0' || strings.Trim(id, "0123456789") != "" {
			return errors.New("backup inspection requires positive run and attempt identifiers")
		}
	}
	path := filepath.Join("/var/lib/komizo/backup-operations", app, run+"-"+attempt+".json")
	if err := backupProtectedPath(path, false); err != nil {
		return err
	}
	var op backupOperation
	if err := readPrivateRelease(path, &op); err != nil {
		return err
	}
	body, err := json.Marshal(op)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}
