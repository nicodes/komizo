package workload

import (
	"encoding/json"
	"errors"
	"github.com/nicodes/komizo/box"
	"os"
	"path/filepath"
	"time"
)

type Operation = box.Deployment

func WritePrivateJSON(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".komizo-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(append(body, '\n')); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func RecordOperation(path, app, candidate, previous, phase string, now time.Time) error {
	if !identifier.MatchString(app) || !revision.MatchString(candidate) || (previous != "" && !revision.MatchString(previous)) {
		return errors.New("invalid deployment operation identity")
	}
	switch phase {
	case "admitted", "configured", "activating", "activated", "ready", "readiness_failed", "prepared_stopped", "failed", "activation_failed", "reconciled":
	default:
		return errors.New("invalid deployment operation phase")
	}
	if body, err := os.ReadFile(path); err == nil {
		var old Operation
		if strictJSON(body, &old) != nil || old.Version != 1 || old.App != app {
			return errors.New("invalid existing deployment operation")
		}
		if phase == "failed" && old.Phase == "activating" {
			phase = "activation_failed"
		}
		if phase != "admitted" && old.Candidate != candidate {
			return errors.New("deployment operation candidate changed")
		}
		if phase == "admitted" && (old.Phase == "activating" || old.Phase == "activation_failed") && old.Candidate != candidate {
			return errors.New("interrupted activation needs reconciliation before another version")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return WritePrivateJSON(path, Operation{Version: 1, App: app, Candidate: candidate, Previous: previous, Phase: phase, At: now})
}
