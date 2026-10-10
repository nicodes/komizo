package workload

import (
	"crypto/rand"
	"encoding/hex"
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
	operation := Operation{Version: 1, App: app, Candidate: candidate, Previous: previous, Phase: phase, At: now}
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
		if phase == "admitted" && (old.Phase == "activating" || old.Phase == "activation_failed") {
			return errors.New("interrupted activation needs reconciliation before another version")
		}
		if phase != "admitted" {
			if previous != old.Previous || !legalOperationTransition(old.Phase, phase) {
				return errors.New("invalid deployment operation transition")
			}
			if !old.Deadline.IsZero() && now.After(old.Deadline) && phase != "failed" && phase != "activation_failed" && phase != "readiness_failed" && phase != "reconciled" {
				return errors.New("deployment operation deadline expired")
			}
			operation.ID, operation.StartedAt, operation.Deadline = old.ID, old.StartedAt, old.Deadline
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if phase != "admitted" {
		return errors.New("deployment operation must start with admission")
	}
	if phase == "admitted" {
		var identity [16]byte
		if _, err := rand.Read(identity[:]); err != nil {
			return err
		}
		operation.ID, operation.StartedAt, operation.Deadline = hex.EncodeToString(identity[:]), now, now.Add(25*time.Minute)
	}
	operation.Phase = phase
	return WritePrivateJSON(path, operation)
}

func legalOperationTransition(from, to string) bool {
	if from == to {
		return true
	} // An identical phase acknowledgement is idempotent.
	if to == "reconciled" {
		return from == "activating" || from == "activation_failed" || from == "readiness_failed" || from == "failed"
	}
	if to == "failed" {
		return from != "ready" && from != "prepared_stopped" && from != "reconciled"
	}
	if to == "activation_failed" {
		return from == "activating"
	}
	switch from {
	case "admitted":
		return to == "configured"
	case "configured":
		return to == "activating" || to == "prepared_stopped"
	case "activating":
		return to == "activated" || to == "prepared_stopped"
	case "activated":
		return to == "ready" || to == "readiness_failed" || to == "prepared_stopped"
	case "readiness_failed":
		return to == "ready"
	}
	return false
}
