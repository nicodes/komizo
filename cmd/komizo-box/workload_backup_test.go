package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/internal/workload"
)

func TestBackupClaimSurvivesProcessDeathAndRefusesReplay(t *testing.T) {
	if path := os.Getenv("KOMIZO_SYNTHETIC_BACKUP_CLAIM"); path != "" {
		if err := claimBackup(path, backupOperation{Version: 1, Phase: "claimed", Deadline: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		self, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if err := self.Kill(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("process kill returned")
	}
	path := filepath.Join(t.TempDir(), "123-1.json")
	child := exec.Command(os.Args[0], "-test.run=^TestBackupClaimSurvivesProcessDeathAndRefusesReplay$")
	child.Env = append(os.Environ(), "KOMIZO_SYNTHETIC_BACKUP_CLAIM="+path)
	if err := child.Run(); err == nil {
		t.Fatal("synthetic claim worker unexpectedly survived process death")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var operation backupOperation
	if err := json.Unmarshal(body, &operation); err != nil || operation.Phase != "claimed" {
		t.Fatalf("durable ambiguous claim missing: %v", err)
	}
	if err := claimBackup(path, backupOperation{Version: 1, Phase: "complete"}); err == nil {
		t.Fatal("interrupted backup replayed")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(body) {
		t.Fatal("refused replay changed the durable claim")
	}
}

func TestBackupRejectsDesiredRevisionBeforeServingAcceptance(t *testing.T) {
	version := strings.Repeat("a", 40)
	env := []byte("APP_VERSION=" + version + "\n")
	operation := workload.Operation{Version: 1, App: "demo", Candidate: version, Phase: "ready"}
	if got, err := backupServingRevision("demo", env, operation); err != nil || got != version {
		t.Fatalf("accepted serving revision refused: %v", err)
	}
	for _, phase := range []string{"staging", "configured", "activating", "activated", "readiness_failed", "prepared_stopped", "reconciled", "failed"} {
		operation.Phase = phase
		if _, err := backupServingRevision("demo", env, operation); err == nil {
			t.Fatalf("%s borrowed ready backup authority", phase)
		}
	}
	operation.Phase = "ready"
	operation.Candidate = strings.Repeat("b", 40)
	if _, err := backupServingRevision("demo", env, operation); err == nil {
		t.Fatal("desired source differs from serving source but backup was authorized")
	}
}
