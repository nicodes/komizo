package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

func TestRolloutProvisionBrokerOnlyPreservesMeasuredApplicationState(t *testing.T) {
	record := appRecord{name: "cazper", user: "komizo-cazper", config: "ghcr.io/nicodes/cazper-config", dir: "/srv/cazper"}
	const unchanged = "app-dir\t0:0:750\ncompose.yml\t0:0:600\nhash\ncontainer\tid\trunning\timage\n"
	var runs []string
	err := performRolloutProvision(record, nil, func() (string, error) { return unchanged, nil },
		func(script string, env map[string]string) error {
			runs = append(runs, script)
			if env["APP_NAME"] != "cazper" {
				t.Fatalf("wrong application environment: %#v", env)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0] != scripts.AlpineScript {
		t.Fatalf("broker-only preparation ran unexpected scripts: %d", len(runs))
	}
}

func TestRolloutProvisionRefusesOwnershipDriftBeforeRefreshing(t *testing.T) {
	record := appRecord{name: "cazper", user: "komizo-cazper", config: "ghcr.io/nicodes/cazper-config", dir: "/srv/cazper"}
	runs := 0
	err := performRolloutProvision(record, nil, func() (string, error) { return "app-dir\t1000:1000:750\n", nil },
		func(string, map[string]string) error { runs++; return nil })
	if err == nil || !strings.Contains(err.Error(), "refusing to normalize ownership") || runs != 0 {
		t.Fatalf("unsafe ownership reached broker refresh: runs=%d err=%v", runs, err)
	}
}

func TestRolloutProvisionDetectsAnyLiveStateChangeBeforeInstallingProfile(t *testing.T) {
	record := appRecord{name: "cazper", user: "komizo-cazper", config: "ghcr.io/nicodes/cazper-config", dir: "/srv/cazper"}
	snapshots := []string{"app-dir\t0:0:750\ncontainer\tid\trunning\told\n", "app-dir\t0:0:750\ncontainer\tid\trunning\tnew\n"}
	runs := 0
	err := performRolloutProvision(record, []byte(`{"app":"cazper"}`), func() (string, error) {
		if len(snapshots) == 0 {
			return "", errors.New("too many snapshots")
		}
		value := snapshots[0]
		snapshots = snapshots[1:]
		return value, nil
	}, func(string, map[string]string) error { runs++; return nil })
	if err == nil || !strings.Contains(err.Error(), "remained unchanged") || runs != 1 {
		t.Fatalf("changed live state did not block profile install: runs=%d err=%v", runs, err)
	}
}

func TestRolloutProvisionInstallsProfileOnlyAfterStableBrokerRefresh(t *testing.T) {
	record := appRecord{name: "cazper", user: "komizo-cazper", config: "ghcr.io/nicodes/cazper-config", dir: "/srv/cazper"}
	const unchanged = "app-dir\t0:0:750\n"
	profile := []byte(`{"app":"cazper"}`)
	var runs []string
	err := performRolloutProvision(record, profile, func() (string, error) { return unchanged, nil },
		func(script string, env map[string]string) error {
			runs = append(runs, script)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0] != scripts.AlpineScript || !strings.Contains(runs[1], "rollout profile --provision") || strings.Contains(runs[1], string(profile)) {
		t.Fatalf("profile provisioning order/transport is unsafe: runs=%d", len(runs))
	}
}
