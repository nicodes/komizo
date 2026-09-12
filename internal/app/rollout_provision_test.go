package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

const safeProvisionSnapshot = "app-dir\t0:0:750\ncompose.yml\t0:0:600\nhash\n.env\t0:0:600\nhash\nsecrets.env\t0:0:600\nhash\n"

func TestRolloutProvisionBrokerOnlyPreservesMeasuredApplicationState(t *testing.T) {
	record := appRecord{name: "cazper", user: "komizo-cazper", config: "ghcr.io/nicodes/cazper-config", dir: "/srv/cazper"}
	const unchanged = safeProvisionSnapshot + "container\tid\trunning\timage\n"
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
	for _, unsafe := range []string{
		"app-dir\t1000:1000:750\ncompose.yml\t0:0:600\n.env\t0:0:600\nsecrets.env\t0:0:600\n",
		"app-dir\t0:0:750\ncompose.yml\t1000:1000:600\n.env\t0:0:600\nsecrets.env\t0:0:600\n",
		"app-dir\t0:0:750\ncompose.yml\t0:0:600\n.env\t0:0:644\nsecrets.env\t0:0:600\n",
		"app-dir\t0:0:750\ncompose.yml\t0:0:600\n.env\t0:0:600\nsecrets.env\t1000:1000:600\n",
	} {
		err := performRolloutProvision(record, nil, func() (string, error) { return unsafe, nil },
			func(string, map[string]string) error { runs++; return nil })
		if err == nil || !strings.Contains(err.Error(), "refusing to normalize ownership") || runs != 0 {
			t.Fatalf("unsafe ownership reached broker refresh: runs=%d err=%v", runs, err)
		}
	}
}

func TestRolloutProvisionDetectsAnyLiveStateChangeBeforeInstallingProfile(t *testing.T) {
	record := appRecord{name: "cazper", user: "komizo-cazper", config: "ghcr.io/nicodes/cazper-config", dir: "/srv/cazper"}
	snapshots := []string{safeProvisionSnapshot + "container\tid\trunning\told\n", safeProvisionSnapshot + "container\tid\trunning\tnew\n"}
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
	const unchanged = safeProvisionSnapshot
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
