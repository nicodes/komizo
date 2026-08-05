package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/box"
)

// THE SERVICE DOES NOT DECIDE WHO MAY COMMAND THIS BOX.
//
// This is the whole of komizo-be design/app-only.md §4, expressed as a test
// because it is the kind of property that is deleted by a helpful refactor. If
// the exchange could return operator keys, a compromised or dishonest service
// could add its own, and komizo would hold root on every machine it knows
// about -- which is the thing appify.md §1 exists to prevent.
//
// So the reply is given every chance to smuggle one, and the credential that
// comes out of it has to carry none.
func TestTheServiceCannotPlantAKeyThatCommandsTheBox(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	theirs := box.FormatDeviceKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Every spelling a future service might use, all at once.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server_id":     "srv_abc123",
			"agent_token":   "kmz_agt_x",
			"registry_key":  "",
			"operator_keys": []string{theirs},
			"device_keys":   []string{theirs},
			"operatorKeys":  []string{theirs},
		})
	}))
	defer srv.Close()

	conf, err := exchange(context.Background(), srv.URL, "kmz_enr_x", "", box.Report{})
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.OperatorKeys) != 0 {
		t.Fatalf("the exchange returned operator keys %v -- the service can command this box", conf.OperatorKeys)
	}
	if conf.CanCommand() {
		t.Error("a box that was told nothing by its operator would take orders")
	}
}

// And the flag is what does decide it.
func TestTheOperatorsKeysAreTheOnesTheFlagCarried(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	mine := box.FormatDeviceKey(pub)

	var k box.DeviceKeyList
	if err := k.Set(mine); err != nil {
		t.Fatal(err)
	}
	// Twice is a paste, not an error.
	if err := k.Set(mine); err != nil {
		t.Fatal(err)
	}
	if len(k) != 1 {
		t.Errorf("the same key twice became %d entries", len(k))
	}
	// A registry key in the wrong flag is refused before it reaches a box.
	if err := k.Set("not_a_device_key"); err == nil {
		t.Error("a value that is not a device key was accepted")
	} else if !strings.Contains(err.Error(), box.DeviceKeyPrefix) {
		t.Errorf("error = %q, want it to name what a device key looks like", err)
	}
}

// Rotating a leaked agent token must not silently un-trust every device.
//
// komizo-be#24 made re-enrolment the way to replace a credential you suspect,
// precisely so that responding to a leak does not mean deleting the server. If
// that also dropped the operator keys, the app would stop working on that box
// with nothing anywhere saying why -- and the person who did it was in the
// middle of handling an incident.
// mustCarry is carryOperatorKeys where the drop count is not what is under test.
func mustCarry(prev box.AgentConf, serverID string, added []string, forget bool) []string {
	keys, _ := carryOperatorKeys(prev, serverID, added, forget)
	return keys
}

func TestReEnrollingTheSameBoxKeepsItsDevices(t *testing.T) {
	prev := box.AgentConf{ServerID: "srv_abc", OperatorKeys: []string{"kmz_dev_a", "kmz_dev_b"}}

	got := mustCarry(prev, "srv_abc", nil, false)
	if len(got) != 2 {
		t.Fatalf("re-enrolling dropped the devices: %v", got)
	}

	// And --device-key ADDS rather than replaces.
	got = mustCarry(prev, "srv_abc", []string{"kmz_dev_c"}, false)
	if len(got) != 3 {
		t.Errorf("adding a device replaced the others: %v", got)
	}
	// Idempotently. Re-running the same enrol command should not grow the list.
	got = mustCarry(prev, "srv_abc", []string{"kmz_dev_a"}, false)
	if len(got) != 2 {
		t.Errorf("re-adding a device it already trusts grew the list: %v", got)
	}
}

// A box that has changed hands starts over.
//
// A different server id means a different row and usually a different account
// -- komizo#28's fallback covers exactly that. Carrying the previous owner's
// devices in would leave them able to command a machine that is not theirs.
func TestABoxThatChangedHandsForgetsTheOldOwnersDevices(t *testing.T) {
	prev := box.AgentConf{ServerID: "srv_theirs", OperatorKeys: []string{"kmz_dev_theirs"}}

	got := mustCarry(prev, "srv_mine", []string{"kmz_dev_mine"}, false)
	if len(got) != 1 || got[0] != "kmz_dev_mine" {
		t.Fatalf("keys = %v, want only the new owner's", got)
	}
	// And with nothing new, it trusts nothing at all rather than the old owner.
	if got := mustCarry(prev, "srv_mine", nil, false); len(got) != 0 {
		t.Errorf("keys = %v, want none -- this box belongs to somebody else now", got)
	}
}

// And there is a way to say it out loud.
func TestForgetDevicesDropsThemOnTheSameBox(t *testing.T) {
	prev := box.AgentConf{ServerID: "srv_abc", OperatorKeys: []string{"kmz_dev_a"}}
	if got := mustCarry(prev, "srv_abc", nil, true); got != nil {
		t.Errorf("keys = %v, want none", got)
	}
	// Forgetting and adding in one command is "these, and only these" -- which
	// is what replacing a lost laptop looks like.
	got := mustCarry(prev, "srv_abc", []string{"kmz_dev_new"}, true)
	if len(got) != 1 || got[0] != "kmz_dev_new" {
		t.Errorf("keys = %v, want only the new one", got)
	}
}

// The same property, asserted where it actually matters: on disk.
//
// The test above proves `exchange` returns a struct with no keys in it, which is
// a fact about a struct literal. What has to be true is that agent.json --
// the file rootd will verify commands against -- carries none, and that survives
// somebody moving the assignment. Run through runEnrol end to end, with --config
// pointed at a temp file.
func TestNothingTheServiceSaysReachesTheKeysOnDisk(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	theirs := box.FormatDeviceKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server_id":     "srv_abc123",
			"agent_token":   "kmz_agt_x",
			"operator_keys": []string{theirs},
			"device_keys":   []string{theirs},
			"operatorKeys":  []string{theirs},
		})
	}))
	defer srv.Close()

	conf := filepath.Join(t.TempDir(), "agent.json")
	if err := runEnrol([]string{"--api", srv.URL, "--token", "kmz_enr_x", "--config", conf}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), theirs) {
		t.Fatalf("the service's key is in the credential on disk:\n%s", raw)
	}
	got, err := box.ReadAgentConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if got.CanCommand() {
		t.Error("a box nobody gave a device key would take orders")
	}

	// And the operator's own key does reach it, so the test above is not passing
	// because nothing is written at all.
	mine := box.FormatDeviceKey(pub)
	if err := runEnrol([]string{"--api", srv.URL, "--token", "kmz_enr_x", "--config", conf,
		"--device-key", mine}); err != nil {
		t.Fatal(err)
	}
	got, err = box.ReadAgentConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if !got.CanCommand() || len(got.OperatorKeys) != 1 || got.OperatorKeys[0] != mine {
		t.Errorf("operator keys = %v, want exactly the one the flag carried", got.OperatorKeys)
	}
}

// The service cannot ADD a key, but it can force a box to forget every one --
// by answering with a different server id. That is accepted; doing it quietly
// is not.
func TestAServiceForcedDropIsCounted(t *testing.T) {
	prev := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{"kmz_dev_a", "kmz_dev_b"}}

	keys, dropped := carryOperatorKeys(prev, "srv_somethingelse", nil, false)
	if len(keys) != 0 {
		t.Errorf("keys = %v, want none", keys)
	}
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2 -- the operator has to be told", dropped)
	}
	// A normal re-enrol of the same box drops nothing and says nothing.
	if _, dropped := carryOperatorKeys(prev, "srv_mine", nil, false); dropped != 0 {
		t.Errorf("dropped = %d on an ordinary re-enrol", dropped)
	}
}
