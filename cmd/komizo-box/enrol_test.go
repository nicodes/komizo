package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	var k keyList
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
