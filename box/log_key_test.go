package box

import (
	"crypto/ed25519"
	"encoding/base64"

	"strings"
	"testing"
)

// Registry observations, root commands and account logs have distinct authority.

// The box `komizo setup` produces once the account has a log key: enrolled,
// no operator devices at all.

// THE HALF THAT PROVES THE BOX IS ANSWERING AT ALL. Without it, everything
// below passes against a box that is simply broken.

// AND THE HALF THIS EPIC EXISTS FOR.

// And the account's own key does the opposite: reads the log, commands
// nothing. Neither key is simply more powerful than the other.

// A log key is not a device key is not a registry key.
//
// The failure this prevents is planting the REGISTRY key as a log key, which is
// the one string that would undo #187 completely: it is the same 32 bytes the
// box already holds, it is exactly what a service wanting your logs would send,
// and nothing about it looks wrong.
func TestOnlyALogKeyIsALogKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(pub)

	for name, in := range map[string]string{
		"a registry key, which is the same bytes with no prefix": raw,
		"a device key":           DeviceKeyPrefix + raw,
		"an agent token":         "kmz_agt_" + raw,
		"a read token":           ReadTokenPrefix + raw,
		"nothing at all":         "",
		"the prefix on its own":  LogKeyPrefix,
		"not base64":             LogKeyPrefix + "!!!!",
		"the right shape, short": LogKeyPrefix + base64.RawURLEncoding.EncodeToString(pub[:16]),
	} {
		if _, err := ParseLogKey(in); err == nil {
			t.Errorf("%s was accepted as a log key", name)
		}
	}
	good := FormatLogKey(pub)
	got, err := ParseLogKey(good)
	if err != nil {
		t.Fatalf("a real log key was refused: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("the key that came back is not the key that went in")
	}
	// Whitespace, because these are copied between two windows.
	if _, err := ParseLogKey("  " + good + "\n"); err != nil {
		t.Errorf("a log key with whitespace around it was refused: %v", err)
	}
}

// NOTHING THE SERVICE CAN SIGN PLANTS A LOG KEY.
//
// The hole this closes is the one that would make the whole epic theatre: if
// komizo could push a log key to a box, it would push its own and read every
// log, and every other guard here would still pass.
//
// So the op set itself is the assertion. A new op that writes a log key has to
// come here and argue for it, which is the point -- see AgentConf.LogKeys.
func TestNoSignedCommandCanPlantALogKey(t *testing.T) {
	for _, op := range commandOps {
		if strings.Contains(op, "log") && op != OpLogsRead {
			t.Errorf("%q looks like an op that touches log keys -- "+
				"if it plants one, komizo can read your logs and #187 is theatre", op)
		}
	}
	// The positive control: the op set is not empty and this test is looking at
	// something. Without it, deleting commandOps entirely would pass.
	if len(commandOps) == 0 {
		t.Fatal("there are no ops at all, so this test checked nothing")
	}
	if !KnownOp(OpLogsRead) {
		t.Error("logs.read is not a known op, so this test is inspecting the wrong list")
	}
}

// A box that commands and serves no logs is a NORMAL box, not a broken one.
//
// It is what every box looks like between komizo-be#180 and the account setting
// a log passphrase, and it will be the state of the user's own box the moment
// this ships. Reporting it as a fault would send somebody to the machine to fix
// something that is working exactly as designed.

// And an operator's device is enough on its own, without an account key.
// That was §5's original answer and the CLI's path still uses it.

// An unreadable log key fails the set rather than being skipped.
//
// Failing open here is silent: a log that can be read looks exactly like a log
// that should be readable.
func TestOneUnreadableLogKeyFailsTheWholeSet(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	conf := AgentConf{ServerID: "srv_mine",
		LogKeys: []string{FormatLogKey(pub), "kmz_log_nonsense"}}
	if _, err := conf.LogTrustedKeys(); err == nil {
		t.Fatal("a set with an unreadable log key was accepted")
	} else if !strings.Contains(err.Error(), "2 of 2") {
		t.Errorf("error = %q, want it to name which key of how many", err)
	}
}
