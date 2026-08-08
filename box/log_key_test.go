package box

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE ASSERTION THE WHOLE EPIC RESTS ON.
//
// komizo-be#187. The registry key commands this box -- that is komizo-be#180 and
// it is what lets any signed-in device work -- and it must not read a log. Both
// halves are checked, because asserting only the refusal would pass against a
// box that refuses everything, which is exactly the failure this codebase keeps
// finding: the passing result indistinguishable from the not-running result.
//
// One key, one box, two routes, opposite answers. Nothing else varies.
func TestTheRegistryKeyCommandsThisBoxAndCannotReadItsLogs(t *testing.T) {
	regPub, regPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	acctPub, acctPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// The box `komizo init` produces once the account has a log key: enrolled,
	// no operator devices at all.
	conf := AgentConf{ServerID: "srv_mine", API: "https://api.example.com", Token: "kmz_agt_x",
		RegistryKey: base64.RawURLEncoding.EncodeToString(regPub),
		LogKeys:     []string{FormatLogKey(acctPub)}}

	cmdKeys, err := conf.TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	logKeys, err := conf.LogTrustedKeys()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "web.log"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := Report{V: Version, At: time.Now().UTC()}
	rep.Server.State = "ready"
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(report, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := APIConfig{ServerID: "srv_mine", RegistryKey: regPub,
		OperatorKeys: cmdKeys, LogKeys: logKeys,
		LogsDir: dir, ReportPath: report}
	tok, err := SignReadToken(regPriv, cfg.ServerID, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(cfg)

	post := func(path string, priv ed25519.PrivateKey, op string, args map[string]string) int {
		t.Helper()
		env, err := SignCommand(priv, Command{Srv: cfg.ServerID,
			Exp: time.Now().Add(time.Minute).Unix(), Op: op, Args: args})
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// THE HALF THAT PROVES THE BOX IS ANSWERING AT ALL. Without it, everything
	// below passes against a box that is simply broken.
	if code := post("/v1/report", regPriv, OpReportRead, nil); code != http.StatusOK {
		t.Fatalf("the registry key could not read the report (%d) -- "+
			"komizo-be#180 is broken, and the log check below proves nothing", code)
	}

	// AND THE HALF THIS EPIC EXISTS FOR.
	if code := post("/v1/logs", regPriv, OpLogsRead, map[string]string{"app": "web"}); code == http.StatusOK {
		t.Error("the registry key read a log -- whoever holds komizo's signing key " +
			"can read every log on every enrolled box, which is what #187 exists to stop")
	}

	// And the account's own key does the opposite: reads the log, commands
	// nothing. Neither key is simply more powerful than the other.
	if code := post("/v1/logs", acctPriv, OpLogsRead, map[string]string{"app": "web"}); code != http.StatusOK {
		t.Errorf("the account's log key could not read a log (%d) -- "+
			"logs would be unreadable by anybody, which is not the goal", code)
	}
	if code := post("/v1/report", acctPriv, OpReportRead, nil); code == http.StatusOK {
		t.Error("a log key read the report -- it is scoped to logs and nothing else")
	}
}

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
func TestAnEnrolledBoxWithNoLogKeyCommandsButServesNoLogs(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	conf := AgentConf{ServerID: "srv_mine", API: "https://api.example.com", Token: "kmz_agt_x",
		RegistryKey: base64.RawURLEncoding.EncodeToString(pub)}

	if !conf.CanCommand() {
		t.Error("an enrolled box will not take orders, so komizo-be#180 is broken")
	}
	if conf.CanReadLogs() {
		t.Error("a box with no log keys claims its logs are readable")
	}
	keys, err := conf.LogTrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("log keys = %d, want none -- the registry key must not leak into this set", len(keys))
	}

	// And an operator's device is enough on its own, without an account key.
	// That was §5's original answer and the CLI's path still uses it.
	devPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	conf.OperatorKeys = []string{FormatDeviceKey(devPub)}
	if !conf.CanReadLogs() {
		t.Error("a planted device cannot read logs, which was §5's original answer")
	}
}

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
