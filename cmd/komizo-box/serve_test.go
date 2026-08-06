package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
)

// The read API over a real socket.
//
// box/api_test.go covers the handler through httptest; this covers the parts
// that only exist once something is actually listening -- the socket's mode,
// the stale-socket case, and a box that has nothing to verify against.

// serveFixture is an enrolled box WITH A TRUSTED DEVICE.
//
// The device came with komizo-be#72. Before it, a read was a token and a GET,
// so a fixture with no device could still be read; now every route wants a
// signed envelope, and a box that trusts nobody answers nothing at all -- which
// is a state worth having a test for, but not the one to build every test on.
func serveFixture(t *testing.T) (dir string, priv, dev ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	devPub, dev, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	conf := box.AgentConf{
		API:         "https://api.example.com",
		ServerID:    "srv_abc123",
		Token:       "kmz_agt_whatever",
		RegistryKey: base64Key(pub),
		// Prefixed, because that is how enrolment writes one and the config
		// refuses a bare key as "some other kind of credential".
		OperatorKeys: []string{box.DeviceKeyPrefix + base64Key(devPub)},
	}
	if err := box.WriteAgentConf(filepath.Join(dir, "agent.json"), conf); err != nil {
		t.Fatal(err)
	}
	rep := box.Report{V: box.Version, At: time.Now().UTC(),
		Server: box.Server{State: "ready", OS: "Alpine Linux v3.20"}}
	if err := box.WriteReport(filepath.Join(dir, "report.json"), rep); err != nil {
		t.Fatal(err)
	}
	return dir, priv, dev
}

// base64Key is the key as enrolment stores it: raw URL-safe base64, one line.
func base64Key(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// startServe runs the command until the test ends and returns the socket path.
func startServe(t *testing.T, dir string) string {
	t.Helper()
	sock := filepath.Join(dir, "api.sock")
	done := make(chan error, 1)
	go func() {
		done <- runServe([]string{
			"--socket", sock,
			"--config", filepath.Join(dir, "agent.json"),
			"--report", filepath.Join(dir, "report.json"),
			"--history", filepath.Join(dir, "history.jsonl"),
		})
	}()
	t.Cleanup(func() {
		// runServe returns on SIGTERM; the test process cannot signal only
		// itself usefully, so the socket is closed instead and the goroutine
		// is left to unwind with the test binary.
		_ = os.Remove(sock)
	})

	// Wait for the socket rather than sleeping a fixed amount.
	for range 200 {
		if _, err := os.Stat(sock); err == nil {
			return sock
		}
		select {
		case err := <-done:
			t.Fatalf("serve exited before listening: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the socket never appeared")
	return ""
}

func socketClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

func TestItServesOverTheSocket(t *testing.T) {
	dir, priv, dev := serveFixture(t)
	sock := startServe(t, dir)

	tok, err := box.SignReadToken(priv, "srv_abc123", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// A SIGNED READ, which since komizo-be#72 is the only kind there is.
	env, err := box.SignCommand(dev, box.Command{Srv: "srv_abc123",
		Exp: time.Now().Add(time.Minute).Unix(), Op: box.OpReportRead})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://box/v1/report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)

	res, err := socketClient(sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("report over the socket = %d, want 200", res.StatusCode)
	}
	var got box.ReportResponse
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Report.Server.OS != "Alpine Linux v3.20" {
		t.Errorf("report did not come through the socket: %+v", got.Report.Server)
	}
}

// AND THE UNSIGNED READ IS GONE OVER THE SOCKET TOO.
//
// The removal is in box/api.go and so applies everywhere the handler is served,
// but this is the transport an operator's app actually reaches through the
// proxy -- and "the route is gone from the mux" and "the box does not answer it
// on the wire" are not the same claim.
func TestTheUnsignedReadIsRefusedOverTheSocket(t *testing.T) {
	dir, priv, _ := serveFixture(t)
	sock := startServe(t, dir)

	tok, err := box.SignReadToken(priv, "srv_abc123", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/report", "/v1/history"} {
		req, _ := http.NewRequest(http.MethodGet, "http://box"+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		res, err := socketClient(sock).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s over the socket = %d, want 401", path, res.StatusCode)
		}
	}
}

// Owner and group only. Anything else on the box has no business opening it --
// the proxy connects as root, which is not subject to the mode.
func TestTheSocketIsNotWorldWritable(t *testing.T) {
	dir, _, _ := serveFixture(t)
	sock := startServe(t, dir)

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != socketMode {
		t.Errorf("socket mode = %04o, want %04o", perm, socketMode)
	}
}

// A socket file outlives the process that made it, so a box powered off
// mid-request has one on disk that nothing is listening to. Binding over it
// fails -- and for a path rather than a port, that is a service that will not
// start until somebody deletes a file by hand.
func TestAStaleSocketDoesNotBlockStartup(t *testing.T) {
	dir, _, _ := serveFixture(t)
	sock := filepath.Join(dir, "api.sock")
	if err := os.WriteFile(sock, nil, 0o660); err != nil {
		t.Fatal(err)
	}

	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatalf("a stale socket stopped the listener: %v", err)
	}
	ln.Close()
}

// A box with no key can only refuse every request, so it opens nothing at all
// rather than holding a socket that answers 401 forever.
func TestABoxWithNoRegistryKeyServesNothing(t *testing.T) {
	dir := t.TempDir()
	conf := box.AgentConf{API: "https://api.example.com", ServerID: "srv_abc123", Token: "kmz_agt_x"}
	if err := box.WriteAgentConf(filepath.Join(dir, "agent.json"), conf); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "api.sock")

	if err := runServe([]string{"--socket", sock, "--config", filepath.Join(dir, "agent.json")}); err != nil {
		t.Fatalf("a keyless box should exit quietly, got %v", err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Error("a box with no registry key opened a socket anyway")
	}
}

// The socket lives in a directory the serving account can write to.
//
// It did not, and that is how this shipped: /run/komizo is 0755 root:root, the
// process opening the socket runs as komizo_monitor, and `bind: permission
// denied` was the whole of what a box said about it. Found by running it on a
// real machine rather than by reading it, which is the fourth time this exact
// shape -- a process given a path it can read and not write -- has bitten.
func TestTheSocketIsNotInADirectoryTheAgentCannotWrite(t *testing.T) {
	if box.APISocketDir == box.RunDir {
		t.Fatal("the socket directory is the run directory, which is root's -- " +
			"the account that opens the socket cannot create anything in it")
	}
	if filepath.Dir(box.APISocketPath) != box.APISocketDir {
		t.Errorf("the socket is at %q, which is not in %q", box.APISocketPath, box.APISocketDir)
	}
}

// And the installer has to make it, since the account cannot.
func TestTheInstallerCreatesAndGivesAwayTheSocketDirectory(t *testing.T) {
	sh := scripts.AgentInstall("stamp", "v0.0.0")
	if !strings.Contains(sh, box.APISocketDir) {
		t.Fatalf("the installer never mentions %s", box.APISocketDir)
	}
	// After the account exists, or the chown fails quietly and leaves a service
	// that starts and cannot bind -- which is exactly what happened.
	adduser := strings.Index(sh, "adduser")
	chown := strings.Index(sh, "chown komizo_monitor:root "+box.APISocketDir)
	if adduser < 0 || chown < 0 {
		t.Fatalf("adduser=%d chown=%d", adduser, chown)
	}
	if chown < adduser {
		t.Error("the socket directory is given away before the account exists")
	}

	// Grouped to ROOT and setgid, so the socket inherits a group the proxy is
	// in -- it has no CAP_DAC_OVERRIDE and is not exempt from the mode.
	if !strings.Contains(sh, "chmod 2750 "+box.APISocketDir) {
		t.Error("the socket directory is not setgid, so the proxy cannot reach the socket")
	}
	// And after the chown, because chown clears the setgid bit.
	if strings.Index(sh, "chmod 2750 "+box.APISocketDir) < chown {
		t.Error("the mode is set before the chown, which clears the setgid bit")
	}
}

// The history is not in a directory the account that serves it cannot enter.
//
// It was, and this is the FIFTH time this shape has bitten -- the report, the
// state directory, the credential, the socket, and now the readings. Every one
// of them was a process handed a path whose modes were decided somewhere else.
//
// This one hid better than the others. ReadSamples treats an unreadable file
// exactly as it treats an absent one, because a box that has never sampled is a
// new box rather than a broken one -- so /v1/history answered "no readings" on
// every box, with nothing anywhere mentioning permission.
func TestTheHistoryIsNotInADirectoryTheAgentCannotRead(t *testing.T) {
	if box.ServedDir == box.StateDir {
		t.Fatal("the history is in the state directory, which is 0750 root:root -- " +
			"the account that serves it cannot traverse it")
	}
	if filepath.Dir(box.HistoryPath) != box.ServedDir {
		t.Errorf("the history is at %q, which is not in %q", box.HistoryPath, box.ServedDir)
	}
	// Setgid, so a reading root appends is born in the agent's group rather
	// than root's. Without it the directory is reachable and every file in it
	// is still 0640 root:root.
	if box.ServedDirMode&os.ModeSetgid == 0 {
		t.Error("the served directory is not setgid, so root's readings stay in root's group")
	}
	if perm := box.ServedDirMode.Perm(); perm&0o050 == 0 {
		t.Errorf("the served directory is %04o: the group cannot read it", perm)
	}
	if perm := box.ServedDirMode.Perm(); perm&0o007 != 0 {
		t.Errorf("the served directory is %04o: anything on the box can read what this machine measured", perm)
	}
}

// And the installer has to make it, since rootd is not the first thing to run.
func TestTheInstallerCreatesAndGivesAwayTheServedDirectory(t *testing.T) {
	sh := scripts.AgentInstall("stamp", "v0.0.0")
	if !strings.Contains(sh, box.ServedDir) {
		t.Fatalf("the installer never mentions %s", box.ServedDir)
	}
	// After the account exists. A chgrp to an account that is not there yet
	// fails quietly and leaves a directory nothing can read out of.
	adduser := strings.Index(sh, "adduser")
	chown := strings.Index(sh, "chown root:komizo_monitor "+box.ServedDir)
	if adduser < 0 || chown < 0 {
		t.Fatalf("adduser=%d chown=%d", adduser, chown)
	}
	if chown < adduser {
		t.Error("the served directory is given away before the account exists")
	}
	if !strings.Contains(sh, "chmod 2750 "+box.ServedDir) {
		t.Error("the served directory is not setgid, so the readings inherit root's group")
	}
	// After the chown, because chown clears the setgid bit.
	if strings.Index(sh, "chmod 2750 "+box.ServedDir) < chown {
		t.Error("the mode is set before the chown, which clears the setgid bit")
	}
}

// And it PROVES the account can read them, rather than asserting it.
//
// Asserting it is exactly what failed: the mode on the file said 0640 and the
// directory above it said nothing may enter, and only reading it as that
// account can tell the difference. The installer already does this for the
// report -- see design/appify.md §3 -- and the history is on the same boundary.
func TestTheInstallerProvesTheAgentCanReadTheHistory(t *testing.T) {
	sh := scripts.AgentInstall("stamp", "v0.0.0")
	if !strings.Contains(sh, `su komizo_monitor -s /bin/sh -c "cat `+box.HistoryPath+` >/dev/null"`) {
		t.Error("the installer never reads the history as the account that will serve it, " +
			"so a box where it cannot finishes install and answers every history request with nothing")
	}
}

// A box upgrading from before ServedDir existed keeps what it recorded.
//
// registry.md §7 accepts losing a box's history when the BOX dies. Losing it to
// an upgrade is not that trade, and it would be silent -- new readings would
// start accumulating and only the chart's left edge would ever have said so.
func TestTheInstallerMovesAnOlderBoxsReadings(t *testing.T) {
	sh := scripts.AgentInstall("stamp", "v0.0.0")
	old := box.StateDir + "/history.jsonl"
	if !strings.Contains(sh, "mv "+old+" "+box.HistoryPath) {
		t.Fatalf("the installer does not move %s into %s", old, box.HistoryPath)
	}
	// A rename does not take the setgid group -- setgid decides the group of
	// files CREATED in a directory -- so a moved file that is not chgrped is a
	// history the serving account still cannot open.
	if !strings.Contains(sh, "chown root:komizo_monitor "+box.HistoryPath) {
		t.Error("the moved history keeps root's group, which is the group that could not read it")
	}
}

// And the installer makes it, since the account cannot make it for itself.
func TestTheInstallerCreatesAndProvesTheInbox(t *testing.T) {
	sh := scripts.AgentInstall("stamp", "v0.0.0")
	if !strings.Contains(sh, box.InboxDir) {
		t.Fatalf("the installer never mentions %s", box.InboxDir)
	}
	adduser := strings.Index(sh, "adduser")
	chown := strings.Index(sh, "chown komizo_monitor:root "+box.InboxDir)
	if adduser < 0 || chown < 0 {
		t.Fatalf("adduser=%d chown=%d", adduser, chown)
	}
	if chown < adduser {
		t.Error("the inbox is given away before the account exists")
	}
	if !strings.Contains(sh, "chmod 2750 "+box.InboxDir) {
		t.Error("the inbox is not setgid")
	}
	if strings.Index(sh, "chmod 2750 "+box.InboxDir) < chown {
		t.Error("the mode is set before the chown, which clears the setgid bit")
	}

	// PROVEN, not asserted -- app-only.md §4 asks for this specifically, because
	// the failure is silent and every previous one in this shape was found on a
	// real box rather than in review.
	if !strings.Contains(sh, `su komizo_monitor -s /bin/sh -c "touch `+box.InboxDir+`/.probe`) {
		t.Error("the installer never writes to the inbox as the account that will, " +
			"so a box where it cannot finishes install and can never be commanded")
	}
}

// The results directory is made the same way, and PROVEN the same way.
//
// It was made correctly and then unmade: the installer sets 2750
// root:komizo_monitor here, and rootd's own PrepareResultsDir chmod'ed it to
// 0750 on every start, which is the same permissions and not the same bit. So
// every result was born root:root, the serving account could list the directory
// and not open anything in it, and every command the app sent answered "no
// result yet" for as long as anyone polled.
//
// The `ls` check that was already here passed throughout, because listing a
// directory and reading a file in it are different permissions. This asserts
// the one that would have caught it: a file, created here by root, read as the
// account that serves this box.
func TestTheInstallerCreatesAndProvesTheResultsDirectory(t *testing.T) {
	sh := scripts.AgentInstall("stamp", "v0.0.0")
	if !strings.Contains(sh, box.ResultsDir) {
		t.Fatalf("the installer never mentions %s", box.ResultsDir)
	}
	adduser := strings.Index(sh, "adduser")
	chown := strings.Index(sh, "chown root:komizo_monitor "+box.ResultsDir)
	if adduser < 0 || chown < 0 {
		t.Fatalf("adduser=%d chown=%d", adduser, chown)
	}
	if chown < adduser {
		t.Error("the results directory is given away before the account exists")
	}
	// Setgid, so a result root writes is born in the serving account's group
	// rather than root's. Without it the directory is reachable and every file
	// in it is 0640 root:root -- which is exactly what shipped.
	if !strings.Contains(sh, "chmod 2750 "+box.ResultsDir) {
		t.Error("the results directory is not setgid, so every result stays in root's group")
	}
	if strings.Index(sh, "chmod 2750 "+box.ResultsDir) < chown {
		t.Error("the mode is set before the chown, which clears the setgid bit")
	}

	// A FILE, not the directory. Asserted on the `cat`, because that is the
	// difference between the check that passed on the broken box and the one
	// that would not have.
	probe := strings.Index(sh, `su komizo_monitor -s /bin/sh -c "cat $probe >/dev/null"`)
	if probe < 0 {
		t.Fatal("the installer never reads a result as the account that will serve it, " +
			"so a box where it cannot finishes install and reports every command as unanswered")
	}
	// After rootd has run. What rootd leaves behind is what the box lives with,
	// and rootd is what took the bit away.
	rootd := strings.Index(sh, "komizo-box rootd --once")
	if rootd < 0 || probe < rootd {
		t.Errorf("rootd=%d probe=%d -- the result is proven readable before rootd has "+
			"prepared the directory, so what rootd leaves behind is never checked", rootd, probe)
	}
}

// The installer hands the state directory's group away, and does it after the
// account exists.
//
// It also has to survive `komizo add`, which used to chown the same directory
// root:root on every run -- so adding an app to a working box silently took the
// agent's traversal away and its history started answering "no readings".
func TestTheStateDirectoryStaysTraversableByTheAgent(t *testing.T) {
	sh := scripts.AgentInstall("stamp", "v0.0.0")
	adduser := strings.Index(sh, "adduser")
	// The WHOLE line. Matching the path as a substring also matches
	// ".../komizo/served" and ".../komizo/served/results", so the first version
	// of this passed with the state directory's chown deleted.
	chown := strings.Index(sh, "chown root:komizo_monitor "+box.StateDir+"\n")
	if adduser < 0 || chown < 0 {
		t.Fatalf("adduser=%d chown=%d -- the installer never gives the state directory away", adduser, chown)
	}
	if chown < adduser {
		t.Error("the state directory is given away before the account exists")
	}

	// And the script that adds an app must not take it back.
	add := scripts.AlpineScript
	if !strings.Contains(add, "chgrp komizo_monitor /var/lib/komizo") {
		t.Error("`komizo add` resets the state directory's group, so adding an app to a " +
			"working box stops its history being readable")
	}
}
