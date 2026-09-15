package rollout

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func authorizationDocument(t *testing.T, executable string, uid, gid uint32) []byte {
	t.Helper()
	body, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	pinID := strings.Repeat("a", 64)
	identity := strings.Repeat("b", 64)
	wire := recoveryAuthorizationWire{Version: 1, App: "fixture", Transaction: "transaction", Service: "worker",
		Old:          RecoveryIncarnationPin{ID: pinID, StartedAt: "2026-09-15T00:00:00Z", FinishedAt: "2026-09-15T00:01:00Z", ExitCode: 1, Generation: "old", Identity: identity},
		Candidate:    RecoveryIncarnationPin{ID: strings.Repeat("c", 64), StartedAt: "2026-09-15T00:02:00Z", Generation: "new", Identity: strings.Repeat("d", 64)},
		VerifierPath: executable, VerifierSHA256: hex.EncodeToString(digest[:]), VerifierArgs: []string{"-test.run=TestRecoveryVerifierHelperProcess", "--", "success"},
		UID: uid, GID: gid, Overall: "8m", Retire: "5m"}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRecoveryAuthorizationIsExactPrivateAndPinned(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authorization.json")
	data := authorizationDocument(t, executable, uint32(max(os.Getuid(), 1)), uint32(max(os.Getgid(), 1)))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	authorization, err := LoadRecoveryAuthorization(path)
	if err != nil || authorization.Digest != hash(data) || authorization.Overall != 8*time.Minute || authorization.Retire != 5*time.Minute {
		t.Fatalf("valid pinned authorization refused: %+v %v", authorization, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryAuthorization(path); err == nil {
		t.Fatal("public recovery authorization accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []string{`"overall":"9m"`, `"unknown":true`} {
		changed := data
		if strings.HasPrefix(replacement, `"overall"`) {
			changed = []byte(strings.Replace(string(data), `"overall":"8m"`, replacement, 1))
		} else {
			changed = append(append([]byte{}, data[:len(data)-1]...), []byte(","+replacement+"}")...)
		}
		if err := os.WriteFile(path, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := LoadRecoveryAuthorization(path); err == nil || got.Digest == authorization.Digest {
			t.Fatalf("changed/unknown authorization accepted: %+v %v", got, err)
		}
	}
	changedChecksum := []byte(strings.Replace(string(data), `"verifier_sha256":"`+authorization.VerifierSHA256+`"`, `"verifier_sha256":"`+strings.Repeat("e", 64)+`"`, 1))
	if err := os.WriteFile(path, changedChecksum, 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := LoadRecoveryAuthorization(path)
	if err != nil || changed.Digest == authorization.Digest {
		t.Fatalf("changed checksum was not bound into authorization identity: %+v %v", changed, err)
	}
}

func TestPinnedRecoveryVerifierProtocolAndFailures(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() == 0 || os.Getgid() == 0 {
		t.Skip("credential-drop control requires an unprivileged test identity")
	}
	sourceExecutable, _ := os.Executable()
	executable := filepath.Join(t.TempDir(), "recovery-verifier")
	body, copyErr := os.ReadFile(sourceExecutable)
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	if err := os.WriteFile(executable, body, 0o555); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authorization.json")
	data := authorizationDocument(t, executable, uint32(os.Getuid()), uint32(os.Getgid()))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	authorization, err := LoadRecoveryAuthorization(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	challenge := RecoveryChallenge{Version: 1, Nonce: "nonce", App: "fixture", Transaction: "transaction", Service: "worker",
		Old: authorization.Old, Candidate: authorization.Candidate, DeadlineUnixMillis: time.Now().Add(25 * time.Second).UnixMilli(), OverallDeadlineUnixMillis: deadline.UnixMilli()}
	session, err := (&ProcessRecoveryVerifier{Authorization: authorization}).Open(ctx, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Release(ctx); err != nil {
		t.Fatal(err)
	}
	session.Preserve()

	for _, mode := range []string{"malformed", "nonempty", "early"} {
		authorization.VerifierArgs[len(authorization.VerifierArgs)-1] = mode
		if session, err := (&ProcessRecoveryVerifier{Authorization: authorization}).Open(ctx, challenge); err == nil || session != nil {
			t.Fatalf("%s verifier response accepted: %v", mode, err)
		}
	}
	for _, mode := range []string{"release-malformed", "release-early"} {
		authorization.VerifierArgs[len(authorization.VerifierArgs)-1] = mode
		releaseSession, err := (&ProcessRecoveryVerifier{Authorization: authorization}).Open(ctx, challenge)
		if err != nil {
			t.Fatalf("%s did not reach release control: %v", mode, err)
		}
		if err := releaseSession.Release(ctx); err == nil {
			t.Fatalf("%s release failure was accepted", mode)
		}
		releaseSession.Preserve()
	}
	authorization.VerifierArgs[len(authorization.VerifierArgs)-1] = "hang"
	hungChallenge := challenge
	hungChallenge.DeadlineUnixMillis = time.Now().Add(50 * time.Millisecond).UnixMilli()
	if session, err := (&ProcessRecoveryVerifier{Authorization: authorization}).Open(ctx, hungChallenge); err == nil || session != nil {
		t.Fatalf("hung verifier handshake accepted: %v", err)
	}
	authorization.VerifierArgs[len(authorization.VerifierArgs)-1] = "release-hang"
	hungReleaseSession, err := (&ProcessRecoveryVerifier{Authorization: authorization}).Open(ctx, challenge)
	if err != nil {
		t.Fatalf("release-hang did not reach release control: %v", err)
	}
	releaseContext, releaseCancel := context.WithTimeout(ctx, 50*time.Millisecond)
	if err := hungReleaseSession.Release(releaseContext); err == nil {
		t.Fatal("hung verifier release accepted")
	}
	releaseCancel()
	hungReleaseSession.Preserve()
	authorization.VerifierArgs[len(authorization.VerifierArgs)-1] = "activated"
	challenge.AlreadyActivated = true
	activatedSession, err := (&ProcessRecoveryVerifier{Authorization: authorization}).Open(ctx, challenge)
	if err != nil {
		t.Fatalf("idempotent already-activated state refused: %v", err)
	}
	if err := activatedSession.Release(ctx); err != nil {
		t.Fatal(err)
	}
	activatedSession.Preserve()
	if err := os.Chmod(executable, 0o755); err != nil {
		t.Fatal(err)
	}
	if session, err := (&ProcessRecoveryVerifier{Authorization: authorization}).Open(ctx, challenge); err == nil || session != nil {
		t.Fatalf("writable verifier executable accepted: %v", err)
	}
	if err := os.Chmod(executable, 0o555); err != nil {
		t.Fatal(err)
	}
	authorization.VerifierSHA256 = strings.Repeat("f", 64)
	if session, err := (&ProcessRecoveryVerifier{Authorization: authorization}).Open(ctx, challenge); err == nil || session != nil {
		t.Fatalf("checksum mismatch accepted: %v", err)
	}
}

func TestRecoveryVerifierHelperProcess(t *testing.T) {
	mode := ""
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
		}
	}
	if mode == "" {
		return
	}
	var challenge RecoveryChallenge
	if json.NewDecoder(io.LimitReader(os.Stdin, recoveryProtocolLimit)).Decode(&challenge) != nil {
		os.Exit(2)
	}
	switch mode {
	case "hang":
		time.Sleep(time.Hour)
	case "malformed":
		fmt.Println("not-a-proof")
		os.Exit(0)
	case "nonempty":
		fmt.Printf("komizo-recovery-verifier-v1 not-empty %s\n", challenge.Nonce)
		os.Exit(0)
	case "early":
		os.Exit(0)
	case "success", "release-malformed", "release-early", "release-hang":
		fmt.Printf("komizo-recovery-verifier-v1 fenced-empty %s\n", challenge.Nonce)
	case "activated":
		if !challenge.AlreadyActivated {
			os.Exit(4)
		}
		fmt.Printf("komizo-recovery-verifier-v1 activated %s\n", challenge.Nonce)
	default:
		os.Exit(2)
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if line != "release "+challenge.Nonce+"\n" {
		os.Exit(3)
	}
	if mode == "release-malformed" {
		fmt.Println("not-a-release-proof")
		os.Exit(0)
	}
	if mode == "release-early" {
		os.Exit(0)
	}
	if mode == "release-hang" {
		time.Sleep(time.Hour)
	}
	fmt.Printf("komizo-recovery-verifier-v1 released %s\n", challenge.Nonce)
	os.Exit(0)
}
