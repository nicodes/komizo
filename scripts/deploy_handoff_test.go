package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeployHandoffReleasesLocksAndDisconnectDoesNotFailRootJournal(t *testing.T) {
	body := deployBody(t)
	start := strings.Index(body, "journal_finished=1\nif ! activation_id=")
	if start < 0 {
		t.Fatal("deploy does not delegate before durable submission")
	}
	fragment := body[start:]
	for _, submitFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "waiter disconnected", true: "submission refused"}[submitFails], func(t *testing.T) {
			root := t.TempDir()
			log := filepath.Join(root, "calls")
			shim := `#!/bin/sh
printf '%s\n' "$*" >> "$CALLS"
case "$2" in
activation-submit) [ "$SUBMIT_FAILS" = 0 ] || exit 1; echo 01234567890123456789012345678901 ;;
activation-wait) exit 42 ;;
operation) exit 0 ;;
*) exit 1 ;;
esac
`
			if err := os.WriteFile(filepath.Join(root, "komizo-box"), []byte(shim), 0700); err != nil {
				t.Fatal(err)
			}
			prelude := `set -eu
APP_NAME=example
WORKLOAD_POLICY=policy
version=candidate
previous=previous
ROUTE_FILE=route
PROXY_CONTAINER=proxy
journal_finished=0
trap 'if [ "$journal_finished" = 0 ]; then echo trap-failed >> "$CALLS"; fi' EXIT
exec 6>"$CALLS.host"
exec 9>"$CALLS.app"
flock() { printf 'unlock:%s\n' "$*" >> "$CALLS"; }
`
			cmd := exec.Command("sh", "-c", prelude+fragment)
			flag := "0"
			if submitFails {
				flag = "1"
			}
			cmd.Env = append(os.Environ(), "PATH="+root+":/usr/bin:/bin", "CALLS="+log, "SUBMIT_FAILS="+flag)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatal("expected submission/wait failure")
			}
			if strings.Contains(string(out), "deploy: started=") {
				t.Fatal("disconnected client claimed activation")
			}
			calls, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			s := string(calls)
			if strings.Contains(s, "trap-failed") {
				t.Fatal("shell rewrote a delegated journal", s)
			}
			if !submitFails {
				if !strings.Contains(s, "unlock:-u 6\nunlock:-u 9\nworkload activation-wait") {
					t.Fatal("root worker cannot acquire released locks", s)
				}
				if strings.Contains(s, "--phase failed") {
					t.Fatal("disconnected waiter cancelled root operation", s)
				}
			} else if !strings.Contains(s, "--phase failed") {
				t.Fatal("failed submission left an unacknowledged staging operation", s)
			}
		})
	}
}
