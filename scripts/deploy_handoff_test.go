package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The adapter neither owns staging locks nor rewrites the root worker journal.
// Actual post-disconnect execution and owner-stop races exercise rootd directly.
func TestDeployHandoffDoesNotRewriteTheRootJournal(t *testing.T) {
	for _, failure := range []string{"submit", "wait", "authority"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			log := filepath.Join(root, "calls")
			shim := `#!/bin/sh
printf '%s\n' "$*" >> "$CALLS"
case "$2" in
deployment-enabled) [ "$FAILURE" != authority ] ;;
deployment-submit) [ "$FAILURE" != submit ] || exit 1; echo 01234567890123456789012345678901 ;;
activation-wait) exit 42 ;;
*) exit 1 ;;
esac
`
			if err := os.WriteFile(filepath.Join(root, "komizo-box"), []byte(shim), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", deployBody(t), "deploy", strings.Repeat("b", 40))
			cmd.Env = append(os.Environ(), "PATH="+root+":/usr/bin:/bin", "CALLS="+log, "FAILURE="+failure)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatal("expected refused authority/submission or disconnected waiter")
			}
			if strings.Contains(string(out), "deploy: started=") {
				t.Fatal("disconnected client claimed activation")
			}
			body, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			calls := string(body)
			if strings.Contains(calls, "--phase") || strings.Contains(calls, "activation-submit") {
				t.Fatal("adapter became a second staging authority", calls)
			}
			if failure == "wait" && !strings.Contains(calls, "workload activation-wait") {
				t.Fatal("durable submission did not reach read-only waiter", calls)
			}
			if failure == "authority" && strings.Contains(calls, "deployment-submit") {
				t.Fatal("unconfigured authority reached submission", calls)
			}
		})
	}
}
