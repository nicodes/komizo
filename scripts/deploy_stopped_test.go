package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Container activation and owner-stop race coverage now exercise rootd in
// cmd/komizo-box/workload_activation_test.go. The shell retains staging only.

// deployBody is the generated per-app deploy script, as it is written to the
// box -- the contents of the quoted heredoc inside alpine.sh.
//
// Placeholders are still __LIKE_THIS__ here, because alpine.sh substitutes them
// with sed ON the box; TestNoScriptShipsAnUnsubstitutedPlaceholder exempts the
// alpine scripts for that reason. Nothing below depends on a placeholder's
// value, and alpine.sh refuses to install a script with one left in it.
func deployBody(t *testing.T) string {
	t.Helper()
	const open = "<<'KOMIZO_DEPLOY_EOF'\n"
	const close = "\nKOMIZO_DEPLOY_EOF\n"
	i := strings.Index(AlpineScript, open)
	if i < 0 {
		t.Fatal("alpine.sh no longer writes the deploy script from a KOMIZO_DEPLOY_EOF heredoc -- has it moved?")
	}
	rest := AlpineScript[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		t.Fatal("the KOMIZO_DEPLOY_EOF heredoc is never closed")
	}
	return rest[:j]
}

func closingFi(t *testing.T, lines []string, open int, what string) int {
	t.Helper()
	depth := 0
	for i := open; i < len(lines); i++ {
		switch {
		case strings.HasPrefix(lines[i], "if "):
			depth++
		case lines[i] == "fi":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	t.Fatalf("%s has no closing fi at column zero", what)
	return 0
}

// versionCommit is the block that records the version this deploy delivered:
// the `if grep -q '^APP_VERSION='` that rewrites the key when .env already has
// one and appends it when it does not.
//
// BOTH BRANCHES, which is the point of lifting the whole block rather than
// naming a line. The append branch runs once in an app's life; the rewrite
// branch runs on every deploy after the first, which is very nearly all of them
// -- so the branch that was pinned was the rare one and the branch that carries
// production was unchecked. Deleting the `sed`, pointing it at the wrong
// variable, or unanchoring its pattern all left `go test ./scripts/` green.
func versionCommit(t *testing.T, body string) (block string, at, end int) {
	t.Helper()
	lines := strings.Split(body, "\n")
	open := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "if grep -q '^APP_VERSION='") {
			open = i
			break
		}
	}
	if open < 0 {
		t.Fatal("the deploy script never records APP_VERSION, so a start after a deploy brings up the previous version")
	}
	close := closingFi(t, lines, open, "the APP_VERSION commit")
	block = strings.Join(lines[open:close+1], "\n")
	at = strings.Index(body, block)
	return block, at, at + len(block)
}

func TestTheDeployedVersionIsRecordedOnEveryDeploy(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	block, _, _ := versionCommit(t, deployBody(t))

	for _, tc := range []struct {
		name string
		env  string
		want string
	}{
		// An app's FIRST deploy: nothing to rewrite, so the key is appended and
		// everything already in the file is left alone.
		{
			"a first deploy, with no APP_VERSION yet",
			"COMPOSE_PROJECT_NAME=web\n",
			"COMPOSE_PROJECT_NAME=web\nAPP_VERSION=abc1234\n",
		},

		// EVERY DEPLOY AFTER THE FIRST, which is very nearly all of them. The
		// old value must be gone, not merely followed by a newer one -- compose
		// takes the last assignment, but a file with two is a file two readers
		// disagree about, and `komizo report` reads it with first-wins.
		{
			"a redeploy, over an existing APP_VERSION",
			"COMPOSE_PROJECT_NAME=web\nAPP_VERSION=old9999\n",
			"COMPOSE_PROJECT_NAME=web\nAPP_VERSION=abc1234\n",
		},

		// The key in the middle of the file, with lines after it. An append-only
		// rewrite would leave the stale one above the new one.
		{
			"a redeploy, with the key above other settings",
			"APP_VERSION=old9999\nCOMPOSE_PROJECT_NAME=web\n",
			"APP_VERSION=abc1234\nCOMPOSE_PROJECT_NAME=web\n",
		},

		// ANCHORED. A key that merely ends in APP_VERSION is somebody else's
		// key, and an unanchored `s|APP_VERSION=.*|` rewrites it too -- silently
		// destroying a value this script was never asked to touch, in the one
		// file the app's whole configuration comes from.
		{
			"a redeploy, beside a key that ends in APP_VERSION",
			"PREV_APP_VERSION=old9999\nAPP_VERSION=old9999\n",
			"PREV_APP_VERSION=old9999\nAPP_VERSION=abc1234\n",
		},

		// The same, where the similarly named key is the ONLY one. `grep -q` is
		// anchored too, so this takes the append branch -- and a `grep` that
		// matched here would take the rewrite branch and never write the key at
		// all.
		{
			"a first deploy, beside a key that ends in APP_VERSION",
			"PREV_APP_VERSION=old9999\n",
			"PREV_APP_VERSION=old9999\nAPP_VERSION=abc1234\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			env := filepath.Join(dir, ".env")
			if err := os.WriteFile(env, []byte(tc.env), 0o600); err != nil {
				t.Fatal(err)
			}
			// `ref` is set because it is in scope at this point in the real
			// script and is the value a slip would most plausibly reach for --
			// it is the thing that was just pulled. It must not end up in .env:
			// APP_VERSION is a tag, and compose substitutes it into image
			// references that already carry a registry and a repository.
			prelude := "set -euf\n" +
				"version=abc1234\n" +
				"ref=registry.example/web-config:abc1234\n" +
				"cd " + dir + "\n"

			cmd := exec.Command("sh", "-c", prelude+strings.ReplaceAll(block, "komizo-box workload operation", ": workload operation"))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("the APP_VERSION commit failed to run: %v\n%s", err, out)
			}

			got, err := os.ReadFile(env)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf(".env is\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}
