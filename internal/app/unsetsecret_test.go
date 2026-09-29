package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// This is the one command that destroys a credential, so its argument handling
// is checked before anything opens a connection, and the shell it pipes is
// driven against a real file rather than asserted about as text.

func TestUnsetSecretRefusesBeforeConnecting(t *testing.T) {
	// Every case must fail on the ARGUMENTS. None of these name a reachable
	// host, so a case that got as far as SSH would hang or fail for the wrong
	// reason -- and a check that runs after the connection is a check that has
	// already asked somebody's server to do something.
	for _, c := range []struct {
		what string
		args []string
		want string
	}{
		{
			"both directions at once",
			[]string{"--host", "root@h", "--app", "blog", "--name", "A", "--keep", "B", "--yes"},
			"not both",
		},
		{
			"list with an edit",
			[]string{"--host", "root@h", "--app", "blog", "--list", "--name", "A"},
			"only reads",
		},
		{
			"neither a name nor a list",
			[]string{"--host", "root@h", "--app", "blog"},
			"nothing to do",
		},
		{
			// --yes is what `komizo remove` requires for the same reason.
			// Overwriting a secret can be undone from GitHub; deleting one
			// that only ever existed on the box cannot be undone at all.
			"deleting without --yes",
			[]string{"--host", "root@h", "--app", "blog", "--name", "OLD_KEY"},
			"--yes",
		},
		{
			// A name is a grep pattern on the far side. A metacharacter here
			// would match keys nobody asked about, in the command that
			// deletes them.
			"a name with a regex metacharacter",
			[]string{"--host", "root@h", "--app", "blog", "--name", "OLD.*", "--yes"},
			"letters, digits and underscore",
		},
		{
			"a hyphen, which no environment variable has",
			[]string{"--host", "root@h", "--app", "blog", "--name", "OLD-KEY", "--yes"},
			"letters, digits and underscore",
		},
		{
			"a reserved app name",
			[]string{"--host", "root@h", "--app", "_proxy", "--name", "A", "--yes"},
			"reserved",
		},
		{
			"a positional argument",
			[]string{"--host", "root@h", "--app", "blog", "--list", "OLD_KEY"},
			"every input is a flag",
		},
	} {
		t.Run(c.what, func(t *testing.T) {
			err := RunUnsetSecret(c.args)
			if err == nil {
				t.Fatalf("expected a refusal, got none")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("expected the message to mention %q, got: %v", c.want, err)
			}
		})
	}
}

// What the flags become, checked without a server.
//
// The --list row is a regression: --list used to fall through to the name
// parser and be refused with "no secret names given", having asked for none.
// It survived the argument tests because they only assert refusals, and it
// survived the script tests because those drive the script directly. It took
// running the command against a real box to see it, which is the case this
// row replaces.
func TestUnsetPlan(t *testing.T) {
	for _, c := range []struct {
		what                string
		names, keep         string
		list, yes           bool
		want                map[string]string
		wantErrorContaining string
	}{
		{
			what: "list asks the box for names and nothing else",
			list: true,
			want: map[string]string{"APP_NAME": "blog", "LIST": "1"},
		},
		{
			what:  "removing named keys",
			names: "A,B", yes: true,
			want: map[string]string{"APP_NAME": "blog", "NAMES": "A B"},
		},
		{
			what: "keeping named keys sets KEEP, so the box inverts the list",
			keep: "A", yes: true,
			want: map[string]string{"APP_NAME": "blog", "NAMES": "A", "KEEP": "1"},
		},
		{
			what:                "the confirmation names what goes",
			names:               "A,B",
			wantErrorContaining: "removes A, B from",
		},
		{
			what:                "and for --keep it names what stays",
			keep:                "A",
			wantErrorContaining: "removes everything except A from",
		},
	} {
		t.Run(c.what, func(t *testing.T) {
			got, err := unsetPlan("blog", "root@h", c.names, c.keep, c.list, c.yes)
			if c.wantErrorContaining != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErrorContaining) {
					t.Fatalf("expected an error mentioning %q, got %v", c.wantErrorContaining, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestSecretNamesParsing(t *testing.T) {
	got, err := secretNames(" A , B ,, A ,C ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Trimmed, blanks dropped, duplicates dropped, order kept: the order is
	// what the operator reads back in the confirmation message.
	if strings.Join(got, ",") != "A,B,C" {
		t.Fatalf("got %v", got)
	}
	if _, err := secretNames(" , "); err == nil {
		t.Fatal("a list of nothing should not be a valid list")
	}
}

// runUnset drives the real script against a real secrets.env.
//
// The script is what runs as root on somebody's box, and the property that
// matters -- which lines survive -- is not visible in its text.
func runUnset(t *testing.T, env map[string]string, secrets string) (dir, out string, err error) {
	t.Helper()
	needs(t, "sh")
	root := t.TempDir()
	app := filepath.Join(root, "srv", "blog")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "secrets.env"), []byte(secrets), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(scripts.AlpineUnsetSecretScript)
	cmd.Env = append(os.Environ(), "APP_NAME=blog", "APP_DIR="+app)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	b, err := cmd.CombinedOutput()
	return app, string(b), err
}

const fixture = "CLERK_SECRET_KEY=sk_live_x\nRUNTIME_DATABASE_URL=postgres://a:b@db/app\nPB_ADMIN_PASSWORD=old\nOPENAI_API_KEY=sk-old\n"

func keysIn(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "secrets.env"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "="); i > 0 {
			names = append(names, line[:i])
		}
	}
	return strings.Join(names, ",")
}

func TestUnsetSecretRemovesOnlyWhatWasNamed(t *testing.T) {
	dir, out, err := runUnset(t, map[string]string{"NAMES": "PB_ADMIN_PASSWORD OPENAI_API_KEY"}, fixture)
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	if got := keysIn(t, dir); got != "CLERK_SECRET_KEY,RUNTIME_DATABASE_URL" {
		t.Fatalf("wrong keys survived: %s", got)
	}
	// Removing several names rewrites the file once per name. An
	// implementation that re-read the ORIGINAL each pass would reinstate
	// every key but the last one removed, and the count line would still
	// look plausible.
	if !strings.Contains(out, "from 4 to 2 keys") {
		t.Fatalf("expected the before/after count, got:\n%s", out)
	}
}

func TestUnsetSecretKeepsTheNamedOnes(t *testing.T) {
	dir, out, err := runUnset(t, map[string]string{"NAMES": "CLERK_SECRET_KEY", "KEEP": "1"}, fixture)
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	if got := keysIn(t, dir); got != "CLERK_SECRET_KEY" {
		t.Fatalf("wrong keys survived: %s", got)
	}
}

func TestUnsetSecretRefusesAnAbsentName(t *testing.T) {
	dir, out, err := runUnset(t, map[string]string{"NAMES": "PB_ADMIN_PASSWORD NOT_THERE"}, fixture)
	if err == nil {
		t.Fatalf("expected a refusal, got:\n%s", out)
	}
	if !strings.Contains(out, "NOT_THERE") {
		t.Fatalf("the message should name the missing key, got:\n%s", out)
	}
	// A typo must change NOTHING. A partial edit that reports failure is
	// worse than either outcome, because the next attempt starts from a file
	// nobody has looked at.
	if got := keysIn(t, dir); got != "CLERK_SECRET_KEY,RUNTIME_DATABASE_URL,PB_ADMIN_PASSWORD,OPENAI_API_KEY" {
		t.Fatalf("the file was modified despite the refusal: %s", got)
	}
}

func TestUnsetSecretLeavesABackupAndPrintsNoValue(t *testing.T) {
	dir, out, err := runUnset(t, map[string]string{"NAMES": "OPENAI_API_KEY"}, fixture)
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "secrets.env.*.bak"))
	if len(matches) != 1 {
		t.Fatalf("expected one backup, found %v", matches)
	}
	info, err := os.Stat(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup is mode %v, not 0600 -- it holds every secret the app had", info.Mode().Perm())
	}
	// The deleted value must not reach the operator's terminal, their shell
	// history, or a CI log if somebody runs this from one.
	for _, secret := range []string{"sk-old", "sk_live_x", "postgres://a:b@db/app"} {
		if strings.Contains(out, secret) {
			t.Fatalf("the output printed a secret value (%s):\n%s", secret, out)
		}
	}
}

func TestUnsetSecretListReadsNamesOnly(t *testing.T) {
	dir, out, err := runUnset(t, map[string]string{"LIST": "1"}, fixture)
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	for _, name := range []string{"CLERK_SECRET_KEY", "OPENAI_API_KEY"} {
		if !strings.Contains(out, name) {
			t.Fatalf("expected %s in the listing:\n%s", name, out)
		}
	}
	for _, secret := range []string{"sk-old", "sk_live_x"} {
		if strings.Contains(out, secret) {
			t.Fatalf("--list printed a value (%s):\n%s", secret, out)
		}
	}
	if got := keysIn(t, dir); got != "CLERK_SECRET_KEY,RUNTIME_DATABASE_URL,PB_ADMIN_PASSWORD,OPENAI_API_KEY" {
		t.Fatalf("--list changed the file: %s", got)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "secrets.env.*.bak")); len(matches) != 0 {
		t.Fatalf("--list wrote a backup: %v", matches)
	}
}

func TestUnsetSecretScriptIsValidShell(t *testing.T) {
	shellCheck(t, "alpine-unset-secret.sh", scripts.AlpineUnsetSecretScript)
}
