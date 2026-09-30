package app

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// The task channel: komizo installs the program, the app writes it.
//
// It used to be the other way round. 181 lines of one product's operations --
// its compose project, its service and volume names, the path of a binary
// only it ships -- were compiled into alpine.sh, which is otherwise the
// generic "set an app up" script. The app could not change any of it without
// a komizo release, and komizo carried a per-app special case forever. By the
// time anyone looked, every path in it was stale: the executable it named had
// been deleted and all three volumes belonged to a database the product had
// migrated off, so the whole profile was dead code only komizo could remove.
//
// The tests that used to live here asserted that profile's allow-list, its
// Docker invocation and its audit log. Those are the app's behaviour now and
// belong to the app's own suite; what is komizo's, and what is tested here,
// is the channel: store it, install it root-owned, keep it across updates,
// and let go of it on request.

// taskBox runs just the installer section against a fixture.
type taskBox struct {
	root, store, bin, taskBin, chownLog string
	section                             string
}

func newTaskBox(t *testing.T) *taskBox {
	t.Helper()
	needs(t, "sh")
	root := t.TempDir()
	b := &taskBox{
		root:     root,
		store:    filepath.Join(root, "tasks"),
		bin:      filepath.Join(root, "bin"),
		taskBin:  filepath.Join(root, "task-blog"),
		chownLog: filepath.Join(root, "chown.log"),
	}
	if err := os.MkdirAll(b.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// chown needs root; record the request instead, which is what the
	// assertion is about anyway.
	write(t, filepath.Join(b.bin, "chown"), 0o755,
		"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CHOWN_LOG\"\n")

	b.section = between(t, scripts.AlpineScript,
		"# --- 3c. Named task path ---------------------------------------------------\n",
		`log "Granting '$CI_USER' narrowly scoped doas access"`)
	return b
}

// run drives the section the way alpine.sh reaches it: TASKS already decided
// (that happens near the top of the script, so the state record can say what
// is true), and the script itself supplied or not.
func (b *taskBox) run(t *testing.T, tasks, scriptBody string) (string, error) {
	t.Helper()
	encoded := ""
	if scriptBody != "" {
		encoded = base64.StdEncoding.EncodeToString([]byte(scriptBody))
	}
	preamble := "set -eu\n" +
		"TASK_STORE=" + b.store + "\n" +
		"TASK_FILE=" + filepath.Join(b.store, "blog.sh") + "\n" +
		"TASK_BIN=" + b.taskBin + "\n" +
		"TASKS=\"" + tasks + "\"\n" +
		"TASK_SCRIPT_B64=\"" + encoded + "\"\n" +
		"log() { echo \"$*\"; }\ndie() { echo \"error: $*\" >&2; exit 1; }\n"
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(preamble + b.section)
	cmd.Env = append(os.Environ(), "PATH="+b.bin+":/usr/bin:/bin", "CHOWN_LOG="+b.chownLog)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// The script arrives byte-for-byte. It goes through a shell environment
// assignment, which is why it is base64 -- a task script is shell, full of
// quotes, backslashes and newlines, and every one of them has to survive.
func TestTheTaskScriptArrivesUnchanged(t *testing.T) {
	b := newTaskBox(t)
	const body = "#!/bin/sh\n# a task\nset -eu\nprintf 'a\\tb \"c\" $d `e`\\n'\ncase \"$1\" in\n\tbackup) ;;\nesac\n"
	if out, err := b.run(t, "1", body); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(b.taskBin)
	if err != nil {
		t.Fatalf("nothing was installed: %v", err)
	}
	if string(got) != body {
		t.Errorf("the script changed in transit.\nwant %q\ngot  %q", body, got)
	}
}

// Root-owned and executable, because the deploy account executes it through
// doas and must not be able to edit it.
func TestTheInstalledTaskProgramIsRootOwnedAndExecutable(t *testing.T) {
	b := newTaskBox(t)
	if out, err := b.run(t, "1", "#!/bin/sh\nexit 0\n"); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}
	st, err := os.Stat(b.taskBin)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Errorf("installed program is mode %04o, want 0755", st.Mode().Perm())
	}
	// The stored copy is NOT executable by anyone but root: it is the record
	// of what was reviewed, not a second way to run it.
	stored, err := os.Stat(filepath.Join(b.store, "blog.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Mode().Perm() != 0o700 {
		t.Errorf("stored script is mode %04o, want 0700", stored.Mode().Perm())
	}
	chowns, _ := os.ReadFile(b.chownLog)
	if !strings.Contains(string(chowns), "root:root "+b.taskBin) {
		t.Errorf("the installer never asked for root:root on the program:\n%s", chowns)
	}
}

// An update that supplies no script reinstalls the stored one.
//
// This is the whole reason the box keeps a copy. Without it, every `komizo
// update` -- which runs once per app on every upgrade -- would quietly drop
// the task program, which is the same class of bug as the doas block eating
// hand-added rules.
func TestAnUpdateWithoutAScriptReinstallsTheStoredOne(t *testing.T) {
	b := newTaskBox(t)
	const body = "#!/bin/sh\necho original\n"
	if _, err := b.run(t, "1", body); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(b.taskBin); err != nil {
		t.Fatal(err)
	}
	if out, err := b.run(t, "1", ""); err != nil {
		t.Fatalf("update failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(b.taskBin)
	if err != nil {
		t.Fatalf("the update dropped the task program: %v", err)
	}
	if string(got) != body {
		t.Errorf("the reinstalled program is not the stored one: %q", got)
	}
}

// Revoking takes BOTH copies. A stored script that nothing installs is a
// root-owned file waiting to be re-granted by accident.
func TestRevokingRemovesTheProgramAndTheStoredCopy(t *testing.T) {
	b := newTaskBox(t)
	if _, err := b.run(t, "1", "#!/bin/sh\nexit 0\n"); err != nil {
		t.Fatal(err)
	}
	if out, err := b.run(t, "", ""); err != nil {
		t.Fatalf("revoke failed: %v\n%s", err, out)
	}
	for _, path := range []string{b.taskBin, filepath.Join(b.store, "blog.sh")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s survived a revoke", path)
		}
	}
}

// A file that is not a script is refused, and nothing is installed from it.
func TestAFileWithoutAShebangIsRefused(t *testing.T) {
	b := newTaskBox(t)
	out, err := b.run(t, "1", "not a script\n")
	if err == nil {
		t.Fatalf("a file with no #! line was installed:\n%s", out)
	}
	if _, err := os.Stat(b.taskBin); !os.IsNotExist(err) {
		t.Error("the refused file was installed anyway")
	}
	if _, err := os.Stat(filepath.Join(b.store, "blog.sh")); !os.IsNotExist(err) {
		t.Error("the refused file was stored anyway")
	}
}

// Installing twice produces the same thing.
func TestInstallingTheSameScriptTwiceChangesNothing(t *testing.T) {
	b := newTaskBox(t)
	const body = "#!/bin/sh\nexit 0\n"
	if _, err := b.run(t, "1", body); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(b.taskBin)
	if _, err := b.run(t, "1", body); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(b.taskBin)
	if string(first) != string(second) {
		t.Error("a second install changed the program")
	}
}

// komizo's own provisioning script must not carry one product's operations.
//
// CODE only. Comments in this file cite the incidents the code exists for --
// gdam's previews, cazper's mounted key -- and naming them is the point: a
// rule whose reason is a real failure is one nobody undoes by accident. What
// must never come back is a branch, a path or a volume name belonging to one
// app, which is what 181 lines of alpine.sh used to be.
func TestTheProvisioningScriptNamesNoParticularApp(t *testing.T) {
	for i, line := range strings.Split(scripts.AlpineScript, "\n") {
		code := line
		if trimmed := strings.TrimLeft(line, " \t"); strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Strip a trailing comment on a code line.
		if h := strings.Index(code, " #"); h >= 0 {
			code = code[:h]
		}
		// fieldsofrevik is the ONE remaining exception, and it is the same
		// disease: SCOPED_ENV=fields-postgres-v2 is one app's per-service env
		// layout, compiled into komizo the way the termcade task profile was.
		// It is still in use, so it cannot come out in the change that removes
		// the other one -- it needs the app to take its own profile over
		// first. Listed here rather than left out, so the debt is written
		// down where the rule is, and so nothing NEW joins it.
		if strings.Contains(strings.ToLower(code), "fieldsofrevik") ||
			strings.Contains(code, "fields-postgres-v2") {
			continue
		}
		for _, app := range []string{"termcade", "cazper", "gdam", "astry", "ormos"} {
			if strings.Contains(strings.ToLower(code), app) {
				t.Errorf("alpine.sh:%d names %q in code -- app-specific logic belongs in "+
					"that app's task script, not in the script that sets every app up:\n  %s",
					i+1, app, line)
			}
		}
	}
}
