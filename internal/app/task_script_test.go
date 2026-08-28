package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// task-termcade is a root/Docker boundary. These tests execute the generated
// program with Docker and timeout replaced, so every assertion is reachable
// without granting the test process either privilege.
type taskBox struct {
	root, bin, audit, log, script string
}

func newTaskBox(t *testing.T) *taskBox {
	t.Helper()
	root := t.TempDir()
	b := &taskBox{
		root:  root,
		bin:   filepath.Join(root, "bin"),
		audit: filepath.Join(root, "log", "tasks.log"),
		log:   filepath.Join(root, "calls.log"),
	}
	for _, d := range []string{b.bin, filepath.Join(root, "srv", "termcade")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	body := between(t, scripts.AlpineScript,
		`cat > "$TASK_BIN.tmp" <<'KOMIZO_TASK_EOF'`, "KOMIZO_TASK_EOF")
	b.script = strings.NewReplacer(
		"/srv/termcade/compose.yml", filepath.Join(root, "srv", "termcade", "compose.yml"),
		"/srv/termcade", filepath.Join(root, "srv", "termcade"),
		"/var/log/komizo/tasks.log", b.audit,
		"/var/log/komizo", filepath.Join(root, "log"),
		"/run/komizo/task-termcade.lock", filepath.Join(root, "run", "task-termcade.lock"),
		"/run/komizo", filepath.Join(root, "run"),
	).Replace(body)
	write(t, filepath.Join(b.root, "srv", "termcade", "compose.yml"), 0o600, "services: {}\n")
	write(t, filepath.Join(b.bin, "chown"), 0o755, "#!/bin/sh\nexit 0\n")
	write(t, filepath.Join(b.bin, "docker"), 0o755, `#!/bin/sh
printf 'docker %s\n' "$*" >> "$STUB_CALLS"
if [ "$1" = compose ]; then
  for arg in "$@"; do
    [ "$arg" = images ] && { echo sha256:fixed-image; exit 0; }
  done
  printf '%s\n' "${STUB_TASK_OUTPUT:-safe output}"
  exit "${STUB_RUN_RC:-0}"
fi
exit 0
`)
	write(t, filepath.Join(b.bin, "timeout"), 0o755, `#!/bin/sh
printf 'timeout %s\n' "$*" >> "$STUB_CALLS"
[ -z "${STUB_TIMEOUT_RC:-}" ] || exit "$STUB_TIMEOUT_RC"
shift 5
exec "$@"
`)
	return b
}

func (b *taskBox) run(args []string, extra ...string) (string, int) {
	cmd := exec.Command("sh", append([]string{"-s"}, args...)...)
	cmd.Stdin = strings.NewReader(b.script)
	cmd.Env = append(os.Environ(), append([]string{
		"PATH=" + b.bin + ":/usr/bin:/bin",
		"STUB_CALLS=" + b.log,
		"DOAS_USER=komizo-termcade",
	}, extra...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	return string(out), err.(*exec.ExitError).ExitCode()
}

func TestTaskWrapperExactAllowlistAndFixedInvocation(t *testing.T) {
	b := newTaskBox(t)
	for _, mode := range []string{"dry-run", "apply", "constrain"} {
		if out, rc := b.run([]string{"release-identity-backfill", mode}); rc != 0 {
			t.Fatalf("allowed mode %q failed rc=%d: %s", mode, rc, out)
		}
	}
	calls, err := os.ReadFile(b.log)
	if err != nil {
		t.Fatal(err)
	}
	got := string(calls)
	for _, want := range []string{
		"timeout -s TERM -k 30 900 docker compose",
		"run --rm --no-deps -T --name termcade-komizo-task api /usr/local/bin/termcade-backfill dry-run",
		"run --rm --no-deps -T --name termcade-komizo-task api /usr/local/bin/termcade-backfill apply",
		"run --rm --no-deps -T --name termcade-komizo-task api /usr/local/bin/termcade-backfill constrain",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fixed invocation missing %q from:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{" sh -c ", " eval ", " --env ", " --volume ", " --entrypoint "} {
		if strings.Contains(" "+b.script+" ", forbidden) {
			t.Errorf("task template contains forbidden command surface %q", forbidden)
		}
	}
}

func TestTaskWrapperRejectsMalformedInputsBeforeDocker(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing", nil},
		{"one", []string{"release-identity-backfill"}},
		{"extra", []string{"release-identity-backfill", "dry-run", "extra"}},
		{"unknown task", []string{"other", "dry-run"}},
		{"unknown mode", []string{"release-identity-backfill", "other"}},
		{"path", []string{"release-identity-backfill", "/bin/sh"}},
		{"image", []string{"release-identity-backfill", "ghcr.io/evil/image"}},
		{"service", []string{"release-identity-backfill", "db"}},
		{"environment", []string{"release-identity-backfill", "X=1"}},
		{"shell", []string{"release-identity-backfill", "dry-run;id"}},
		{"control", []string{"release-identity-backfill", "dry-run\napply"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newTaskBox(t)
			if out, rc := b.run(tc.args); rc != 64 {
				t.Fatalf("malformed input reached rc=%d, want 64: %s", rc, out)
			}
			if _, err := os.Stat(b.log); !os.IsNotExist(err) {
				t.Fatalf("Docker/timeout was reached before rejection: %v", err)
			}
		})
	}
}

func TestTaskWrapperPropagatesExitAndTimeoutAndCleansUp(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		rc   int
	}{
		{"child exit", "STUB_RUN_RC=23", 23},
		{"timeout", "STUB_TIMEOUT_RC=124", 124},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newTaskBox(t)
			if out, rc := b.run([]string{"release-identity-backfill", "dry-run"}, tc.env); rc != tc.rc {
				t.Fatalf("got rc=%d, want %d: %s", rc, tc.rc, out)
			}
			if _, err := os.Stat(filepath.Join(b.root, "run", "task-termcade.lock")); !os.IsNotExist(err) {
				t.Fatalf("task lock survived failure: %v", err)
			}
			calls, _ := os.ReadFile(b.log)
			if !strings.Contains(string(calls), "docker rm -f termcade-komizo-task") {
				t.Errorf("fixed container cleanup did not run:\n%s", calls)
			}
			audit, _ := os.ReadFile(b.audit)
			if !strings.Contains(string(audit), "result="+strings.TrimPrefix(tc.env, strings.Split(tc.env, "=")[0]+"=")) {
				t.Errorf("audit did not record propagated result:\n%s", audit)
			}
		})
	}
}

func TestTaskAuditIsNonSensitiveAndActorIsSanitized(t *testing.T) {
	b := newTaskBox(t)
	secret := "credential-must-not-enter-audit"
	if out, rc := b.run([]string{"release-identity-backfill", "dry-run"},
		"DOAS_USER=bad actor\nforged=1", "STUB_TASK_OUTPUT="+secret); rc != 0 {
		t.Fatalf("rc=%d: %s", rc, out)
	}
	audit, err := os.ReadFile(b.audit)
	if err != nil {
		t.Fatal(err)
	}
	got := string(audit)
	for _, want := range []string{"actor=unknown", "app=termcade", "task=release-identity-backfill", "mode=dry-run", "image=sha256:fixed-image", "result=0"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, secret) || strings.Contains(got, "forged=1") {
		t.Errorf("task output or injected audit fields leaked into audit:\n%s", got)
	}
}

func TestTaskInstallerIsRootOwnedMode755AndIdempotent(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	chownLog := filepath.Join(root, "chown.log")
	write(t, filepath.Join(bin, "chown"), 0o755, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CHOWN_LOG\"\n")
	section := between(t, scripts.AlpineScript, `if [ "$TASKS" = "release-identity-backfill" ]; then`, `log "Granting '$CI_USER' narrowly scoped doas access"`)
	section = "if [ \"$TASKS\" = \"release-identity-backfill\" ]; then\n" + section
	taskBin := filepath.Join(root, "task-termcade")
	run := func(tasks string) {
		cmd := exec.Command("sh", "-s")
		cmd.Stdin = strings.NewReader("set -eu\nTASKS=" + tasks + "\nTASK_BIN=" + taskBin + "\nlog() { :; }\ndie() { exit 1; }\n" + section)
		cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "CHOWN_LOG="+chownLog)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("installer failed: %v\n%s", err, out)
		}
	}
	run("release-identity-backfill")
	first, err := os.ReadFile(taskBin)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(taskBin)
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("wrapper mode=%o, want 755", st.Mode().Perm())
	}
	run("release-identity-backfill")
	second, _ := os.ReadFile(taskBin)
	if string(first) != string(second) {
		t.Fatal("second install changed generated wrapper")
	}
	chowns, _ := os.ReadFile(chownLog)
	if !strings.Contains(string(chowns), "root:root "+taskBin) {
		t.Fatalf("installer did not request root:root ownership:\n%s", chowns)
	}
	run("")
	if _, err := os.Stat(taskBin); !os.IsNotExist(err) {
		t.Fatalf("explicit revocation left wrapper installed: %v", err)
	}
}
