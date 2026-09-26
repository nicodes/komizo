//go:build linux

package scripts

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// A clerk value that reaches a failure message would be a log. Tests print only
// a redacted copy, and a pty hit is reported without the transcript.
func redactClerk(s string, markers ...string) string {
	for _, m := range markers {
		if m == "" {
			continue
		}
		s = strings.ReplaceAll(s, m, "[redacted]")
	}
	return s
}

func ioctl(f *os.File, req, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), req, arg)
	if errno != 0 {
		return errno
	}
	return nil
}

func openPty() (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int32
	if err := ioctl(master, syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); err != nil {
		master.Close()
		return nil, nil, err
	}
	var n uint32
	if err := ioctl(master, syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

func echoEnabled(f *os.File) (bool, error) {
	var term syscall.Termios
	if err := ioctl(f, syscall.TCGETS, uintptr(unsafe.Pointer(&term))); err != nil {
		return false, err
	}
	return term.Lflag&syscall.ECHO != 0, nil
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type ttyRun struct {
	cmd    *exec.Cmd
	master *os.File
	slave  *os.File
	stdout *lockedBuf
	stderr *lockedBuf
	pty    *lockedBuf

	mu      sync.Mutex
	exited  bool
	waitErr error
	done    chan struct{}
}

func (r *ttyRun) hasExited() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exited
}

func (r *ttyRun) err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.waitErr
}

func provisionTTYFixture(t *testing.T) (scriptPath, candidate, appDir string) {
	t.Helper()
	_, appDir, stateFile, lock, _ := scopedPaths(t)
	writeState(t, stateFile, appDir)
	writeCompose(t, appDir, "services:\n  db:\n    image: pb:1\n")
	candidate = filepath.Join(t.TempDir(), "candidate.yml")
	if err := os.WriteFile(candidate, []byte(pgCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	script := renderScoped(t, fieldsScopedEnvBody, appDir, stateFile, lock)
	scriptPath = filepath.Join(t.TempDir(), "provision")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return scriptPath, candidate, appDir
}

func startTTYProvision(t *testing.T, scriptPath, candidate string) *ttyRun {
	t.Helper()
	master, slave, err := openPty()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		master.Close()
		slave.Close()
	})
	on, err := echoEnabled(slave)
	if err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Fatal("pty started with echo off, so the test cannot prove the script disabled it")
	}
	cmd := exec.Command(scriptPath, "--compose-file", candidate)
	cmd.Env = os.Environ()
	cmd.Stdin = slave
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	run := &ttyRun{
		cmd:    cmd,
		master: master,
		slave:  slave,
		stdout: &lockedBuf{},
		stderr: &lockedBuf{},
		pty:    &lockedBuf{},
		done:   make(chan struct{}),
	}
	go func() { _, _ = io.Copy(run.stdout, stdout) }()
	go func() { _, _ = io.Copy(run.stderr, stderr) }()
	go func() { _, _ = io.Copy(run.pty, master) }()
	go func() {
		err := cmd.Wait()
		run.mu.Lock()
		run.waitErr = err
		run.exited = true
		run.mu.Unlock()
		close(run.done)
	}()
	return run
}

func (r *ttyRun) waitStderr(t *testing.T, needle string, markers ...string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(r.stderr.String(), needle) {
			return
		}
		if r.hasExited() {
			t.Fatalf("provision exited before %s: %s", needle, redactClerk(r.stderr.String(), markers...))
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %s", needle, redactClerk(r.stderr.String(), markers...))
}

func (r *ttyRun) writeLine(t *testing.T, line string) {
	t.Helper()
	if _, err := r.master.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
}

func (r *ttyRun) finish(t *testing.T, timeout time.Duration) error {
	t.Helper()
	select {
	case <-r.done:
		return r.err()
	case <-time.After(timeout):
		_ = r.cmd.Process.Kill()
		t.Fatal("provision timed out")
	}
	return nil
}

func (r *ttyRun) assertNoClerkEcho(t *testing.T, markers ...string) {
	t.Helper()
	// Give the pty reader a moment to drain kernel echo. A hit is not printed.
	time.Sleep(100 * time.Millisecond)
	transcript := r.pty.String()
	for _, m := range markers {
		if m != "" && strings.Contains(transcript, m) {
			t.Fatal("pty echoed a clerk value")
		}
	}
	combined := r.stdout.String() + r.stderr.String()
	for _, m := range markers {
		if m != "" && strings.Contains(combined, m) {
			t.Fatalf("provision printed a clerk value: %s", redactClerk(combined, markers...))
		}
	}
}

func (r *ttyRun) assertEchoRestored(t *testing.T) {
	t.Helper()
	on, err := echoEnabled(r.slave)
	if err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Fatal("terminal echo was left off")
	}
}

func TestTTYClerkEntryDoesNotEchoValues(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required to finish terminal provision")
	}
	issuer := "https://tty-ok-9f3a.example"
	jwks := "https://tty-ok-9f3a.example/jwks"
	parties := "https://app-tty-ok-9f3a.example"
	markers := []string{issuer, jwks, parties, "tty-ok-9f3a", "app-tty-ok-9f3a"}

	scriptPath, candidate, appDir := provisionTTYFixture(t)
	run := startTTYProvision(t, scriptPath, candidate)
	run.waitStderr(t, "CLERK_ISSUER:", markers...)
	run.writeLine(t, issuer)
	run.waitStderr(t, "CLERK_JWKS_URL:", markers...)
	run.writeLine(t, jwks)
	run.waitStderr(t, "CLERK_AUTHORIZED_PARTIES:", markers...)
	run.writeLine(t, parties)

	err := run.finish(t, 30*time.Second)
	run.assertNoClerkEcho(t, markers...)
	run.assertEchoRestored(t)
	if err != nil {
		t.Fatalf("provision failed: %s", redactClerk(run.stderr.String(), markers...))
	}
	out := run.stdout.String()
	if !strings.HasPrefix(out, "generation=") || strings.Count(out, "\n") != 1 {
		t.Fatalf("stdout = %q", out)
	}
	body, err := os.ReadFile(filepath.Join(appDir, "secrets", "current", "api.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "CLERK_ISSUER="+issuer) || !strings.Contains(string(body), "CLERK_JWKS_URL="+jwks) || !strings.Contains(string(body), "CLERK_AUTHORIZED_PARTIES="+parties) {
		t.Fatal("terminal entry was not recorded")
	}
}

func TestTTYClerkEntryRestoresEchoOnRefusal(t *testing.T) {
	issuer := "https://tty-refuse-9f3a.example/$x"
	jwks := "https://tty-refuse-9f3a.example/jwks"
	parties := "https://app-tty-refuse-9f3a.example"
	markers := []string{issuer, jwks, parties, "tty-refuse-9f3a", "app-tty-refuse-9f3a"}

	scriptPath, candidate, appDir := provisionTTYFixture(t)
	run := startTTYProvision(t, scriptPath, candidate)
	run.waitStderr(t, "CLERK_ISSUER:", markers...)
	run.writeLine(t, issuer)
	run.waitStderr(t, "CLERK_JWKS_URL:", markers...)
	run.writeLine(t, jwks)
	run.waitStderr(t, "CLERK_AUTHORIZED_PARTIES:", markers...)
	run.writeLine(t, parties)

	err := run.finish(t, 8*time.Second)
	run.assertNoClerkEcho(t, markers...)
	run.assertEchoRestored(t)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() == 0 {
		t.Fatalf("bad clerk exit = %v, want refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(appDir, "secrets")); !os.IsNotExist(statErr) {
		t.Fatal("refused terminal entry wrote secrets")
	}
}

func TestTTYClerkEntryRestoresEchoOnSignal(t *testing.T) {
	scriptPath, candidate, _ := provisionTTYFixture(t)
	run := startTTYProvision(t, scriptPath, candidate)
	deadline := time.Now().Add(8 * time.Second)
	hidden := false
	for time.Now().Before(deadline) {
		if run.hasExited() {
			t.Fatalf("provision exited before hiding echo: %s", redactClerk(run.stderr.String()))
		}
		on, err := echoEnabled(run.slave)
		if err != nil {
			t.Fatal(err)
		}
		if !on {
			hidden = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !hidden {
		t.Fatal("echo was not disabled")
	}
	if err := run.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err := run.finish(t, 5*time.Second)
	run.assertEchoRestored(t)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 129 {
		t.Fatalf("signal exit = %v, want 129", err)
	}
}
