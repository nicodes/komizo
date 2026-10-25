//go:build linux || darwin

package devenv

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProcessGroupCleanup(t *testing.T) {
	for _, mode := range []string{"signal", "leader-exits"} {
		t.Run(mode, func(t *testing.T) {
			ready := filepath.Join(t.TempDir(), "descendant.pid")
			cmd := exec.Command(os.Args[0], "-test.run=^TestProcessGroupHelper$")
			cmd.Env = commandEnvironment(os.Environ(), map[string]string{"GHENV_GROUP_ROLE": "supervisor", "GHENV_GROUP_READY": ready, "GHENV_GROUP_MODE": mode})
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
			var descendant int
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if data, err := os.ReadFile(ready); err == nil {
					descendant, _ = strconv.Atoi(string(data))
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if descendant < 1 {
				t.Fatal("descendant did not become ready")
			}
			defer syscall.Kill(descendant, syscall.SIGKILL)
			if mode == "signal" {
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			wait := make(chan error, 1)
			go func() { wait <- cmd.Wait() }()
			select {
			case err := <-wait:
				if err != nil {
					t.Fatalf("supervisor failed: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("supervisor did not finish bounded cleanup")
			}
			for time.Now().Before(deadline) {
				if !runningProcess(descendant) {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("SIGTERM-ignoring descendant survived group cleanup")
		})
	}
}

func runningProcess(pid int) bool {
	if runtime.GOOS == "darwin" {
		output, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
		return err == nil && len(strings.TrimSpace(string(output))) > 0 && !strings.HasPrefix(strings.TrimSpace(string(output)), "Z")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	_, suffix, _ := strings.Cut(string(data), ") ")
	return !strings.HasPrefix(suffix, "Z ") && !strings.HasPrefix(suffix, "X ")
}

func TestProcessGroupHelper(t *testing.T) {
	switch os.Getenv("GHENV_GROUP_ROLE") {
	case "terminal":
		err := launchWithGrace([]string{"sh", "-c", `IFS= read -r line; test "$line" = synthetic-input`}, nil, 250*time.Millisecond)
		if err != nil {
			os.Exit(7)
		}
		group, err := terminalGroup(os.Stdin.Fd(), syscall.TIOCGPGRP, 0)
		if err != nil || group != int32(syscall.Getpgrp()) {
			os.Exit(8)
		}
		os.Exit(0)
	case "supervisor":
		_ = launchWithGrace([]string{os.Args[0], "-test.run=^TestProcessGroupHelper$"}, map[string]string{"GHENV_GROUP_ROLE": "wrapper", "TOKEN": "synthetic-only"}, 250*time.Millisecond)
		os.Exit(0)
	case "wrapper":
		child := exec.Command(os.Args[0], "-test.run=^TestProcessGroupHelper$")
		child.Env = commandEnvironment(os.Environ(), map[string]string{"GHENV_GROUP_ROLE": "descendant"})
		if err := child.Start(); err != nil {
			os.Exit(3)
		}
		if os.Getenv("GHENV_GROUP_MODE") == "leader-exits" {
			for {
				if _, err := os.Stat(os.Getenv("GHENV_GROUP_READY")); err == nil {
					os.Exit(0)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		time.Sleep(time.Hour)
	case "descendant":
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT)
		if os.Getenv("TOKEN") != "synthetic-only" {
			os.Exit(4)
		}
		if err := os.WriteFile(os.Getenv("GHENV_GROUP_READY"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(5)
		}
		time.Sleep(time.Hour)
	default:
		return
	}
	os.Exit(0)
}

func TestForegroundTerminal(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed for the pseudoterminal regression test")
	}
	script := `import os, pty, select, signal, sys, time
pid, fd = pty.fork()
if pid == 0:
    role = 'terminal' if sys.argv[2] == 'input' else 'supervisor'
    env = dict(os.environ, GHENV_GROUP_ROLE=role, GHENV_GROUP_MODE='signal')
    os.execve(sys.argv[1], [sys.argv[1], '-test.run=^TestProcessGroupHelper$'], env)
done = False
try:
    if sys.argv[2] == 'input':
        os.write(fd, b'synthetic-input\n')
    else:
        deadline = time.monotonic() + 8
        while not os.path.exists(os.environ['GHENV_GROUP_READY']):
            if time.monotonic() >= deadline: raise RuntimeError('descendant not ready')
            time.sleep(0.01)
        os.write(fd, b'\x03')
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        ended, status = os.waitpid(pid, os.WNOHANG)
        if ended:
            done = True
            sys.exit(os.waitstatus_to_exitcode(status))
        ready, _, _ = select.select([fd], [], [], 0.05)
        if ready:
            try: os.read(fd, 4096)
            except OSError: pass
    raise RuntimeError('interactive child did not read foreground terminal input')
finally:
    os.close(fd)
    if not done:
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
        os.waitpid(pid, 0)
`
	for _, mode := range []string{"input", "ctrl-c"} {
		t.Run(mode, func(t *testing.T) {
			ready := filepath.Join(t.TempDir(), "descendant.pid")
			cmd := exec.Command(python, "-c", script, os.Args[0], mode)
			cmd.Env = commandEnvironment(os.Environ(), map[string]string{"GHENV_GROUP_READY": ready})
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("foreground terminal regression: %v\n%s", err, output)
			}
			if mode == "ctrl-c" {
				data, err := os.ReadFile(ready)
				if err != nil {
					t.Fatal(err)
				}
				pid, _ := strconv.Atoi(string(data))
				if runningProcess(pid) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatal("foreground Ctrl-C left a descendant running")
				}
			}
		})
	}
}
