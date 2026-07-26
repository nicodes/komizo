package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nicodes/ncicd"
)

// Operations that touch the server run as tea.Cmds and stream their output
// back as messages, so an apk install does not freeze the interface.

type appsMsg struct {
	apps []appRow
	err  error
}

type runOutputMsg string

type runDoneMsg struct {
	err    error
	result *addResult // set when the operation produced values to paste
}

// addResult is what `add` and `rotate` leave the user with: the two things
// GitHub needs.
type addResult struct {
	app        string
	keyPath    string
	knownHosts string
	rotated    bool
}

func fetchApps(t target) tea.Cmd {
	return func() tea.Msg {
		out, err := t.runCapture(inventoryScript)
		if err != nil {
			return appsMsg{err: fmt.Errorf("could not read the server's inventory: %w", err)}
		}
		apps, _ := parseInventory(out)
		return appsMsg{apps: apps}
	}
}

// runState buffers an operation's output so the view can show it scrolling.
type runState struct {
	title  string
	lines  []string
	ch     chan tea.Msg
	done   bool
	err    error
	result *addResult
}

func newRunState(title string) runState {
	return runState{title: title, ch: make(chan tea.Msg, 256)}
}

func (r *runState) append(s string) {
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		r.lines = append(r.lines, l)
	}
}

// wait blocks on the next chunk of output. Returning it as a Cmd keeps the
// event loop in charge of when we read.
func (r runState) wait() tea.Cmd {
	return func() tea.Msg { return <-r.ch }
}

func (r runState) view(finished bool, height int) string {
	var b strings.Builder
	b.WriteString("\n  " + titleStyle.Render(r.title) + "\n\n")

	// Show the tail; a bootstrap prints more than fits.
	max := height - 12
	if max < 5 {
		max = 5
	}
	start := 0
	if len(r.lines) > max {
		start = len(r.lines) - max
	}
	for _, l := range r.lines[start:] {
		b.WriteString("  " + dimStyle.Render(l) + "\n")
	}

	if !finished {
		b.WriteString("\n  working…\n")
		return b.String()
	}

	if r.err != nil {
		b.WriteString("\n  " + errStyle.Render(r.err.Error()) + "\n")
		b.WriteString(help("enter", "back"))
		return b.String()
	}

	if r.result != nil {
		b.WriteString("\n" + r.result.view())
	} else {
		b.WriteString("\n  " + titleStyle.Render("Done.") + "\n")
	}
	b.WriteString(help("enter", "back"))
	return b.String()
}

func (a addResult) view() string {
	var b strings.Builder
	b.WriteString("  " + titleStyle.Render("Add these to the repo for "+a.app) + "\n")
	b.WriteString(dimStyle.Render("  Settings → Secrets and variables → Actions") + "\n\n")
	b.WriteString("  " + keyStyle.Render("SSH_DEPLOY_KEY") + dimStyle.Render("  (secret)") + "\n")
	b.WriteString(dimStyle.Render("    cat "+a.keyPath) + "\n\n")
	b.WriteString("  " + keyStyle.Render("SSH_KNOWN_HOSTS") + dimStyle.Render("  (variable, not a secret)") + "\n")
	for _, l := range strings.Split(a.knownHosts, "\n") {
		b.WriteString(dimStyle.Render("    "+l) + "\n")
	}
	if a.rotated {
		b.WriteString(warnStyle.Render("\n  The previous key stopped working just now. Update the secret\n" +
			"  before this app's next deploy.\n"))
	} else {
		b.WriteString(dimStyle.Render("\n  Then add app: " + a.app + " to the deploy step in that repo's workflow.\n"))
	}
	return b.String()
}

// stream runs a command, feeding each line back as a message.
func stream(ch chan tea.Msg, c *exec.Cmd, stdin string) error {
	c.Stdin = strings.NewReader(stdin)
	pipe, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	c.Stderr = c.Stdout
	if err := c.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		ch <- runOutputMsg(sc.Text())
	}
	return c.Wait()
}

// These need the run channel, which lives in the model, so they are methods
// rather than free functions returning a Cmd.
func (m model) startAdd(app, config string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		res, err := doAdd(t, app, config, false, ch)
		ch <- runDoneMsg{err: err, result: res}
	}()
	return m.run.wait()
}

func (m model) startRotate(app string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		res, err := doAdd(t, app, "", true, ch)
		ch <- runDoneMsg{err: err, result: res}
	}()
	return m.run.wait()
}

func (m model) startRemove(app string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		env := map[string]string{"APP_NAME": app}
		c := exec.Command("ssh", t.sshArgs(envPrefix(env)+"sh -s")...)
		err := stream(ch, c, ncicd.AlpineRemoveScript)
		ch <- runDoneMsg{err: err}
	}()
	return m.run.wait()
}

// doAdd performs the same sequence as `ncicd add`, reporting progress through
// ch instead of stdout.
func doAdd(t target, app, config string, rotate bool, ch chan tea.Msg) (*addResult, error) {
	user := deriveUser(app)

	if rotate {
		out, err := t.quiet(fmt.Sprintf(
			`sed -n 's/^CONFIG_IMAGE="\(.*\)"$/\1/p' %s 2>/dev/null`, deployBin(app)))
		if err != nil || strings.TrimSpace(out) == "" {
			return nil, fmt.Errorf("could not read the config image for %q off the server", app)
		}
		config = strings.TrimSpace(out)
		ch <- runOutputMsg("keeping the configured image: " + config)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(home, ".ssh", fmt.Sprintf("deploy_%s_%s", app, sanitize(t.host)))

	if rotate || !fileExists(keyPath) {
		if fileExists(keyPath) {
			backup := fmt.Sprintf("%s.replaced.%s", keyPath, time.Now().Format("20060102150405"))
			if err := os.Rename(keyPath, backup); err != nil {
				return nil, err
			}
			_ = os.Rename(keyPath+".pub", backup+".pub")
			ch <- runOutputMsg("previous key kept at " + backup)
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return nil, err
		}
		gen := exec.Command("ssh-keygen", "-q", "-t", "ed25519",
			"-C", fmt.Sprintf("ncicd:%s@%s", user, t.host), "-f", keyPath, "-N", "")
		if out, err := gen.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("ssh-keygen failed: %s", strings.TrimSpace(string(out)))
		}
		ch <- runOutputMsg("generated " + keyPath)
	} else {
		ch <- runOutputMsg("reusing " + keyPath)
	}

	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return nil, err
	}

	env := map[string]string{
		"CI_PUBKEY":    strings.TrimSpace(string(pub)),
		"CI_USER":      user,
		"APP_NAME":     app,
		"CONFIG_IMAGE": config,
		"HARDEN_SSH":   "0",
	}
	c := exec.Command("ssh", t.sshArgs(envPrefix(env)+"sh -s")...)
	if err := stream(ch, c, ncicd.AlpineScript); err != nil {
		return nil, fmt.Errorf("the server-side script failed; nothing further was changed")
	}

	kh, err := readKnownHosts(t)
	if err != nil {
		return nil, err
	}
	return &addResult{app: app, keyPath: keyPath, knownHosts: kh, rotated: rotate}, nil
}

func envPrefix(env map[string]string) string {
	var b strings.Builder
	for _, k := range sortedKeys(env) {
		fmt.Fprintf(&b, "%s='%s' ", k, env[k])
	}
	return b.String()
}
