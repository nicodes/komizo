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
)

// Operations that touch the server run as tea.Cmds and stream their output
// back as messages, so an apk install does not freeze the interface.

type appsMsg struct {
	apps  []appRow
	srv   serverRow
	proxy proxyRow
	net   netRow
	err   error
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

	// Both values have to reach GitHub, so both are selectable and both are
	// copyable.
	//
	// onClipboard is which one is there NOW, not which have ever been copied.
	// There is one clipboard: ticking every value that had been copied at some
	// point claimed two things were on it at once, and read as the mark being
	// stuck to the first row.
	cursor      int
	onClipboard int // index, or -1 for nothing
	copyErr     string

	// Set when this was a config-image change rather than a fresh setup: the
	// GitHub values are unchanged, so telling someone to paste them again
	// would be wrong.
	changedConfig string
}

// The two things this screen exists to hand over, in the order you paste them.
const (
	resultKey = iota
	resultHosts
	resultItems
)

// value returns what the cursor is pointing at. The key is a path, because its
// contents must not be held anywhere that might later be rendered.
// items is how many rows this result offers. A rotation offers one: the host
// keys did not change, so presenting them as something to copy would imply
// otherwise.
func (a addResult) items() int {
	if a.rotated {
		return 1
	}
	return resultItems
}

func (a addResult) copySelected() error {
	if a.cursor == resultKey {
		return copyFileToClipboard(a.keyPath)
	}
	return copyToClipboard(a.knownHosts + "\n")
}

func fetchApps(t target) tea.Cmd {
	return func() tea.Msg {
		out, err := t.runCapture(inventoryScript)
		if err != nil {
			return appsMsg{err: fmt.Errorf("could not read the server's inventory: %w", err)}
		}
		apps, srv, proxy, net, _ := parseInventory(out)
		return appsMsg{apps: apps, srv: srv, proxy: proxy, net: net}
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
	b.WriteString("\n" + gutter + titleStyle.Render(r.title) + "\n\n")

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
		b.WriteString(gutter + dimStyle.Render(l) + "\n")
	}

	if !finished {
		b.WriteString("\n" + gutter + barStyle.Render("▍") + dimStyle.Render(" working…") + "\n")
		return b.String()
	}

	if r.err != nil {
		b.WriteString("\n" + gutter + dot("err") + " " + errStyle.Render(r.err.Error()) + "\n")
		b.WriteString(help("enter", "back"))
		return b.String()
	}

	if r.result != nil {
		b.WriteString("\n" + r.result.view())
		if clipboardAvailable() {
			b.WriteString(help("↑↓", "select", "c", "copy", "enter", "back"))
			return b.String()
		}
	} else {
		b.WriteString("\n" + gutter + dot("ok") + " " + titleStyle.Render("Done") + "\n")
	}
	b.WriteString(help("enter", "back"))
	return b.String()
}

func (a addResult) view() string {
	var b strings.Builder
	if a.changedConfig != "" {
		b.WriteString(gutter + dot("ok") + " " + titleStyle.Render(a.app+" now reads its config from") + "\n")
		b.WriteString(gutter + "  " + a.changedConfig + "\n")
		b.WriteString(para("\n"+gutter, "Nothing in GitHub changed -- the deploy key and host keys are the\n"+
			"same. The next deploy pulls config from here."))
		return b.String()
	}
	b.WriteString(gutter + dot("ok") + " " + titleStyle.Render("Add these to the repo for "+a.app) + "\n")
	b.WriteString(dimStyle.Render(gutter+"  Settings → Secrets and variables → Actions") + "\n")

	// --- 1. the deploy key ---------------------------------------------------
	// The VALUE is the file's contents, and they are deliberately not shown:
	// this screen ends up in screenshots and scrollback. Spelled out because a
	// bare path under the name reads like a value.
	b.WriteString(a.row(resultKey, "SSH_DEPLOY_KEY", dimStyle.Render("secret")))
	b.WriteString(gutter + "      " + dimStyle.Render("the private key in this file, contents not shown:") + "\n")
	b.WriteString(gutter + "      " + a.keyPath + "\n")

	// --- 2. the host keys ----------------------------------------------------
	// Rotating replaces the deploy KEYPAIR. The server's host keys are its own
	// and are untouched, so offering them here would say that something else
	// needs updating in GitHub when nothing does. They stay one keypress away
	// on the server screen.
	if a.rotated {
		b.WriteString(para("\n"+gutter, "SSH_KNOWN_HOSTS is unchanged — the server's own keys did not\n"+
			"move. Press k on the server screen if you need it again."))
	} else {
		// Shown in full, unlike the key: a host key needs integrity, not
		// secrecy, and masking it makes a mismatch unreadable in a CI log.
		b.WriteString(a.row(resultHosts, "SSH_KNOWN_HOSTS", dimStyle.Render("variable, not a secret")))
		for _, l := range strings.Split(a.knownHosts, "\n") {
			b.WriteString(gutter + "      " + dimStyle.Render(l) + "\n")
		}
	}

	if a.copyErr != "" {
		b.WriteString("\n" + gutter + dot("warn") + " " + warnStyle.Render(a.copyErr) + "\n")
		b.WriteString(para(gutter+"  ", "cat "+a.keyPath))
	}

	if a.rotated {
		b.WriteString("\n" + gutter + dot("warn") + " " + warnStyle.Render(
			"the previous key stopped working just now") + "\n")
		b.WriteString(para(gutter+"  ", "Update the secret before this app's next deploy."))
	} else {
		b.WriteString("\n" + para(gutter, "Then add app: "+a.app+" to the deploy step in that repo's workflow."))
	}
	return b.String()
}

// row renders one selectable value, marked the same way the app list marks its
// selection, with a tick once it has been copied.
func (a addResult) row(i int, name, kind string) string {
	caret, label := "  ", keyStyle.Render(name)
	if a.cursor == i {
		caret = barStyle.Render("▍") + " "
		label = keyStyle.Render(name)
	}
	mark := ""
	if a.onClipboard == i {
		mark = "  " + okStyle.Render("← on the clipboard")
	}
	return "\n" + gutter + caret + label + "  " + kind + mark + "\n"
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
func (m model) startAdd(app, config, knownAs string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	if knownAs != "" {
		t.aliases = append(t.aliases, knownAs)
	}
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

// startInit prepares the server, then optionally the proxy. Two scripts rather
// than one, streamed to the same screen: the proxy is a choice, and a box whose
// Docker install worked but whose proxy did not is still a usable server.
func (m model) startInit(o initOpts) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		c := exec.Command("ssh", t.sshArgs(envPrefix(map[string]string{"SHARED_NETWORK": o.network})+"sh -s")...)
		if err := stream(ch, c, AlpineInitScript); err != nil {
			ch <- runDoneMsg{err: fmt.Errorf("could not set the server up -- see the output above")}
			return
		}
		ch <- runOutputMsg("")
		ch <- runOutputMsg("installing the shared reverse proxy...")
		pc := exec.Command("ssh", t.sshArgs(envPrefix(proxyEnv(proxyOpts{
			network: o.network, image: o.image,
		}))+"sh -s")...)
		if err := stream(ch, pc, AlpineProxyScript); err != nil {
			ch <- runDoneMsg{err: fmt.Errorf("the server is ready, but the proxy failed -- press s to retry it")}
			return
		}
		ch <- runDoneMsg{}
	}()
	return m.run.wait()
}

// startProxy installs or updates the one shared reverse proxy. Not destructive
// and not app-scoped, so it needs no confirmation step -- re-running it is how
// you update Caddy or move it to another network.
func (m model) startProxy(o proxyOpts) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		c := exec.Command("ssh", t.sshArgs(envPrefix(proxyEnv(o))+"sh -s")...)
		err := stream(ch, c, AlpineProxyScript)
		ch <- runDoneMsg{err: err}
	}()
	return m.run.wait()
}

// startConfigChange re-points an app at a different config image. Re-running
// the setup script is what applies it -- the same operation as adding, which is
// why the key is reused rather than replaced: doAdd only generates one when the
// file is absent.
func (m model) startConfigChange(app, config string) tea.Cmd {
	ch := m.run.ch
	t := m.tgt
	go func() {
		res, err := doAdd(t, app, config, false, ch)
		if res != nil {
			res.changedConfig = config
		}
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
		err := stream(ch, c, AlpineRemoveScript)
		ch <- runDoneMsg{err: err}
	}()
	return m.run.wait()
}

// doAdd performs the same sequence as `komizo add`, reporting progress through
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
			"-C", fmt.Sprintf("komizo:%s@%s", user, t.host), "-f", keyPath, "-N", "")
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
	if err := stream(ch, c, AlpineScript); err != nil {
		return nil, fmt.Errorf("the server-side script failed; nothing further was changed")
	}

	kh, err := readKnownHosts(t)
	if err != nil {
		return nil, err
	}
	return &addResult{app: app, keyPath: keyPath, knownHosts: kh, rotated: rotate,
		onClipboard: -1}, nil
}

func envPrefix(env map[string]string) string {
	var b strings.Builder
	for _, k := range sortedKeys(env) {
		fmt.Fprintf(&b, "%s='%s' ", k, env[k])
	}
	return b.String()
}
