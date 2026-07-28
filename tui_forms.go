package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// --- adding an app ---------------------------------------------------------

type addForm struct {
	fields  []field
	focus   int
	problem string
}

type field struct {
	label string
	help  string
	value string
	check func(string) error
}

// render shows the value, with a caret only where one can be typed.
func (f field) render(focused bool) string {
	if focused {
		return f.value + barStyle.Render("▏")
	}
	if f.value == "" {
		return dimStyle.Render("—")
	}
	return f.value
}

// renderFields is the shared layout for every form, so they cannot drift apart.
// Only the focused row shows its help, which keeps a three-field form to a
// screenful instead of a wall of grey.
func renderFields(fields []field, focus int) string {
	var b strings.Builder
	for i, fl := range fields {
		caret := "  "
		label := dimStyle.Render(pad(fl.label, 14))
		if i == focus {
			caret = barStyle.Render("▍") + " "
			label = titleStyle.Render(pad(fl.label, 14))
		}
		b.WriteString(gutter + caret + label + " " + fl.render(i == focus) + "\n")
		if i == focus {
			for _, ln := range wrap(fl.help, 62) {
				b.WriteString(gutter + "    " + dimStyle.Render(ln) + "\n")
			}
		}
	}
	return b.String()
}

// The third field is always asked, and that is the fix for a real trap.
//
// Host keys are pinned per NAME: known_hosts is matched on the exact string the
// client dialled, so entries written for one name match nothing when CI dials
// another, and the deploy stops with "no entry for <name>" while the correct
// keys sit in the variable.
//
// This used to be asked only when connected by IP, on the reasoning that a box
// reached by name is already being reached by the name CI uses. That is true of
// exactly one arrangement -- one app, one domain, and you administer it over
// that same domain. It is false the moment a box has an admin name of its own:
// connect as komizo.example.com to set up an app CI deploys to app.example.com,
// and the interface offered no way to say so at all.
//
// So it is always here, blank means "no others", and either kind of address
// works on both sides.
func newAddForm(t target) addForm {
	help := "optional. Other names CI connects by, comma-separated — host keys are pinned per name, so a name missing here fails the deploy."
	if t.isIP() {
		help = "the domain CI connects by, if it is not this address — host keys are pinned per name. Comma-separated for more than one."
	}
	return addForm{fields: []field{
		{
			label: "app name",
			help:  "letters, digits, underscore, hyphen. Names its directory, account and commands.",
			check: validateApp,
		},
		{
			label: "config image",
			help:  "registry path with NO tag, e.g. ghcr.io/you/blog-config. Where the host reads compose.yml from.",
			check: validateConfigImage,
		},
		{
			label: "known as",
			help:  help,
			check: validateKnownAs,
		},
	}}
}

// validateKnownAs checks a comma-separated list of extra hostnames. Empty is
// fine: most boxes are reached by one name.
func validateKnownAs(s string) error {
	for _, h := range splitNames(s) {
		if err := validateHost(h); err != nil {
			return err
		}
	}
	return nil
}

// mergeNames adds names not already present, preserving order. Adding a second
// app on the same box should not repeat the first one's aliases.
func mergeNames(have, add []string) []string {
	seen := map[string]bool{}
	for _, h := range have {
		seen[h] = true
	}
	for _, h := range add {
		if !seen[h] {
			seen[h] = true
			have = append(have, h)
		}
	}
	return have
}

// splitNames turns "a.example.com, b.example.com" into its parts, dropping
// blanks so a trailing comma is not an error.
func splitNames(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// knownAs is the extra hostnames, if any were given.
func (f addForm) knownAs() []string { return splitNames(f.fields[2].value) }

func (f addForm) app() string    { return strings.TrimSpace(f.fields[0].value) }
func (f addForm) config() string { return strings.TrimSpace(f.fields[1].value) }

// trustPrompt asks whether to add a host key to known_hosts, with the
// fingerprints beside the question.
//
// The same trust ssh asks for on a first connection, and asked the same way --
// except that komizo puts the fingerprints next to the question instead of
// making you run a second command to see them. They came off the network and
// nothing has verified them, which is exactly why the question exists.
func (m model) trustPrompt(msg connectMsg) prompt {
	detail := "These came from the network, not from the server's own /etc/ssh. " +
		"Compare them against your provider's console before accepting."
	for _, ln := range msg.fp {
		detail += "\n" + ln
	}
	scan, tgt := msg.scan, msg.tgt
	return prompt{
		question: "Trust the host key for " + tgt.host + "?",
		detail:   detail,
		action: func(m *model, _ string) tea.Cmd {
			if _, err := writeKnownHosts(scan); err != nil {
				m.status, m.statusErr = err.Error(), true
				return nil
			}
			return m.beginLoading(connect(tgt))
		},
	}
}

// addPrompt is the add form, asked in the footer with the list still behind it.
func (m model) addPrompt() prompt {
	return prompt{
		kind:     promptForm,
		question: "Add an app",
		detail: "A deploy keypair is generated on this machine; only the public " +
			"half is sent. Safe to run again on an app that already exists.",
	}
}

func (m model) handleFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := &m.form
	switch msg.String() {
	case "esc":
		m.prompt = nil
		return m, nil
	case "tab", "down":
		f.focus = (f.focus + 1) % len(f.fields)
	case "shift+tab", "up":
		f.focus = (f.focus - 1 + len(f.fields)) % len(f.fields)
	case "enter":
		if f.focus < len(f.fields)-1 {
			f.focus++
			return m, nil
		}
		for i := range f.fields {
			if err := f.fields[i].check(strings.TrimSpace(f.fields[i].value)); err != nil {
				f.problem = err.Error()
				f.focus = i
				return m, nil
			}
		}
		// Recorded on the target, not just passed to the operation, so the
		// server screen keeps showing the complete SSH_KNOWN_HOSTS afterwards.
		// It used to be handed to the add alone, which meant the one screen
		// meant to be the durable home for that value silently gave a shorter
		// answer than the add had just printed.
		m.tgt.aliases = mergeNames(m.tgt.aliases, f.knownAs())
		// Adding an app is not destructive, so it runs without a confirmation
		// step -- re-running it on an existing app is how you repair one.
		m.prompt = nil
		return m, tea.Batch(
			m.startOp(fmt.Sprintf("Setting up %q", f.app())),
			m.startAdd(f.app(), f.config()))
	case "backspace":
		v := f.fields[f.focus].value
		if v != "" {
			f.fields[f.focus].value = v[:len(v)-1]
		}
		f.problem = ""
	default:
		if s := msg.String(); len(s) == 1 {
			f.fields[f.focus].value += s
			f.problem = ""
		}
	}
	return m, nil
}

// --- the shared reverse proxy ----------------------------------------------

// --- setting the server up -------------------------------------------------

// A fresh box gets a statement and one decision, not a form.
//
// It asked two questions once -- the network name, then whether to install the
// proxy. Both are gone. The network is the worst possible thing to decide on a
// server with nothing on it, and the proxy is what every app on the box is
// reached through, so "no" only meant finding out later. It is always
// installed; stopping it afterwards is one keypress on the server screen.

func (m model) handleSetupKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "ctrl+c":
		return m, tea.Quit
	case "enter":
		// Straight to the loading screen. What is about to be installed was
		// worth reading while it was a decision; once it is running, the only
		// thing anyone wants from the page is whether it is still going -- and
		// leaving the description up behind a spinner reads as though it is
		// still asking. The box is re-read when it finishes, and that read
		// decides where you land: the monitor, or back here if it did not take.
		cmd := m.startOp("Setting up " + m.tgt.host)
		m.scr = screenLoading
		return m, tea.Batch(cmd,
			m.startInit(initOpts{network: defaultNetwork, image: defaultProxy}))
	}
	return m, nil
}

// viewSetup is what a fresh box gets: a statement of what is about to be
// installed, centred, and one key.
//
// Centred to match the two other pages that are one thing on an empty screen --
// the login field and the loading pane. It was written flush left like the
// monitor, which is a list of many things and reads as one; this is a single
// paragraph with a decision at the end of it, and a wall of text pinned to the
// left margin of an otherwise blank page reads as an error report.
//
// The rows are padded to a common width before they are centred, so the block
// keeps a left edge. Centring each line by its own length would stagger the
// three descriptions and lose the column.
func (m model) viewSetup() string {
	rows := [][2]string{
		{"docker", "the container runtime, enabled at boot"},
		{defaultNetwork, "the network apps share to reach each other"},
		{"caddy", "one reverse proxy, terminating HTTPS for every app"},
	}
	var block []string
	for _, r := range rows {
		block = append(block, dimStyle.Render(pad(r[0], 8))+"  "+dimStyle.Render(r[1]))
	}

	lines := []string{titleStyle.Render("This server is not set up yet"), ""}
	if m.srv.state == "docker-stopped" {
		lines = append(lines,
			dot("warn")+" "+warnStyle.Render("Docker is installed but not running; continuing starts it"),
			"")
	}
	lines = append(lines, dimStyle.Render("Setting it up installs"), "")
	lines = append(lines, alignBlock(block)...)
	lines = append(lines, "")
	lines = append(lines, alignBlock([]string{
		dimStyle.Render("No accounts, and nothing under /srv — that comes later, when"),
		dimStyle.Render("you add an app. Safe to re-run; it also updates Docker."),
	})...)
	return m.centred(lines...)
}

// --- the prompts, shared -----------------------------------------------------
//
// Both the list and the detail screen offer rotate and remove. They were
// written out at the call site once, which is how the detail screen came to
// advertise two keys it did not handle: the help line was copied, the handler
// was not.

func (m model) rotatePrompt(a appRow) prompt {
	q := fmt.Sprintf("Rotate the deploy key for %q?", a.name)
	return prompt{
		question: q,
		detail: "The current key stops working immediately — update SSH_DEPLOY_KEY " +
			"before this app's next deploy.",
		action: func(m *model, _ string) tea.Cmd {
			return tea.Batch(
				m.startOp("Rotating the deploy key for "+a.name),
				m.startRotate(a.name))
		},
	}
}

func (m model) removePrompt(a appRow) prompt {
	// Names the host. The header used to carry it on every screen; now that it
	// does not, the most destructive prompt has to say which box it means
	// rather than "this server".
	q := fmt.Sprintf("Remove %q from %s?", a.name, m.tgt.host)
	return prompt{
		kind:     promptTypeWord,
		word:     a.name,
		question: q,
		detail: "Deletes " + a.dir + ", its volumes, the account " + a.user +
			" and its rules. Images stay in your registry. Cannot be undone.",
		action: func(m *model, _ string) tea.Cmd {
			return tea.Batch(m.startOp("Removing "+a.name), m.startRemove(a.name))
		},
	}
}

// --- changing which config image an app trusts -------------------------------
//
// The pin is the trust anchor: root decides where the host will accept config
// from, and CI cannot override it. That is exactly why it needs an obvious way
// to be changed -- a wrong value fails at deploy time as "not found" from the
// registry, which reads like a build problem rather than a setting on the box.
//
// An input in the footer rather than a form of its own. It is one value, it is
// already on the app's row two lines above, and editing it in place means you
// can see what you are changing it from.
func (m model) configPrompt(a appRow) prompt {
	return prompt{
		kind:     promptInput,
		question: "Config image for " + a.name,
		detail:   "Registry path with NO tag — the deploy supplies that.",
		typed:    a.image,
		check:    validateConfigImage,
		action: func(m *model, v string) tea.Cmd {
			// Unchanged is not a no-op worth running: re-running setup would
			// reinstall everything to arrive back where it started.
			if v == a.image {
				return nil
			}
			return tea.Batch(m.startOp("Pointing "+a.name+" at "+v), m.startConfigChange(a.name, v))
		},
	}
}
