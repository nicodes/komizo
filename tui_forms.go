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

func (m model) handleFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := &m.form
	switch msg.String() {
	case "esc":
		m.scr = screenList
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
		m.scr = screenRunning
		m.run = newRunState(fmt.Sprintf("Setting up %q", f.app()))
		return m, m.startAdd(f.app(), f.config())
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

func (f addForm) view() string {
	var b strings.Builder
	b.WriteString("\n" + gutter + titleStyle.Render("Add an app") + "\n\n")
	b.WriteString(renderFields(f.fields, f.focus))
	if f.problem != "" {
		b.WriteString("\n" + gutter + dot("err") + " " + errStyle.Render(f.problem) + "\n")
	}
	b.WriteString("\n" + para(gutter, "A deploy keypair is generated on this machine; only the public half\nis sent. Safe to run again on an app that already exists."))
	b.WriteString(help("tab", "next field", "enter", "confirm", "esc", "cancel"))
	return b.String()
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

func (m model) handleInitKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "ctrl+c":
		return m, tea.Quit
	case "enter":
		m.scr = screenRunning
		m.run = newRunState("Setting up " + m.tgt.host)
		return m, m.startInit(initOpts{network: defaultNetwork, image: defaultProxy})
	}
	return m, nil
}

func viewInit(srv serverRow) string {
	var b strings.Builder
	b.WriteString("\n" + gutter + titleStyle.Render("Connected") +
		dimStyle.Render(" — this server is not set up yet") + "\n\n")

	if srv.state == "docker-stopped" {
		b.WriteString(gutter + dot("warn") + " " + warnStyle.Render(
			"Docker is installed but not running. Continuing will try to start it.") + "\n\n")
	}

	b.WriteString(para(gutter, "Setting it up installs:"))
	b.WriteString("\n")
	for _, l := range [][2]string{
		{"docker", "the container runtime, enabled at boot"},
		{defaultNetwork, "the network apps share to reach each other"},
		{"caddy", "one reverse proxy, terminating HTTPS for every app"},
	} {
		b.WriteString(gutter + "  " + dimStyle.Render(pad(l[0], 10)) + " " + dimStyle.Render(l[1]) + "\n")
	}
	b.WriteString("\n" + para(gutter, "No accounts, and nothing under /srv — that comes later, when you\nadd an app. Safe to re-run; it is also how you update Docker."))
	b.WriteString(help("enter", "set it up", "q", "quit"))
	return b.String()
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
			m.scr = screenRunning
			m.run = newRunState(q)
			return m.startRotate(a.name)
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
			m.scr = screenRunning
			m.run = newRunState(q)
			return m.startRemove(a.name)
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
			m.scr = screenRunning
			m.run = newRunState("Pointing " + a.name + " at " + v)
			return m.startConfigChange(a.name, v)
		},
	}
}
