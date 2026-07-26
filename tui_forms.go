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

func newAddForm() addForm {
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
	}}
}

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
	b.WriteString("\n  " + titleStyle.Render("Add an app") + "\n\n")
	for i, fl := range f.fields {
		caret := "  "
		if i == f.focus {
			caret = "▸ "
		}
		val := fl.value
		if i == f.focus {
			val += "█"
		}
		b.WriteString(fmt.Sprintf("%s%-14s %s\n", caret, dimStyle.Render(fl.label), val))
		if i == f.focus {
			b.WriteString(dimStyle.Render("                 "+fl.help) + "\n")
		}
	}
	if f.problem != "" {
		b.WriteString("\n  " + errStyle.Render(f.problem) + "\n")
	}
	b.WriteString(dimStyle.Render("\n  A deploy keypair is generated on this machine; only the public half\n" +
		"  is sent. Safe to run again on an app that already exists.\n"))
	b.WriteString(help("tab", "next field", "enter", "confirm", "esc", "cancel"))
	return b.String()
}

// --- confirming something destructive --------------------------------------

type confirmPrompt struct {
	title string
	body  []string
	// confirmWord, when set, must be typed out in full. Reserved for actions
	// that delete data -- a single keypress is too easy to hit by accident.
	confirmWord string
	typed       string
	action      func(*model) tea.Cmd
}

func (m model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	c := &m.confirm
	switch msg.String() {
	case "esc":
		m.scr = screenList
		return m, nil
	case "enter":
		if c.confirmWord != "" && c.typed != c.confirmWord {
			return m, nil
		}
		m.scr = screenRunning
		m.run = newRunState(c.title)
		return m, c.action(&m)
	case "backspace":
		if c.typed != "" {
			c.typed = c.typed[:len(c.typed)-1]
		}
	default:
		if c.confirmWord != "" {
			if s := msg.String(); len(s) == 1 {
				c.typed += s
			}
		}
	}
	return m, nil
}

func (c confirmPrompt) view() string {
	var b strings.Builder
	b.WriteString("\n  " + warnStyle.Render(c.title) + "\n\n")
	for _, l := range c.body {
		b.WriteString("  " + dimStyle.Render(l) + "\n")
	}
	if c.confirmWord != "" {
		b.WriteString(fmt.Sprintf("\n  Type %s to confirm: %s█\n",
			keyStyle.Render(c.confirmWord), c.typed))
		if c.typed == c.confirmWord {
			b.WriteString(help("enter", "do it", "esc", "cancel"))
		} else {
			b.WriteString(help("esc", "cancel"))
		}
	} else {
		b.WriteString(help("enter", "confirm", "esc", "cancel"))
	}
	return b.String()
}
