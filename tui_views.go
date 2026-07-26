package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true)
	dimStyle   = lipgloss.NewStyle().Faint(true)
	keyStyle   = lipgloss.NewStyle().Bold(true)
	selStyle   = lipgloss.NewStyle().Bold(true).Reverse(true)
	errStyle   = lipgloss.NewStyle().Bold(true)
	warnStyle  = lipgloss.NewStyle().Bold(true)
)

func header(t target, width int) string {
	line := fmt.Sprintf(" ncicd  %s", t.addr())
	if t.port != 22 {
		line += fmt.Sprintf(":%d", t.port)
	}
	if width > lipgloss.Width(line) {
		line += strings.Repeat(" ", width-lipgloss.Width(line))
	}
	return titleStyle.Render(line) + "\n"
}

// help renders the key hints as a single line, so the shortcuts are always
// visible rather than something to remember.
func help(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, keyStyle.Render(pairs[i])+" "+dimStyle.Render(pairs[i+1]))
	}
	return "\n  " + strings.Join(parts, dimStyle.Render("  ·  ")) + "\n"
}

func viewList(m model) string {
	var b strings.Builder

	if len(m.apps) == 0 {
		b.WriteString("\n  No apps on this server yet.\n")
		b.WriteString(dimStyle.Render("\n  An app is a compose stack with its own directory, deploy account\n" +
			"  and privileged commands. Add one to get started.\n"))
		b.WriteString(help("a", "add an app", "R", "refresh", "q", "quit"))
		return b.String()
	}

	b.WriteString("\n")
	rows := [][]string{{"", "APP", "ACCOUNT", "VERSION", "UP", "CONFIG IMAGE"}}
	for i, a := range m.apps {
		marker := "  "
		if i == m.cursor {
			marker = "▸ "
		}
		rows = append(rows, []string{marker, a.name, a.user, short(a.version), a.running, a.image})
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	for ri, r := range rows {
		var line strings.Builder
		for i, c := range r {
			line.WriteString(c)
			if i < len(r)-1 {
				line.WriteString(strings.Repeat(" ", widths[i]-len(c)+2))
			}
		}
		switch {
		case ri == 0:
			b.WriteString("  " + dimStyle.Render(line.String()) + "\n")
		case ri-1 == m.cursor:
			b.WriteString("  " + selStyle.Render(line.String()) + "\n")
		default:
			b.WriteString("  " + line.String() + "\n")
		}
	}

	if m.status != "" {
		b.WriteString("\n  " + warnStyle.Render(m.status) + "\n")
	}
	b.WriteString(help(
		"↑↓", "select", "enter", "details", "a", "add",
		"r", "rotate key", "x", "remove", "R", "refresh", "q", "quit"))
	return b.String()
}

func viewDetail(m model) string {
	a := m.apps[m.cursor]
	var b strings.Builder
	b.WriteString("\n  " + titleStyle.Render(a.name) + "\n\n")
	for _, kv := range [][2]string{
		{"deploy account", a.user},
		{"directory", a.dir},
		{"live version", short(a.version)},
		{"containers up", a.running},
		{"config image", a.image},
		{"deploy command", "doas /usr/local/bin/deploy-" + a.name},
		{"secret command", "doas /usr/local/bin/set-secret-" + a.name},
	} {
		b.WriteString(fmt.Sprintf("  %-16s %s\n", dimStyle.Render(kv[0]), kv[1]))
	}
	b.WriteString(dimStyle.Render("\n  Deploys happen from CI. This account can only deploy a tag that\n" +
		"  already exists in the registry, and set secrets it cannot read back.\n"))
	b.WriteString(help("esc", "back", "q", "back"))
	return b.String()
}

// short trims a commit SHA to something readable without losing which it is.
func short(v string) string {
	if v == "" || v == "none" {
		return dimStyle.Render("none")
	}
	if len(v) > 12 {
		return v[:12]
	}
	return v
}
