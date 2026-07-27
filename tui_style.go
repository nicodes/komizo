package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// One place for how everything looks, so a screen cannot drift from the rest.
//
// The palette is deliberately small: an accent for things you can act on, and
// three states. Colour carries meaning here and nothing else -- nothing is
// coloured to be decorative, so a red on this screen always means something is
// broken.
//
// AdaptiveColor picks per terminal background, because a mid-grey that reads as
// "secondary" on a dark theme is nearly invisible on a light one.
var (
	cAccent = lipgloss.AdaptiveColor{Light: "#0B7285", Dark: "#3BC9DB"}
	cOK     = lipgloss.AdaptiveColor{Light: "#2B8A3E", Dark: "#69DB7C"}
	cWarn   = lipgloss.AdaptiveColor{Light: "#E67700", Dark: "#FFD43B"}
	cErr    = lipgloss.AdaptiveColor{Light: "#C92A2A", Dark: "#FF6B6B"}
	cMuted  = lipgloss.AdaptiveColor{Light: "#868E96", Dark: "#7A8288"}
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true)
	dimStyle   = lipgloss.NewStyle().Foreground(cMuted)
	keyStyle   = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	selStyle   = lipgloss.NewStyle().Bold(true)
	okStyle    = lipgloss.NewStyle().Foreground(cOK)

	// Distinct on purpose. These were both plain bold once, which meant a
	// warning and a failure were indistinguishable -- the one moment the
	// difference matters most.
	warnStyle = lipgloss.NewStyle().Foreground(cWarn)
	errStyle  = lipgloss.NewStyle().Foreground(cErr).Bold(true)

	barStyle   = lipgloss.NewStyle().Foreground(cAccent)
	brandStyle = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
)

const gutter = "  "

// pad right-pads to a visible width. lipgloss.Width, never len: a styled cell
// carries escape bytes that len counts and the terminal does not, which is what
// used to knock every column out of line as soon as a value was dimmed.
func pad(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// header is the one persistent line: who you are talking to, always visible so
// there is no doubt which box a destructive key applies to.
func header(t target, width int) string {
	addr := t.addr()
	if t.port != 22 {
		addr = fmt.Sprintf("%s:%d", addr, t.port)
	}
	line := gutter + brandStyle.Render("komizo") + dimStyle.Render("  "+addr)
	rule := width - 4
	if rule < 8 {
		rule = 8
	}
	return "\n" + line + "\n" + gutter + dimStyle.Render(strings.Repeat("─", rule)) + "\n"
}

// help renders the key hints as one line, so the shortcuts are always on screen
// rather than something to remember.
func help(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, keyStyle.Render(pairs[i])+" "+dimStyle.Render(pairs[i+1]))
	}
	return "\n" + gutter + strings.Join(parts, dimStyle.Render(" · ")) + "\n"
}

// section is a quiet label above a group of rows. Lowercase and muted, so it
// separates without competing with the content under it.
func section(name string) string {
	return "\n" + gutter + dimStyle.Render(name) + "\n"
}

// kv is the standard label/value row, used by every detail screen so they line
// up with each other and not just with themselves.
func kv(label, value string) string {
	return gutter + dimStyle.Render(pad(label, 14)) + " " + value + "\n"
}

// dot is a status indicator. Shape as well as colour, so it still reads on a
// terminal without colour and for anyone who cannot distinguish red from green.
func dot(state string) string {
	switch state {
	case "ok":
		return okStyle.Render("●")
	case "warn":
		return warnStyle.Render("◐")
	case "err":
		return errStyle.Render("○")
	default:
		return dimStyle.Render("·")
	}
}

// wrap breaks text on spaces to a visible width. Field help used to be one
// long line that simply ran off the right edge of a narrow terminal.
func wrap(s string, w int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	lines, cur := []string{}, words[0]
	for _, word := range words[1:] {
		// Visible width, not bytes: an em-dash is three bytes and one column,
		// and counting bytes would wrap prose early for no reason.
		if lipgloss.Width(cur)+1+lipgloss.Width(word) > w {
			lines = append(lines, cur)
			cur = word
			continue
		}
		cur += " " + word
	}
	return append(lines, cur)
}

// para renders a block of muted prose. Each line is styled separately on
// purpose: rendering a multi-line string through one style pads every line out
// to the width of the longest, which litters the screen with trailing spaces.
func para(indent, text string) string {
	var b strings.Builder
	for _, ln := range strings.Split(text, "\n") {
		if ln == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString(indent + dimStyle.Render(ln) + "\n")
	}
	return b.String()
}

// trimTrailing strips trailing blanks from every line. Belt and braces over
// para: any style applied to a multi-line string pads it, and a stray run of
// spaces shows up the moment someone selects text in a terminal.
func trimTrailing(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimRight(ln, " ")
	}
	return strings.Join(lines, "\n")
}

// table lays out rows in aligned columns. header is row 0; selected is an index
// into the data rows, or -1.
//
// The selected row is marked with an accent bar rather than reverse video: a
// reversed line inverts every colour inside it, so a red warning in the selected
// row would come out looking fine.
func table(rows [][]string, selected int) string {
	if len(rows) == 0 {
		return ""
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) && lipgloss.Width(c) > widths[i] {
				widths[i] = lipgloss.Width(c)
			}
		}
	}

	var b strings.Builder
	for ri, r := range rows {
		var cells []string
		for i, c := range r {
			if i == len(r)-1 {
				cells = append(cells, c) // no trailing pad on the last column
			} else {
				cells = append(cells, pad(c, widths[i]))
			}
		}
		line := strings.TrimRight(strings.Join(cells, "  "), " ")

		switch {
		case ri == 0:
			b.WriteString(gutter + "  " + dimStyle.Render(line) + "\n")
		case ri-1 == selected:
			b.WriteString(gutter + barStyle.Render("▍") + " " + selStyle.Render(line) + "\n")
		default:
			b.WriteString(gutter + "  " + line + "\n")
		}
	}
	return b.String()
}
