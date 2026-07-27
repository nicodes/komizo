package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// A log gets the whole window.
//
// It used to open as a pane under the app list, which meant the thing you came
// to read was whatever fitted in the space left over -- usually a dozen lines,
// on the screen where the list you were no longer looking at was taking up
// twenty. A log is either worth reading or it is not, and if it is, it is worth
// the page.
//
// The page is deliberately the same page: identical title, identical footer in
// the identical place. Only the middle changes, so nothing about where you are
// has to be re-learned.

// logViewport is how many lines of log fit on screen.
//
// The chrome is MEASURED, not guessed at with a constant. It was a constant,
// and it was two lines short -- so a full window rendered two lines taller than
// the terminal, the terminal scrolled to fit, and the title went off the top.
// A title that disappears once there is something to read is the opposite of a
// title, and the bug is invisible until a log happens to be long enough.
//
// The footer is the part that moves: it grows by two lines when a status
// appears, which is exactly what pressing "copy" does.
func (m model) logViewport() int {
	chrome := strings.Count(header(), "\n") +
		strings.Count(section(""), "\n") +
		strings.Count(m.logsFooter(), "\n") +
		// The blank line before the log, the position line and its blank, and
		// the one the whole render ends on. Off by one here means the terminal
		// scrolls and the title is the thing that leaves.
		4
	// One line at the floor rather than three. A floor above what actually
	// fits is a floor that overflows the terminal to honour itself, which is
	// the bug this function exists to avoid -- just at a size nobody uses.
	if n := m.height - chrome; n > 1 {
		return n
	}
	return 1
}

// loading reports whether we are waiting for the log to arrive.
//
// Tracked with a flag rather than inferred from an empty body: a container that
// has genuinely logged nothing also has an empty body, and it would otherwise
// spin forever waiting for output that has already arrived.
func (m model) loading() bool { return m.logsOf != "" && !m.logsReady }

// logLines is the log as lines, without a trailing blank.
func (m model) logLines() []string {
	if m.logs == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(m.logs, "\n"), "\n")
}

// maxLogScroll is the furthest down we can go: enough to put the last line at
// the bottom of the viewport, and no further. Scrolling into blank space below
// the end is a way of losing the text you were reading.
func (m model) maxLogScroll() int {
	if n := len(m.logLines()) - m.logViewport(); n > 0 {
		return n
	}
	return 0
}

func (m model) handleLogsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	page := m.logViewport() - 1
	switch msg.String() {
	case "esc", "q", "left", "h":
		m.scr = screenList
		m.status, m.statusErr = "", false
		return m, nil

	case "up", "k":
		m.logScroll--
	case "down", "j":
		m.logScroll++
	case "pgup", "b":
		m.logScroll -= page
	case "pgdown", " ", "f":
		m.logScroll += page
	case "g", "home":
		m.logScroll = 0
	case "G", "end":
		m.logScroll = m.maxLogScroll()

	case "R":
		// Re-read it. A log is the one thing on this page worth asking for
		// again with nothing having changed. Through openLogs so it shows the
		// spinner while it waits, exactly as it did the first time.
		if m.logsOf == "" {
			return m, nil
		}
		return m.openLogs(m.logsOf, m.logsLabel, m.logsCmd)

	case "c":
		if m.logs == "" {
			return m, nil
		}
		// The whole log, not the part on screen. Copying what happens to be
		// visible would make the result depend on the size of the window.
		if err := copyToClipboard(m.logs); err != nil {
			m.status, m.statusErr = err.Error(), true
		} else {
			m.status, m.statusErr = "copied", false
		}
		return m, nil
	}

	if m.logScroll > m.maxLogScroll() {
		m.logScroll = m.maxLogScroll()
	}
	if m.logScroll < 0 {
		m.logScroll = 0
	}
	return m, nil
}

func (m model) viewLogs() string {
	var b strings.Builder
	b.WriteString(section(m.logsLabel + " log"))

	if m.loading() {
		b.WriteString(m.centred(spinner(m.spin)))
		return b.String()
	}

	lines := m.logLines()
	if len(lines) == 0 {
		b.WriteString(m.centred(dimStyle.Render("this one has logged nothing")))
		return b.String()
	}

	start := m.logScroll
	if start > m.maxLogScroll() {
		start = m.maxLogScroll()
	}
	end := start + m.logViewport()
	if end > len(lines) {
		end = len(lines)
	}

	b.WriteString("\n")
	for _, ln := range lines[start:end] {
		b.WriteString(gutter + dimStyle.Render(ln) + "\n")
	}

	// Where you are, but only when there is somewhere else to be.
	if m.maxLogScroll() > 0 {
		b.WriteString("\n" + gutter + dimStyle.Render(
			fmt.Sprintf("lines %d–%d of %d", start+1, end, len(lines))) + "\n")
	}
	return b.String()
}

// centred puts one short thing in the middle of the viewport, so a window with
// nothing to show yet still looks like the window it is about to be.
func (m model) centred(s string) string {
	h := m.logViewport()
	above := h / 2
	left := (m.width - lipglossWidth(s)) / 2
	if left < len(gutter) {
		left = len(gutter)
	}
	return strings.Repeat("\n", above+1) +
		strings.Repeat(" ", left) + s + "\n" +
		strings.Repeat("\n", h-above-1)
}

// logsFooter is the same footer as the list's, with the keys this window has.
func (m model) logsFooter() string {
	var b strings.Builder
	b.WriteString("\n" + gutter +
		dimStyle.Render(strings.Repeat("─", ruleWidth(m.width))) + "\n")
	if m.status != "" {
		mark, style := dot("ok"), okStyle
		if m.statusErr {
			mark, style = dot("err"), errStyle
		}
		b.WriteString("\n" + gutter + mark + " " + style.Render(m.status) + "\n")
	}
	b.WriteString(help("↑↓", "scroll", "R", "refresh", "esc", "back", "q", "quit"))
	return b.String() + trimTrailing(help("c", "copy", "g/G", "top/bottom", "pgup/pgdn", "page"))
}
