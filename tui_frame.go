package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Every page is the same three parts: a title that does not move, a middle that
// scrolls, and a footer pinned to the bottom of the terminal.
//
// The log window was built this way first, and it was the only page that was.
// Everywhere else the page was simply written top to bottom and left to find
// its own length -- which worked exactly as long as it fitted. Past that the
// terminal did the scrolling, and what the terminal scrolls off is the TOP: the
// title went first, then the Server section, then the Proxy section, and the
// keys at the bottom went wherever the last line happened to land. A host with
// a dozen apps had no title, no fixed footer, and no way to see both ends of
// its own list.
//
// So the frame belongs to every screen, and the parts each screen still owns
// are its body and its keys. Three consequences worth naming:
//
//   - The page is ALWAYS exactly the height of the terminal. The middle is
//     padded out when it is short, so the footer sits on the bottom row whether
//     there is one app or thirty, and nothing moves as the list grows.
//
//   - The keys are always on screen, which is what makes them worth printing.
//     A help line that scrolls away is a help line you have to remember.
//
//   - Status and errors moved into the footer. They used to be appended
//     wherever the body ended, so the reply to a keypress appeared in a
//     different place on every screen -- and on a long list, off it.

// cursorBar is the accent mark that shows the selected row. Every page draws
// its selection with it, which is what lets the frame find the cursor without
// knowing anything about what a given page is a list OF.
const cursorBar = "▍"

// rowsOf splits rendered output into terminal rows.
//
// One trailing newline is dropped: a block written as "…\n" is the rows before
// it, not those rows plus an empty one. Getting this wrong makes every page one
// line too tall, which is invisible until it is the line that overflows.
func rowsOf(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// anchorOf is the row the cursor is on, or -1 on a page with no selection.
//
// Found by looking for the mark rather than reported by the page, deliberately:
// a page that had to return its own cursor line would have to count rows it
// currently just writes, and the count would go wrong the first time anything
// above the cursor changed height -- which is exactly what the focused field's
// help text, the status line and a wrapped error all do.
func anchorOf(body []string) int {
	for i, ln := range body {
		if strings.Contains(ln, cursorBar) {
			return i
		}
	}
	return -1
}

// viewport is how many body rows fit between the header and the footer.
//
// The chrome is MEASURED rather than guessed at with a constant. It was a
// constant in the log window once, and it was two lines short, so a full window
// rendered two lines taller than the terminal, the terminal scrolled to fit,
// and the title went off the top -- a bug invisible until a log happened to be
// long enough.
//
// The footer is measured through a SKELETON: a status line of the right height
// rather than the real one. The real one is what the log window's position
// indicator lives on, and that text needs the viewport to say which lines are
// showing. Height does not depend on the text, only on whether there is one, so
// the skeleton breaks the loop without approximating anything.
func (m model) viewport() int {
	status := ""
	if m.hasStatus() {
		status = "\n" + gutter + "\n"
	}
	n := m.height - len(rowsOf(m.headerLine())) - len(rowsOf(m.footerFrame(status)))
	// One row at the floor rather than a comfortable minimum: a floor above
	// what actually fits is a floor that overflows the terminal to honour
	// itself, which is the failure this function exists to prevent.
	if n < 1 {
		return 1
	}
	return n
}

// maxScroll is the furthest down a page can go: enough to put its last row on
// the bottom of the viewport, and no further. Scrolling into blank space past
// the end is a way of losing the text you were reading.
func (m model) maxScroll() int {
	if n := len(rowsOf(m.pageBody())) - m.viewport(); n > 0 {
		return n
	}
	return 0
}

// reflow keeps the scroll offset honest after anything that could change what
// is on screen -- a keypress, a window resize, an inventory landing, a line of
// output arriving.
//
// It runs in Update rather than in View because View has to stay pure: it is
// called on a copy, so anything it "fixed" would be recomputed from the stale
// value on the very next frame.
//
// Three behaviours, because the pages genuinely differ.
//
// A log follows nothing: it is the one page where scrolling is the reason you
// are there, and a log that jumped somewhere on every repaint -- and there is
// one every ten seconds -- would be unreadable.
//
// A page with a cursor follows the cursor. A page without one follows its tail,
// which is where output arrives and where a command that just failed says why.
// Keyed off whether there IS a cursor rather than off the screen, because one
// screen is both: a run streams with no cursor, and finishes either with a
// result you arrow through or with an error where the last lines are the point.
func (m *model) reflow() {
	avail := m.viewport()
	body := rowsOf(m.pageBody())

	switch i := anchorOf(body); {
	case m.scr == screenLogs:
		// The user drives it.

	case i >= 0:
		// Scroll the minimum that puts the cursor back on screen, so moving one
		// row moves the page one row. Recentring instead would repaint the whole
		// middle on every press, and the row you were reading next would not be
		// where you last saw it.
		if i < m.scroll {
			m.scroll = i
		}
		if i >= m.scroll+avail {
			m.scroll = i - avail + 1
		}

	default:
		m.scroll = len(body) - avail
	}

	if hi := len(body) - avail; m.scroll > hi {
		m.scroll = hi
	}
	if m.scroll < 0 {
		m.scroll = 0
	}
}

func (m model) View() string {
	head := rowsOf(m.headerLine())
	foot := rowsOf(m.pageFooter())
	body := rowsOf(m.pageBody())

	// No window size yet: the first frame, before Bubble Tea reports one. Render
	// unframed rather than lay the page out against a height of zero.
	if m.height <= 0 {
		return trimTrailing(strings.Join(concat(head, body, foot), "\n"))
	}

	// A footer taller than the window it is in. The add form is the case: a
	// question, its consequence, three fields and the focused field's help is a
	// dozen rows, and a short terminal has fewer. Keep the END of it -- the
	// fields you are typing into and the keys -- and let the question scroll off
	// the top of the footer, rather than letting the page overflow.
	if room := m.height - len(head) - 1; len(foot) > room {
		if room < 0 {
			room = 0
		}
		foot = foot[len(foot)-room:]
	}

	avail := m.height - len(head) - len(foot)
	if avail < 1 {
		avail = 1
	}

	start := m.scroll
	if hi := len(body) - avail; start > hi {
		start = hi
	}
	if start < 0 {
		start = 0
	}
	end := start + avail
	if end > len(body) {
		end = len(body)
	}

	// Padded to the full viewport even when the body is shorter, which is what
	// pins the footer to the bottom row instead of letting it float up under a
	// short list.
	mid := append([]string{}, body[start:end]...)
	for len(mid) < avail {
		mid = append(mid, "")
	}

	return trimTrailing(strings.Join(m.clip(concat(head, mid, foot)), "\n"))
}

// clip cuts every row to the width of the terminal.
//
// Without it the whole frame is a suggestion. A row wider than the window wraps
// onto a second one, the page comes out taller than the terminal, and the
// terminal scrolls to fit -- taking the title off the top, which is the exact
// failure this file exists to prevent. A log line is routinely wider than a
// window, so this is the common case, not the corner.
//
// So a long line is cut rather than folded. That does lose the end of it, and
// the alternative loses the top of the page: one is visible and expected, and
// the other silently undoes the layout.
func (m model) clip(lines []string) []string {
	if m.width <= 0 {
		return lines
	}
	cut := lipgloss.NewStyle().MaxWidth(m.width)
	for i, ln := range lines {
		lines[i] = cut.Render(ln)
	}
	return lines
}

func concat(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// headerLine is the header, except on the screen whose whole content is the
// name: the loading pane centres "komizo" over the spinner, and the corner
// carrying it as well would be the same word twice on an otherwise empty page.
// A blank row rather than nothing, so the layout does not shift when the first
// inventory lands and the real header appears.
func (m model) headerLine() string {
	if m.scr == screenLoading || m.scr == screenLogin {
		return "\n"
	}
	return header(m.crumb())
}

// crumb is where you are, for the header: komizo / monitor.
//
// It is what the log window's own title line used to be, moved up beside the
// brand. That line sat at the top of the body, which meant reading to the
// bottom of a long log left a screen of untitled output; up here it cannot
// scroll away, and it costs the page no rows, because the header was already
// there saying only "komizo".
func (m model) crumb() string {
	switch m.scr {
	case screenLogin:
		return "login"
	case screenLogs:
		return m.logsLabel + " logs"
	case screenSetup:
		return "setup"
	case screenMonitor:
		return "monitor"
	}
	return ""
}

// pageBody is the scrolling middle: what the screen is about, and nothing that
// belongs to the frame.
func (m model) pageBody() string {
	switch m.scr {
	case screenLogin:
		return m.loginPane()
	case screenLoading:
		return m.loadingPane()
	case screenMonitor:
		return viewMonitor(m)
	case screenLogs:
		return m.viewLogs()
	case screenSetup:
		return m.viewSetup()
	}
	return ""
}

// footerFrame is the footer's shape: a rule, then the reply to your last
// keypress, then the keys. Taken apart from pageFooter so the height can be
// measured with a stand-in status -- see viewport.
func (m model) footerFrame(status string) string {
	keys := m.footerKeys()
	if keys == "" && status == "" {
		return ""
	}
	// A blank row above the rule and none below it. The one above separates the
	// footer from the page; the one below separated the rule from the thing it
	// is drawn for, which is backwards -- a divider belongs against what it
	// divides. Both blocks start with a newline of their own, so the leading one
	// is trimmed rather than never written: the status line and the keys are
	// each used on their own elsewhere.
	return "\n" + dimStyle.Render(strings.Repeat("─", ruleWidth(m.width))) + "\n" +
		dedent(strings.TrimLeft(status+trimTrailing(keys), "\n"))
}

// dedent pulls the footer out to the left margin.
//
// Done here, once, rather than by teaching every block that can appear in a
// footer to skip the gutter -- the keys, the status line, four kinds of prompt,
// the add form's fields and the values an operation leaves behind. Relative
// indentation survives, so a field's help text stays indented under its field.
func dedent(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimPrefix(ln, gutter)
	}
	return strings.Join(lines, "\n")
}

func (m model) pageFooter() string { return m.footerFrame(m.statusLine()) }

// hasStatus is whether there is a reply to show, without saying what it is.
// Height needs the first and not the second, and the second is what needs the
// height. See viewport.
func (m model) hasStatus() bool {
	switch {
	case m.err != nil:
		return true
	case m.status != "":
		return true
	case m.scr == screenLogs && len(m.logLines()) > 0:
		return true
	}
	return false
}

// loginPane is `komizo` with no host: the name, what this is, and a field.
//
// Centred, and with the header stood down, because there is nothing else on
// the page and no page to be anywhere in yet. The address is the only thing
// this program needs that it cannot work out for itself.
func (m model) loginPane() string {
	return m.centred(
		brandStyle.Render("komizo"),
		"",
		dimStyle.Render("your server, secured"),
		"",
		m.loginField(),
	)
}

// loginField is the address being typed, with a caret and a placeholder.
//
// The placeholder is an example rather than a label -- "root@example.com" says
// both what to type and that the user part is expected, which "host" does not.
func (m model) loginField() string {
	if m.login == "" {
		return dimStyle.Render("root@example.com") + barStyle.Render("▏")
	}
	return m.login + barStyle.Render("▏")
}

// statusLine is the one line between the rule and the keys: what just happened,
// or where you are in a log.
//
// One place for all of it. It used to be three -- the list appended its status
// after the app rows, the log window put its own inside the footer, and a
// connection error was written wherever the body ended -- so the answer to a
// keypress appeared somewhere different depending on which page you were on.
func (m model) statusLine() string {
	line := func(glyph, text string) string {
		return "\n" + gutter + glyph + " " + text + "\n"
	}
	switch {
	case m.err != nil:
		return line(dot("err"), errStyle.Render(m.err.Error()))
	case m.status != "":
		if m.statusErr {
			return line(dot("err"), errStyle.Render(m.status))
		}
		return line(dot("ok"), okStyle.Render(m.status))
	case m.scr == screenLogs && len(m.logLines()) > 0:
		return m.logPosition()
	}
	return ""
}

// footerKeys is what this screen can do, and it is the last thing on the page
// on every one of them.
func (m model) footerKeys() string {
	// An operation on the loading screen says so in the middle of the page, so
	// the footer stays empty rather than spinning a second time under it.
	if m.running() && m.scr == screenLoading {
		return ""
	}
	// A question replaces the keys rather than joining them: while one is open
	// the keys underneath do not apply, and printing both would offer two sets
	// of instructions at once. Before any screen's own keys, because an
	// operation started from the setup screen runs in its footer.
	if m.prompt != nil {
		return m.promptView()
	}
	switch m.scr {
	case screenMonitor:
		return m.helpLines()
	case screenLogs:
		return m.logsKeys()
	case screenSetup:
		return helpLine(m.width, "enter", "set it up", "q", "quit")
	case screenLogin:
		return helpLine(m.width, "enter", "connect", "esc", "quit")
	}
	return ""
}

// logPosition is where you are in the log, and it is only interesting when
// there is somewhere else to be.
func (m model) logPosition() string {
	n := len(m.logLines())
	if m.maxScroll() == 0 {
		return "\n" + gutter + dimStyle.Render(fmt.Sprintf("%d lines", n)) + "\n"
	}
	start := m.scroll
	end := start + m.viewport()
	if end > n {
		end = n
	}
	return "\n" + gutter + dimStyle.Render(
		fmt.Sprintf("lines %d–%d of %d", start+1, end, n)) + "\n"
}

// centred puts one short thing in the middle of the viewport, so a window with
// nothing to show yet still looks like the window it is about to be.
func (m model) centred(lines ...string) string {
	// Half the empty space above, so the block sits in the middle of the space
	// it has rather than the middle of the terminal -- which are different
	// numbers once the footer is a form or a result.
	above := (m.viewport() - len(lines)) / 2
	if above < 0 {
		above = 0
	}
	var b strings.Builder
	b.WriteString(strings.Repeat("\n", above))
	for _, ln := range lines {
		left := (m.width - lipglossWidth(ln)) / 2
		if left < len(gutter) {
			left = len(gutter)
		}
		b.WriteString(strings.Repeat(" ", left) + ln + "\n")
	}
	return b.String()
}

// alignBlock pads lines to a common width, so centring them gives the block one
// left edge instead of staggering every line by its own length.
func alignBlock(lines []string) []string {
	w := 0
	for _, ln := range lines {
		w = max(w, lipglossWidth(ln))
	}
	out := make([]string, len(lines))
	for i, ln := range lines {
		out[i] = pad(ln, w)
	}
	return out
}

// loadingPane is the one thing this interface shows while it waits: a spinner
// with the word under it, in the middle of whatever space the page has.
//
// One component for both places that wait, because they are the same wait --
// an SSH command is running and the page cannot be drawn until it answers. They
// were written separately and looked it: the first read said "▍ connecting…" on
// a line at the top left, and a log opening showed a bare spinner in the middle
// with no word at all, which reads as a glyph nobody explained.
// The name, then the spinner under it, both in the accent.
//
// This was a wordmark for a while: "komizo" drawn in braille dots with a
// shimmer sweeping across it. It worked, in the sense that it did what it said,
// and it never looked like anything but dots pretending to be letters -- a
// bitmap font at four rows is a font nobody chose. The word is already
// available in the terminal's own type, which renders it properly at whatever
// size and weight the user has picked.
func (m model) loadingPane() string {
	// The name only on the first read, where there is nothing else to say and
	// the header has stood down. A log opening has its own header -- "komizo /
	// blog-web-1 logs" -- and repeating the brand under it would be the same
	// word twice on a page that is already telling you what it is fetching.
	if m.scr != screenLoading {
		return m.centred(spinnerAccent(m.spin))
	}
	lines := []string{brandStyle.Render("komizo"), "", spinnerAccent(m.spin)}
	// An operation says what it is: setting a server up takes a minute, and a
	// spinner on its own for that long is indistinguishable from a hang.
	if m.running() {
		lines = append(lines, "", dimStyle.Render(m.run.title))
	}
	return m.centred(lines...)
}
