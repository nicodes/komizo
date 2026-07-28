package app

import (
	"fmt"
	"strings"
	"time"

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

	// The breadcrumb: the terminal's own foreground, unstyled. Not bold, and
	// not the accent -- both belong to the brand beside it, and a crumb wearing
	// either would compete with the word it is hanging off.
	crumbStyle = lipgloss.NewStyle()
)

const gutter = "  "

// tagline is the line under the name, wherever the name appears centred. One
// string, so the login screen, the loader and the setup page cannot drift into
// three different descriptions of the same tool.
const tagline = "Your server & keys secured"

// lipglossWidth is the visible width of a styled string, in columns.
func lipglossWidth(s string) int { return lipgloss.Width(s) }

// pad right-pads to a visible width. lipgloss.Width, never len: a styled cell
// carries escape bytes that len counts and the terminal does not, which is what
// used to knock every column out of line as soon as a value was dimmed.
func pad(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// header is the tool, then where in it you are: komizo / monitor.
//
// A breadcrumb rather than a bare name, because the pages stopped announcing
// themselves. The log window used to write its own title into the body and the
// list never had one at all -- so the only thing on screen saying which page
// you were on was the shape of the page.
//
// Two weights, not two sizes. A terminal has one font size and no escape
// sequence changes it, so "bigger" here is the brand keeping the accent colour
// and the bold, with the crumb in plain white beside it: the eye still lands on
// "komizo" first, and the part that changes reads as the part that changes.
//
// No rule under it. There is one at the bottom, above the footer, and that one
// earns its place by separating the part you read from the part you type at.
// A second rule six lines above it separated the title from the content, which
// were never in danger of being confused.
//
// The address used to sit here. It moved to a row in the Server section, where
// it is one fact among the others rather than a permanent banner -- but that
// removed it from the confirmation screens, so anything destructive now names
// the host itself. See removePrompt.
func header(crumb string) string {
	line := brandStyle.Render("komizo")
	if crumb != "" {
		line += dimStyle.Render(" / ") + crumbStyle.Render(crumb)
	}
	// Flush left, and no blank row above it. The header and the footer are the
	// window's edges: they run corner to corner, and the gutter belongs to the
	// content between them. Indenting them by two put the title in from the
	// corner and left the rule short at both ends, so the page read as a box
	// floating inside the terminal rather than as the terminal.
	return line + "\n"
}

// title capitalises the first letter. The key hints want "stop" lowercase and
// the question wants it capitalised, and they are the same word.
func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ruleWidth is how wide the footer's rule is: the whole window. It stopped
// short by two at each end when the footer was indented, which read as a line
// drawn around something rather than a division of the page.
func ruleWidth(width int) int {
	if width > 8 {
		return width
	}
	return 8
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

// helpLine is help that fits, by dropping pairs from the END OF THE MIDDLE
// until it does, and saying so with an ellipsis.
//
// The footer is one line now, and one line can be too long for a window. It is
// clipped to the terminal either way -- a wrapped footer makes the page taller
// than the screen and scrolls the title away -- so the question is only which
// end gets lost, and clipping alone loses the right-hand one. That is "q quit":
// the single key someone in trouble is looking for.
//
// So the first pair and the last survive at any width. They are the two that
// work on every screen and mean the same thing everywhere -- how to move, how
// to leave -- and a footer down to just those two is still a useful footer. The
// keys that go are the ones that only apply to the row you happen to be on,
// which is also what the ellipsis is admitting.
func helpLine(width int, pairs ...string) string {
	var items [][2]string
	for i := 0; i+1 < len(pairs); i += 2 {
		items = append(items, [2]string{pairs[i], pairs[i+1]})
	}

	render := func(items [][2]string, elided bool) string {
		var parts []string
		for _, it := range items {
			parts = append(parts, keyStyle.Render(it[0])+" "+dimStyle.Render(it[1]))
		}
		if elided && len(parts) > 1 {
			last := parts[len(parts)-1]
			parts = append(parts[:len(parts)-1], dimStyle.Render("…"), last)
		}
		return "\n" + gutter + strings.Join(parts, dimStyle.Render(" · ")) + "\n"
	}

	elided := false
	for {
		out := render(items, elided)
		if width <= 0 || lipgloss.Width(strings.Trim(out, "\n")) <= width || len(items) <= 2 {
			return out
		}
		// Drop the last of the middle: the pairs nearest the end are the row's
		// own, and the ones nearest the front are the ones every row shares.
		items = append(items[:len(items)-2], items[len(items)-1])
		elided = true
	}
}

// section is the heading above a group of rows -- Server, Proxy, Apps.
//
// Bold rather than coloured. The title above is the one blue thing on the page,
// and a heading in the same colour would compete with it; weight is enough to
// mark a break when the rows under it are all plain.
func section(name string) string {
	return "\n" + gutter + titleStyle.Render(name) + "\n"
}

// kv is the standard label/value row, used by every detail screen so they line
// up with each other and not just with themselves.
func kv(label, value string) string {
	return gutter + dimStyle.Render(pad(label, 14)) + " " + value + "\n"
}

// kvSel is kv with a cursor. Same row, marked with the accent bar the tree
// uses, so a selection reads the same wherever it is on the page.
func kvSel(label, value string, selected bool) string {
	if !selected {
		return kv(label, value)
	}
	return barStyle.Render("▍") + " " + selStyle.Render(pad(label, 14)) +
		" " + brighten(value) + "\n"
}

// kvDot is a label/value row whose value leads with a status glyph.
//
// The glyph is passed separately so it survives selection with its colour --
// see brighten. Every value on this page that has a status is built this way,
// which is also what keeps the text after it uniformly muted.
func kvDot(label, glyph, text string, selected bool) string {
	// A row with no status is a row with no glyph, not a row with a blank where
	// one would go -- otherwise its value starts one column right of every
	// other value on the page.
	if glyph != "" {
		glyph += " "
	}
	if selected {
		return barStyle.Render("▍") + " " + selStyle.Render(pad(label, 14)) +
			" " + glyph + brighten(text) + "\n"
	}
	return gutter + dimStyle.Render(pad(label, 14)) + " " +
		glyph + dimStyle.Render(text) + "\n"
}

// stripStyles removes ANSI sequences, so a composed value can be re-styled
// rather than layered on top of what it already carries.
func stripStyles(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// brighten re-renders text at full strength for the cursor.
//
// Everything on the page is muted until it is selected, and then all of it goes
// bright -- label and value alike, rather than the label alone. Layering a
// style on top would not do it: a dimmed segment stays dim inside a bold
// wrapper, so it has to be stripped back to text first.
//
// Status glyphs are never passed through here. They are kept out by the callers
// rather than recognised and restored, which was how this worked until every
// status became the same filled circle and the shape stopped saying which one
// it was. Colour cannot be recovered from stripped text; it can only be kept.
func brighten(s string) string { return selStyle.Render(stripStyles(s)) }

// spinFrames is the busy indicator, sized to one column so it can stand in for
// a status dot without the row shifting under it.
var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// The accent, everywhere, including where it stands in for a status dot.
//
// It was amber on a row, on the reasoning that the three status colours are the
// vocabulary there and a blue one would read as a fourth kind of healthy. What
// that missed is that amber already means something on this page -- a partially
// up app, a container in a crash loop -- so a spinner wearing it reads as a
// warning for as long as it turns, which is exactly when nothing is known yet.
//
// Waiting is not a state the box is in. It is the interface saying it has not
// finished asking, and the accent is what the interface uses to speak for
// itself: the brand, the cursor, the keys. Nothing red, amber or green is ever
// about the tool rather than the server.
func spinner(n int) string {
	return barStyle.Render(spinFrames[n%len(spinFrames)])
}

// dot is a status indicator: one filled circle, three colours.
//
// It used to vary the shape too -- a hollow circle for a fault, a half-filled
// one for a warning -- so that it read without colour. That is a real property
// to give up, and it was given up on purpose: three different glyphs down a
// column of otherwise identical rows drew the eye to the SHAPE, and the shape
// is the part carrying no information anyone is scanning for. Colour is what
// people actually read here, and the words beside it say the same thing.
//
// The absent state keeps its own mark. "No proxy installed" is not a status the
// thing is in; it is the absence of the thing.
func dot(state string) string {
	switch state {
	case "ok":
		return okStyle.Render("●")
	case "warn":
		return warnStyle.Render("●")
	case "err":
		return errStyle.Render("●")
	default:
		return dimStyle.Render("·")
	}
}

// textWidth is how wide prose in the footer may run.
//
// The terminal's width, less the gutter the text is written with -- it used to
// be the constant 74, chosen for a window nobody has to have. Anything wider
// than the window is clipped now rather than wrapped, so a hard-coded margin is
// a sentence with its end cut off.
func textWidth(width int) int {
	if w := width - len(gutter)*2; w > 20 {
		return w
	}
	return 20
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

// treeRow is one line of the app list.
type treeRow struct {
	cells []string
	// idx is this row's position in the model's focus list, or -1 for a row the
	// cursor cannot land on (the header, and the diagnostic rows). Set
	// explicitly rather than counted here, so the highlight is driven by the
	// same list the keys act on.
	idx int
}

// tree lays the app list out in one set of columns, every row aligned.
//
// It used to keep two sets and draw the branch glyphs itself, on the reasoning
// that an app's account and a container's name are unrelated and should not be
// forced to the same width. True of the meanings, wrong about the reading: a
// table whose second column starts in two different places is one your eye has
// to re-find on every row, and the branch glyph pushed every child three
// columns further right again. Nesting is now a prefix inside the name cell, so
// it indents without moving anything after it.
//
// selected is an index into the model's focus list; a row is highlighted when
// its idx matches. Rows carrying -1 are skipped, which is how the diagnostic
// lines stay unreachable.
//
// The selected row is marked with an accent bar rather than reverse video: a
// reversed line inverts every colour inside it, so a red warning in the
// selected row would come out looking fine.
func tree(rows []treeRow, selected int) string {
	if len(rows) == 0 {
		return ""
	}
	var w []int
	for _, r := range rows {
		for i, c := range r.cells {
			for len(w) <= i {
				w = append(w, 0)
			}
			if lipgloss.Width(c) > w[i] {
				w[i] = lipgloss.Width(c)
			}
		}
	}

	var b strings.Builder
	for _, r := range rows {
		var cells []string
		for i, c := range r.cells {
			if i == len(r.cells)-1 {
				cells = append(cells, c) // no trailing pad on the last column
			} else {
				cells = append(cells, pad(c, w[i]))
			}
		}
		line := strings.TrimRight(strings.Join(cells, "  "), " ")

		// The same indent kvSel uses, so the cursor bar sits in one column all
		// the way down the page. It used to be nested a further two in here,
		// which made the selection appear to step sideways the moment it
		// reached the app list.
		if r.idx >= 0 && r.idx == selected {
			// The first cell is the status glyph and is left exactly as it is;
			// everything after it goes bright. Brightening the glyph too would
			// mean stripping its colour, and there is no way to put back which
			// colour it was once every state is the same circle.
			glyph, rest := cells[0], strings.Join(cells[1:], "  ")
			b.WriteString(barStyle.Render("▍") + " " + glyph + "  " +
				brighten(strings.TrimRight(rest, " ")) + "\n")
			continue
		}
		b.WriteString(gutter + line + "\n")
	}
	return b.String()
}

// since is how long ago something happened, in the one format this page uses
// for every duration on it: largest unit first, zero units left out.
//
//	1d 12h 4m    4m    2h 30m    1d 5m    now
//
// Truncated rather than rounded, because a row that says "3h" and a row that
// says "2h 59m" should not be able to describe the same moment.
//
// No seconds. Minutes is the finest resolution anything here is worth watching
// at, and a number ticking every second draws the eye to the row that changed
// rather than to the row that is wrong.
func since(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	if d < time.Minute {
		// Covers a clock ahead of ours as well; a skew between here and the box
		// is not worth reporting as a negative age.
		return "now"
	}

	days, hours, mins := int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60
	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	// Minutes are shown unless they are zero AND something larger was, so a
	// duration is never an empty string.
	if mins > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%dm", mins))
	}
	return strings.Join(parts, " ")
}
