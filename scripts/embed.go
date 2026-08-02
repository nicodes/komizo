package scripts

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

// The server-side shell, shipped over SSH and run as root on the box.
//
// ALL of it lives here as .sh files, and none of it is built with fmt.Sprintf.
// That second half is the point.
//
// Shell held in a Go FORMAT string has to have every literal '%' doubled, and
// '%' is not rare in shell -- it is parameter expansion (${a%.env}), printf,
// arithmetic modulo, and date formats. The sampler alone carried all four
// meanings in one string, plus Go's own verbs on top. Miss one doubling and the
// meaning changes SILENTLY, in code that runs as root.
//
// alpine.sh already learned this and says so in its own comments: it used to be
// an unquoted heredoc with every '$' hand-escaped, "where one missed backslash
// silently moved an expansion from deploy time to install time -- the worst
// possible failure mode for the most security-sensitive file on the box". The
// fix there was to write ordinary shell and spell the substituted values
// __LIKE_THIS__. This is the same fix, applied to the half that was still in Go.
//
// So: the files are ordinary shell. They are syntax-highlighted, greppable,
// runnable by hand, printed verbatim by `komizo script`, and checked by
// shellcheck through one glob -- none of which is true of a Go string.

//go:embed alpine.sh
var AlpineScript string

//go:embed alpine-remove.sh
var AlpineRemoveScript string

//go:embed alpine-init.sh
var AlpineInitScript string

//go:embed alpine-proxy.sh
var AlpineProxyScript string

// The read-only halves: what the interface and the sampler run to describe a
// box. Not printed by `komizo script` -- they change nothing -- but they run on
// the same server and get the same treatment.

//go:embed inventory.sh
var inventory string

//go:embed metrics.sh
var metrics string

//go:embed system-log.sh
var systemLog string

//go:embed storage.sh
var storage string

//go:embed sampler.sh
var sampler string

//go:embed sampler-install.sh
var samplerInstall string

// agent-install.sh puts komizo-box on the box and starts it. The binary itself
// travels on its own connection -- see AgentInstall.

//go:embed agent-install.sh
var agentInstall string

// The pieces more than one script needs. Spliced in by placeholder rather than
// duplicated: the cgroup handling is the fiddly part, and two copies would
// drift in the direction of whichever nobody was looking at.

//go:embed lib-state.sh
var libState string

//go:embed lib-system-probe.sh
var libSystemProbe string

//go:embed lib-volume-probe.sh
var libVolumeProbe string

// leftover matches a placeholder that nothing replaced.
var leftover = regexp.MustCompile(`__[A-Z][A-Z0-9_]*__`)

// render substitutes __PLACEHOLDER__ values into a script and refuses to return
// one that still has any left.
//
// The refusal is the safety property. A renamed placeholder, or a caller that
// forgot one, would otherwise ship a literal __APP__ to a server and fail
// somewhere much later with a message about a directory that does not exist.
// alpine.sh guards its own substitution the same way, and calls a leftover what
// it is: a komizo bug.
//
// Panics rather than returning an error because every caller passes a fixed set
// of keys decided at compile time. A leftover is unreachable unless the code is
// wrong, and threading an error through would only move the same crash further
// from its cause.
func render(script string, subs ...string) string {
	if len(subs)%2 != 0 {
		panic("scripts.render: odd number of substitution arguments")
	}
	out := strings.NewReplacer(subs...).Replace(script)
	if m := leftover.FindString(out); m != "" {
		panic(fmt.Sprintf("scripts.render: %s was never substituted -- this is a komizo bug", m))
	}
	return out
}

// ShQuote wraps a value for a shell command line.
//
// Single quotes, with any single quote in the value closed, escaped and
// reopened -- the one form that is safe for arbitrary text in POSIX sh.
//
// Exported and living HERE because this is the package that builds shell. The
// app package had its own copy; it now calls this one, so there is a single
// definition of the rule that makes every quoted value in this tool safe.
func ShQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
