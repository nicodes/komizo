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
// arithmetic modulo, and date formats. One script alone carried all four
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

// AlpineReloadSSHDScript applies the sshd config every app in an update wrote.
//
// Separate from alpine.sh because it runs ONCE per update rather than once per
// app -- komizo#65. alpine.sh validates its own edit and defers; this is what
// makes the deferral safe to have.
//
//go:embed alpine-reload-sshd.sh
var AlpineReloadSSHDScript string

//go:embed alpine-init.sh
var AlpineInitScript string

//go:embed alpine-proxy.sh
var AlpineProxyScript string

// agent-install.sh puts komizo-box on the box and starts it.
//
// The read-only half of what komizo used to pipe at a server -- the inventory,
// the request counts, the cgroup reads -- is not here any more. It is Go, in
// internal/box, running on the box as komizo-box. What is left in this package
// is the half that PROVISIONS: it runs once, as root, and changes the machine.
//
// The binary itself travels on its own connection -- see AgentInstall.

//go:embed agent-install.sh
var agentInstall string

// agent-enrol.sh and agent-unenrol.sh point a box at a komizo service, and
// stop it reporting. Both run as root; both are optional, permanently.

//go:embed agent-enrol.sh
var agentEnrol string

//go:embed agent-unenrol.sh
var agentUnenrol string

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
	// Checked against the TEMPLATE, not the output.
	//
	// Against the output it also fires on VALUES, and one of the values is now a
	// device key: base64url includes uppercase and underscore, so a key with
	// __BC__ anywhere in it crashed the CLI claiming a komizo bug. The check is
	// about placeholders somebody forgot to pass, which is a property of the
	// script, so the script is what it reads.
	seen := map[string]bool{}
	for i := 0; i < len(subs); i += 2 {
		seen[subs[i]] = true
	}
	for _, m := range leftover.FindAllString(script, -1) {
		if !seen[m] {
			panic(fmt.Sprintf("scripts.render: %s was never substituted -- this is a komizo bug", m))
		}
	}
	return strings.NewReplacer(subs...).Replace(script)
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
