package scripts

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// every script this package can produce, named for a failure message.
//
// One list, so a check added below covers all of them and a script added later
// cannot quietly escape one. The builders are called with values shaped like
// the real ones -- a leftover placeholder panics inside render(), so simply
// building this map is itself an assertion.
func all(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"alpine":        AlpineScript,
		"alpine-init":   AlpineInitScript,
		"alpine-proxy":  AlpineProxyScript,
		"alpine-remove": AlpineRemoveScript,
		"agent-install": AgentInstall("94d5dbd1333d", "0.0.11"),
	}
}

// A placeholder nothing replaced must never reach a server.
//
// render() panics on one, so this is really a test that every builder passes
// the full set of keys its script expects. It is the check that replaces the
// class of bug the old fmt.Sprintf templates had: there, a missing argument was
// a %!s(MISSING) shipped to a box as root.
func TestNoScriptShipsAnUnsubstitutedPlaceholder(t *testing.T) {
	left := regexp.MustCompile(`__[A-Z][A-Z0-9_]*__`)
	for name, s := range all(t) {
		// alpine.sh substitutes its own placeholders ON the server, with sed,
		// so the copy shipped there still carries them by design. Everything
		// else is fully rendered before it leaves this machine.
		if strings.HasPrefix(name, "alpine") {
			continue
		}
		if m := left.FindString(s); m != "" {
			t.Errorf("%s still contains %s", name, m)
		}
	}
}

// BusyBox awk clamps printf %d to 32 bits.
//
// A disk over 2GB printed as -2147483648, the reader refused the negative byte
// count, and the index drew no disk bar at all -- on every box whose disk was
// bigger than 2GB, which is every box. Anything that can pass 2^31 -- byte
// counts, cumulative jiffies, cumulative microseconds -- must print with %.0f,
// which is exact to 2^53.
//
// Checked over EVERY script rather than only the probe it was found in. The
// original test read one Go constant; now that the shell is files, the same
// mistake could be made in any of them.
// An exemption is claimed IN THE SCRIPT, on the line above, as
//
//	# clamp-ok: <why this number cannot reach 2^31>
//
// rather than by a list of substrings kept here. A list here goes stale
// silently -- it matched "cores" and would have gone on matching it after the
// line moved -- and it puts the argument somewhere the person editing the awk
// will not see. Requiring the comment makes each %d a decision with a reason
// attached, next to the thing it is about.
//
// Generalising this from one Go constant to every script is what found the
// mspan timestamps, which would have started printing negative in 2038.
func TestNoScriptPrintsAClampableNumber(t *testing.T) {
	for name, s := range all(t) {
		lines := strings.Split(s, "\n")
		exempt := false
		for i, ln := range lines {
			trimmed := strings.TrimSpace(ln)
			if strings.HasPrefix(trimmed, "#") {
				// An exemption covers the run of code after it, until the next
				// blank line -- enough for a multi-line printf, not enough to
				// silently cover the rest of the file.
				if strings.Contains(trimmed, "clamp-ok:") {
					exempt = true
				}
				continue
			}
			if trimmed == "" {
				exempt = false
				continue
			}
			if !strings.Contains(ln, "%d") || exempt {
				continue
			}
			t.Errorf("%s line %d prints with %%d, which BusyBox awk clamps to 32 bits.\n"+
				"  %s\n"+
				"  Use %%.0f, or add `# clamp-ok: <why>` above it.", name, i+1, trimmed)
		}
	}
}

// Everything here is POSIX sh run by Alpine's busybox ash, including the
// fragments that are only ever spliced into another script -- a library that
// does not parse takes its caller down with it.
func TestEveryScriptIsValidShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	for name, s := range all(t) {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s is not valid shell: %v\n%s", name, err, out)
		}
	}
}

// TestShellcheck is the check `sh -n` cannot be.
//
// `sh -n` parses: it catches a heredoc left open or an unbalanced quote, and
// nothing else. It says nothing about an unquoted expansion that word-splits on
// a path with a space in it, a `read` without -r, or a variable used before it
// is set -- the class of defect that actually reaches a server, because the
// script runs fine until the one input that breaks it.
//
// Run over the FILES rather than the rendered output. A rendered script has its
// placeholders replaced, so a lint error introduced by the substitution would be
// invisible in the file a person edits; and the file is the artefact under
// review. Rendering is covered by the tests above.
//
// This lives here now rather than in the app package. It used to reach across
// with a `../../scripts/*.sh` glob and a second list of Go constants -- two
// homes for one question. There is one home.
func TestShellcheck(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck is not installed")
	}
	files, err := filepath.Glob("*.sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no *.sh found -- has the layout changed?")
	}
	// -s sh, not bash: these run under Alpine's busybox ash, and checking them
	// as bash would accept arrays and [[ ]] the box cannot run.
	//
	// No severity floor and no blanket excludes. Everything it reports is a
	// deliberate idiom carrying a `# shellcheck disable=` with its reason beside
	// it, which is the honest place for that argument.
	args := append([]string{"-s", "sh"}, files...)
	if out, err := exec.Command("shellcheck", args...).CombinedOutput(); err != nil {
		t.Errorf("shellcheck: %v\n%s", err, out)
	}
}

// The rule that makes every quoted value in this tool safe, now that there is
// one copy of it.
func TestShQuote(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"blog", `'blog'`},
		{"", `''`},
		{"a b", `'a b'`},
		// The case the whole function exists for: a value that would otherwise
		// close the quoting and start a new word.
		{"a'b", `'a'\''b'`},
		{"'; rm -rf /; '", `''\''; rm -rf /; '\'''`},
		{"$(whoami)", `'$(whoami)'`},
		{"`id`", "'`id`'"},
	} {
		if got := ShQuote(c.in); got != c.want {
			t.Errorf("ShQuote(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// A quoted value must survive the shell intact -- the property the tests above
// only assert the shape of.
func TestShQuoteSurvivesTheShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	for _, in := range []string{
		"blog", "a b", "a'b", "$(whoami)", "`id`", "a\nb", `back\slash`, "*", "~",
	} {
		out, err := exec.Command("sh", "-c", "printf %s "+ShQuote(in)).Output()
		if err != nil {
			t.Fatalf("sh failed for %q: %v", in, err)
		}
		if string(out) != in {
			t.Errorf("ShQuote(%q) came back as %q", in, out)
		}
	}
}
