package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
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
		// These two were missing, and the comment above is what they were
		// missing from: "a script added later cannot quietly escape one" was
		// true of the checks and not of the map. Both run as root -- enrol from
		// init.go and enrol.go, unenrol from enrol.go -- and neither was seen by
		// the clampable-number check, the shell parse, the placeholder check, or
		// the heredoc scan built on this map. Demonstrated: a `%d` that overflows
		// 32 bits added to agent-enrol.sh was green, and the identical line in
		// agent-install.sh was caught.
		"agent-enrol":   AgentEnrol("https://api.example", "kmz_enr_x", "api.example", []string{"AAAA"}, false),
		"agent-unenrol": AgentUnenrol(),
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

// shippedTemplates is every script komizo writes ONTO a box from inside another
// script: the body of each quoted heredoc, with placeholders substituted, keyed
// by "<file>:<TAG>".
//
// Found by scanning for the heredocs rather than by a list kept here, because a
// list here is the thing that goes stale -- see the CI guard this package's
// checks are run by, which named two tests, one of which had moved and one of
// which no longer existed, and passed for however long on "no tests to run".
// A template added later is covered without anybody editing this file.
//
// A SHEBANG is what marks a heredoc as shell. alpine-proxy.sh writes a Caddy
// config the same way, and Caddy config is not shell -- so "it declares itself a
// script" is the rule, which is self-describing and needs no exception list.
//
// Placeholder values are irrelevant to whether the result parses, so unknown
// ones get a path-shaped literal. What matters is that no `__PLACEHOLDER__`
// survives to be read as a bare word where a command belongs.
func shippedTemplates(t *testing.T) map[string]string {
	t.Helper()
	// EVERY SPELLING OF A HEREDOC, not the one this repo happens to use today.
	//
	// This was `<<'([A-Z_]+)'\n`: single quotes only, uppercase-and-underscore
	// tags only, and a newline required immediately after the closing quote. Five
	// other spellings the shell accepts vanished from the scan in silence --
	// `<<-'TAG'`, `<<"TAG"`, a redirect written after the tag, a tag with a digit
	// in it, a lowercase tag. A new root-run template opened any of those ways
	// was simply not there, and the comment above promises the opposite.
	//
	// Matched to the end of the physical line rather than to `\n` so that
	// `cat <<'TAG' > /path` is found. The tag pattern is the shell's own rule for
	// a name. The three quotings are spelled out rather than captured and
	// back-referenced because RE2 has no backreferences -- so each alternative
	// pins its own closing quote, which is the same guarantee written longhand.
	heredoc := regexp.MustCompile(`<<-?[ \t]*(?:'([A-Za-z_][A-Za-z0-9_]*)'|"([A-Za-z_][A-Za-z0-9_]*)"|([A-Za-z_][A-Za-z0-9_]*))[^\n]*\n`)
	placeholder := regexp.MustCompile(`__[A-Z][A-Z_]*__`)
	known := map[string]string{
		"__APP_NAME__":        "web",
		"__APP_DIR__":         "/srv/web",
		"__CONFIG_IMAGE__":    "registry.example/web-config",
		"__PROXY_CONTAINER__": "komizo-proxy",
		"__PROXY_DIR__":       "/srv/komizo-proxy",
		"__ROUTES_DIR__":      "/srv/komizo-proxy/routes",
		"__STATE_DIR__":       "/var/lib/komizo/apps",
	}
	out := map[string]string{}
	for name, src := range all(t) {
		for _, m := range heredoc.FindAllStringSubmatchIndex(src, -1) {
			tag := ""
			for _, g := range [][2]int{{m[2], m[3]}, {m[4], m[5]}, {m[6], m[7]}} {
				if g[0] >= 0 {
					tag = src[g[0]:g[1]]
					break
				}
			}
			rest := src[m[1]:]
			j := strings.Index(rest, "\n"+tag+"\n")
			if j < 0 {
				// `<<-` strips leading tabs from the terminator too.
				if k := strings.Index(rest, "\n\t"+tag+"\n"); k >= 0 {
					j = k
				} else {
					t.Errorf("%s: heredoc %s is never closed", name, tag)
					continue
				}
			}
			body := rest[:j+1]
			if !strings.HasPrefix(body, "#!") {
				continue // not a script -- alpine-proxy.sh writes Caddy config this way
			}
			for _, ph := range placeholder.FindAllString(body, -1) {
				v, ok := known[ph]
				if !ok {
					v = "/srv/komizo-substituted"
				}
				body = strings.ReplaceAll(body, ph, v)
			}
			out[name+":"+tag] = body
		}
	}
	// THE SET, not the count, and certainly not "more than nothing".
	//
	// `len(out) == 0` was the only control, so the scan could fall from six
	// templates to one and every check built on it would go on passing for the
	// five it had stopped looking at. A scan is only as good as the proof that it
	// still finds what it found yesterday.
	//
	// This is a list, which is the thing the comment above says it is avoiding,
	// and the difference is what happens when it is wrong. A list used to SELECT
	// goes stale silently -- the scan stops finding a template and nothing says
	// so. A list used to CHECK a scan fails loudly in both directions: a template
	// that leaves is a bug, and a template that joins is a one-line decision
	// somebody makes on purpose, with the new name in front of them.
	want := []string{
		"agent-install:KOMIZO_AGENT_RC_EOF",
		"agent-install:KOMIZO_API_RC_EOF",
		"agent-install:KOMIZO_RC_EOF",
		"alpine-init:EOF",
		"alpine:KOMIZO_DEPLOY_EOF",
		"alpine:KOMIZO_SECRET_EOF",
	}
	// A SECOND, UNRELATED SIGNAL for the same question, because the set check
	// above cannot see the failure that matters most.
	//
	// A template the scan never finds is absent from `got` AND from `want`, so
	// the two agree and the check passes -- the one shape of mistake that
	// silently shrinks coverage is the one shape the set comparison is blind to.
	// A list can only police templates somebody already knew about.
	//
	// So: every one of these templates is a script, and every script begins with
	// a shebang at the start of a line. Counting embedded shebangs asks "how many
	// scripts are in here" without going anywhere near heredoc syntax, so a
	// heredoc spelling the regex does not know about makes the two disagree. Two
	// independent implementations of the same count, and they have to match.
	//
	// A `#!` that is not a template -- inside a comment, or echoed -- would fail
	// this. That is the right outcome: it is a line that reads exactly like the
	// start of a shipped script, and somebody should decide which it is.
	for name, src := range all(t) {
		embedded := strings.Count(src, "\n#!")
		n := 0
		for k := range out {
			if strings.SplitN(k, ":", 2)[0] == name {
				n++
			}
		}
		if embedded != n {
			t.Errorf("%s has %d embedded shebangs but the heredoc scan found %d templates in it -- "+
				"a script is being written onto a box that nothing here parses, lints or substitutes", name, embedded, n)
		}
	}

	var got []string
	for k := range out {
		got = append(got, k)
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Errorf("the heredoc scan found\n  %v\nand the shipped templates are\n  %v\n"+
			"A template missing here is one that nothing parses, lints or substitutes -- it ships to a box as root unchecked. "+
			"A template added here is fine: add it to the list.", got, want)
	}
	return out
}

// NOTHING EVER PARSED THE SCRIPTS THAT RUN ON A BOX.
//
// TestEveryScriptIsValidShell and TestShellcheck both read the FILES in this
// directory. Inside those files each of these templates is the body of a QUOTED
// heredoc, which is a string literal -- so neither `sh -n` nor shellcheck ever
// treated a line of one as shell. Six programs, all run as root: the per-app
// deploy script and the secret helper out of alpine.sh, three OpenRC init
// scripts out of agent-install.sh, and the boot-time firewall script out of
// alpine-init.sh.
//
// Demonstrated rather than argued. Planted inside revert() in the deploy script,
// on the tree before this test existed: an unclosed `if`, and an unbalanced
// quote. Both left `shellcheck -s sh scripts/*.sh` clean AND `go test ./...`
// green. Either would have installed fine and died at the first rollback --
// the path that only runs when something else has already gone wrong, so the
// failure arrives on top of another failure, at the worst moment to be reading
// a log.
//
// deploy_stopped_test.go lifts two blocks out of one of these and runs them,
// which is exactly why the gap was easy to miss: the parts under test parse,
// and everything else was unexamined.
func TestEveryShippedTemplateIsValidShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	placeholder := regexp.MustCompile(`__[A-Z][A-Z_]*__`)
	for name, body := range shippedTemplates(t) {
		if left := placeholder.FindString(body); left != "" {
			t.Errorf("%s: %s survived substitution, so this is not what a box receives", name, left)
			continue
		}
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(body)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s is not valid shell: %v\n%s", name, err, out)
		}
	}
}

// And the deploy script linted, which `sh -n` cannot be -- see TestShellcheck
// for the argument.
//
// TestShellcheck deliberately runs over the files, and says why: a rendered
// script has its placeholders replaced, so a complaint about the substitution
// would point at a line nobody can edit. That reasoning is right, and it leaves
// these bodies uncovered, because in the file each one is a string.
//
// ONLY THE DEPLOY SCRIPT, for now. It is the one that runs on every deploy, and
// it is clean. The other five are not yet: the three OpenRC init scripts raise
// SC2034 on every variable OpenRC itself consumes (`name`, `command`,
// `command_user`, `respawn_delay`), which needs a disable and a reason on each
// rather than a blanket exclude -- this package's rule, stated in TestShellcheck.
// Tracked in komizo#59; TestEveryShippedTemplateIsValidShell parses all of them in
// the meantime, which is what catches a script that cannot run at all.
func TestTheGeneratedDeployScriptPassesShellcheck(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck is not installed")
	}
	const key = "alpine:KOMIZO_DEPLOY_EOF"
	body, ok := shippedTemplates(t)[key]
	if !ok {
		t.Fatalf("%s is no longer among the shipped templates -- has the deploy script moved out of its heredoc?", key)
	}
	f := filepath.Join(t.TempDir(), "deploy.sh")
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("shellcheck", "-s", "sh", f).CombinedOutput(); err != nil {
		t.Errorf("shellcheck on the generated deploy script: %v\n%s\n"+
			"(the source is alpine.sh's KOMIZO_DEPLOY_EOF heredoc; line numbers are into that body)", err, out)
	}
}
