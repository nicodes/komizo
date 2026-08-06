package scripts

import (
	"fmt"
	"maps"
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
		// The two OPTIONAL ones. They run as root like the rest, and until
		// komizo#59 they were the only scripts this package can produce that no
		// whole-script check ever saw -- shellcheck reads them as files, but
		// nothing looked at what a builder actually renders, and nothing would
		// have seen a heredoc added inside one.
		"agent-enrol":   AgentEnrol("https://api.komizo.dev", "kmz_enr_abc", "komizo.example.com", []string{"kmz_dev_abcdefgh"}, false),
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

// requireShellcheck turns a skip into a failure.
//
// komizo-be docs/checks.md #1: a check that cannot run must not be indistinguishable from
// a check that passed. `make check` and CI both set this, because in both of
// those a missing tool is the check not happening; a contributor running
// `go test ./...` on a machine without shellcheck still gets a skip, which is
// the honest answer there.
const requireShellcheck = "KOMIZO_REQUIRE_SHELLCHECK"

// needPinnedShellcheck ends the test unless the shellcheck on PATH is the one
// .mise.toml installs.
//
// THE VERSION, not just the presence -- komizo#59, and the hole that survived
// the first attempt at it. The Makefile grew a version comparison for its own
// `shellcheck scripts/*.sh` line, but these tests resolve the tool with
// exec.LookPath, so on a machine with 0.9.0 installed `make check` printed
// "shellcheck 0.11.0 (docker)" and then linted all six templates with 0.9.0 --
// which fails on the very line komizo#59 cites as the reason to pin. And with
// shellcheck absent but docker present it printed the same line and SKIPPED the
// six entirely, so the whole of #59 was a green tick.
//
// The version belongs here rather than only in the Makefile because this is
// where the tool is actually invoked. A check that reads its own requirements
// cannot be routed around by whatever called it.
func needPinnedShellcheck(t *testing.T) {
	t.Helper()
	want := shellcheckPin(t)

	unusable := func(format string, a ...any) {
		t.Helper()
		msg := fmt.Sprintf(format, a...)
		if os.Getenv(requireShellcheck) != "" {
			t.Fatalf("%s.\n%s is set, so this is a failure rather than a skip -- "+
				"the shell that runs as root on a box would otherwise go unchecked "+
				"and the run would still be green.", msg, requireShellcheck)
		}
		t.Skipf("%s -- `mise install` gets it", msg)
	}

	if _, err := exec.LookPath("shellcheck"); err != nil {
		unusable("shellcheck %s is not installed", want)
	}
	out, err := exec.Command("shellcheck", "--version").Output()
	if err != nil {
		unusable("shellcheck is on PATH but will not report its version: %v", err)
	}
	got := ""
	for _, ln := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "version: "); ok {
			got = v
			break
		}
	}
	if got != want {
		unusable("shellcheck %s is on PATH but .mise.toml pins %s, and they disagree "+
			"about real rules (0.9.0 raises SC2015 on `A && B || continue`, 0.11.0 "+
			"does not)", got, want)
	}
}

// shellcheckPin is the version .mise.toml installs.
//
// Read out of the file rather than written here, so there is one number. A pin
// that cannot be found is fatal in every case, including a plain `go test`:
// unlike a missing tool, it means the repository is inconsistent with itself
// and no version of this check is the right one to run.
func shellcheckPin(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", ".mise.toml"))
	if err != nil {
		t.Fatalf("cannot read the shellcheck pin: %v", err)
	}
	m := regexp.MustCompile(`(?m)^shellcheck *= *"([^"]+)"`).FindSubmatch(b)
	if m == nil {
		t.Fatal("no shellcheck pin in .mise.toml -- the lint has no version to be, " +
			"and whichever one happens to be installed would silently become the standard")
	}
	return string(m[1])
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
	needPinnedShellcheck(t)
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

// heredocBody is what a heredoc actually delivers, which is not always what the
// source looks like.
//
// `<<-` IS NOT A SPELLING VARIANT OF `<<`. It strips a leading TAB from every
// line of the body and lets the terminator be indented, so reading the source
// verbatim gives text no box ever receives -- and, worse, looking for the
// terminator at column 0 finds nothing, drops the template, and leaves every
// check built on it quietly measuring one script fewer.
//
// That is not hypothetical: `scripts/alpine.sh` uses `<<-EOF` three times
// today, and adding a `-` to one of the quoted tags -- a refactor with no
// semantic effect -- used to delete a root-run script from the lint in silence.
func heredocBody(rest, tag string, dash bool) (string, bool) {
	var body strings.Builder
	for _, ln := range strings.Split(rest, "\n") {
		text := ln
		if dash {
			text = strings.TrimLeft(ln, "\t")
		}
		if text == tag {
			return body.String(), true
		}
		body.WriteString(text)
		body.WriteString("\n")
	}
	return "", false
}

// shippedTemplates is every script komizo writes ONTO a box from inside another
// script: the body of each quoted heredoc, with placeholders substituted, keyed
// by "<file>:<TAG>".
//
// Found by scanning for the heredocs rather than from a list kept here, because
// a list here is the thing that goes stale. A template added later is covered
// without anybody editing this file.
//
// A SHEBANG is what marks a heredoc as shell. alpine-proxy.sh writes a Caddy
// config the same way, and Caddy config is not shell -- so "it declares itself a
// script" is the rule, which is self-describing and needs no exception list.
//
// Placeholder values are irrelevant to whether the result parses or lints, so
// unknown ones get a path-shaped literal. What matters is that no
// __PLACEHOLDER__ survives to be read as a bare word where a command belongs.
func shippedTemplates(t *testing.T) map[string]string {
	t.Helper()
	heredoc := regexp.MustCompile(`<<(-?)'([A-Z_]+)'\n`)
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
			dash, tag := src[m[2]:m[3]] == "-", src[m[4]:m[5]]
			body, ok := heredocBody(src[m[1]:], tag, dash)
			if !ok {
				t.Errorf("%s: heredoc %s is never closed", name, tag)
				continue
			}
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
	// A FLOOR, not a zero check. `len(out) == 0` on its own was not enough: a
	// `<<'TAG'` changed to `<<-'TAG'` dropped ONE template -- the secret helper,
	// which runs as root -- out of the lint, the parse and the placeholder
	// check, and five remained, so nothing fired. komizo-be docs/checks.md #1: the
	// all-clear and the ran-on-less-than-it-thought were the same signal.
	//
	// Six today. Adding a seventh needs no edit here; losing one is meant to be
	// something a person looks at, because a template leaving this map leaves
	// every check in this file at the same time.
	const shipped = 6
	if len(out) < shipped {
		t.Fatalf("the heredoc scan found %d shipped templates, and there are at least %d.\n"+
			"  Every check built on this map just got smaller without failing. If one was\n"+
			"  genuinely removed, lower the floor deliberately; if one was re-spelled --\n"+
			"  `<<-` instead of `<<`, an indented terminator -- fix the scan.\n"+
			"  Found: %v", len(out), shipped, slices.Sorted(maps.Keys(out)))
	}
	return out
}

// FIVE OF THE SIX SCRIPTS KOMIZO WRITES ONTO A BOX WERE PARSED AND NEVER LINTED.
//
// komizo#59. TestShellcheck above reads the FILES in this directory, and inside
// those files each of these templates is the body of a QUOTED heredoc -- a
// string literal, which shellcheck never treats as shell. Six programs, all run
// as root: the per-app deploy script and the secret helper out of alpine.sh,
// three OpenRC service files out of agent-install.sh, and the boot-time
// firewall script out of alpine-init.sh.
//
// `sh -n` over them is not this check. It catches an unbalanced quote and an
// unclosed block and nothing else -- not an unquoted expansion that word-splits
// on a path with a space in it, not a `read` without -r, not a variable used
// before it is set. That is the class that actually reaches a box, because the
// script runs fine until the one input that breaks it.
//
// EVERY template, from the scan, rather than a named subset. The deploy script
// was linted alone for a while and the reason was honest -- the OpenRC files
// raise SC2034 on every variable OpenRC itself consumes, and doing that
// properly is work. It is done: see agent-install.sh, where the exemption is
// argued next to the code and then pinned from outside by the test below, which
// is a stronger check than the one being disabled rather than a way around it.
//
// Written to files with their template names, so a complaint says which heredoc
// in which script it is about. Line numbers are into the BODY, which is what a
// person editing alpine.sh is looking at anyway.
func TestEveryShippedTemplatePassesShellcheck(t *testing.T) {
	needPinnedShellcheck(t)
	dir := t.TempDir()
	var files []string
	for name, body := range shippedTemplates(t) {
		f := filepath.Join(dir, strings.ReplaceAll(name, ":", "--")+".sh")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	// Sorted, so a failure reads the same way twice running. Map order is not.
	sort.Strings(files)

	// -s sh and no excludes, for the reasons TestShellcheck gives. Anything
	// reported is either a defect or an exemption argued in the script.
	args := append([]string{"-s", "sh"}, files...)
	if out, err := exec.Command("shellcheck", args...).CombinedOutput(); err != nil {
		t.Errorf("shellcheck over the scripts komizo writes onto a box: %v\n%s\n"+
			"(each file is one heredoc body; the name is <script>--<TAG> and the line numbers are into that body)",
			err, out)
	}
}

// And every one of them still PARSES, which is the check that catches a script
// that cannot run at all.
//
// Kept separate from the lint above rather than folded into it, because they
// have different failure modes and different requirements: this one needs `sh`,
// which is everywhere, and shellcheck's absence must not take it down with it.
// A box receiving a script with an unclosed `if` finds out at the moment the
// script runs, as root, halfway through a deploy.
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

// THE PRICE OF THE SC2034 DISABLE, PAID.
//
// The three OpenRC service files carry `# shellcheck disable=SC2034`, and that
// is a file-scope disable of a real rule in a file that runs as root. The
// argument for it is in agent-install.sh: an OpenRC service file is
// configuration written in shell syntax, openrc-run sources it and reads the
// variables, and nothing in the file uses them -- so SC2034 fires on all
// twenty-two assignments and every one of those reports is wrong.
//
// What that disable costs is the thing SC2034 would otherwise have caught:
// `comand_args="serve"`. OpenRC does not read that name, so the service starts
// with no arguments and no complaint from anything -- an agent that runs, looks
// healthy to rc-status, and does the wrong job.
//
// So the exemption is a swap, and it is only a fair one if the replacement
// covers everything the disable switches off. It did not at first: the disable
// sits before the first command, which makes it FILE-scoped -- reaching inside
// depend() and covering an assignment written with a leading space -- while
// this check only looked at column zero. Two live gaps, and the comment on
// unknownOpenRCNames asserted the opposite of what the code did. Both are shut
// by reading EVERY assignment in the file, which is also the truer rule: one of
// these files is configuration, so an assignment in it that OpenRC does not
// read is a mistake wherever it appears.
//
// Against what it replaces it is stronger in one direction and narrower in
// another, and both are worth stating. Stronger: SC2034 would accept
// `comand_args` the moment any line mentioned it, and this never does, because
// it is checked against OpenRC's own shell. Narrower: SC2034 also reports a
// genuinely unused local, which this cannot -- so a local is refused outright
// rather than allowed through unexamined.
//
// Identified by SHEBANG, so a fourth service added later is covered without
// this list being edited -- the same rule shippedTemplates uses to decide what
// is shell at all.
func TestAnOpenRCServiceOnlyAssignsNamesOpenRCReads(t *testing.T) {
	found := 0
	for name, body := range shippedTemplates(t) {
		if !strings.HasPrefix(body, "#!/sbin/openrc-run") {
			continue
		}
		found++
		for _, n := range unknownOpenRCNames(body) {
			t.Errorf("%s assigns %q, which is not a name openrc-run or supervise-daemon reads.\n"+
				"  SC2034 is disabled for the WHOLE of that file -- see agent-install.sh -- so\n"+
				"  nothing else would report it, at any indentation or inside any function, and\n"+
				"  on the box it would simply be ignored.\n"+
				"  If OpenRC does read it, add it to openRCReads with where that is documented.\n"+
				"  If it is meant to be a local variable, it cannot be: move the disable off\n"+
				"  file scope first, because nothing would tell you it had gone unused.", name, n)
		}
	}
	// The three that exist today. A scan that stopped matching would leave this
	// test iterating nothing and passing, which is the shape komizo-be#101 is
	// about: the all-clear and the never-ran are the same signal.
	if found < 3 {
		t.Fatalf("found %d OpenRC service templates, expected at least the three in agent-install.sh -- the scan has stopped finding them", found)
	}
}

// And the check above can actually fail.
//
// A positive control, because everything TestAnOpenRCServiceOnlyAssignsNamesOpenRCReads
// looks at is clean by construction: if unknownOpenRCNames stopped finding
// assignments at all -- a regexp that no longer matches, a body read from the
// wrong place -- it would report nothing, which is exactly what "all names are
// known" looks like. This is the one input where the two answers differ.
//
// The typo is the real one: `comand_args` is a plausible slip and the failure it
// causes on a box is invisible.
func TestUnknownOpenRCNamesFindsATypo(t *testing.T) {
	got := unknownOpenRCNames(`#!/sbin/openrc-run
name="komizo-agent"
comand_args="agent"
export respwan_delay=5
readonly command_user="komizo_monitor"
 indented_typo="x"
respawn_delay=5

depend() {
	unused_here=1
	need net
}
`)
	// Every form the file-scope SC2034 disable stops shellcheck reporting: the
	// bare typo, the export, the one-space indent, and one inside a function.
	// The three real names must not appear.
	want := []string{"comand_args", "respwan_delay", "indented_typo", "unused_here"}
	if !slices.Equal(got, want) {
		t.Errorf("unknownOpenRCNames = %v, want %v.\n"+
			"  A local inside a function is not a service variable; `export` and `readonly`\n"+
			"  are assignments and must not hide one; and the real names must not be reported.", got, want)
	}
}

// unknownOpenRCNames is every assignment in an OpenRC service file whose name
// OpenRC does not read.
//
// EVERY assignment, at any indentation, anywhere in the file -- including
// inside depend(). An earlier version anchored at `^` with no leading
// whitespace and claimed that assignments inside functions were still covered
// by SC2034. They are not: the disable in these files sits before the first
// command, which makes it FILE-scoped, so it reaches into depend() too. That
// left two live gaps and the comment asserted the opposite of the code:
//
//	 comand_args="rootd"    one leading space, invisible to `^`, and OpenRC
//	                        sources the file so the space changes nothing
//	depend() { unused=1; }  inside a function, and SC2034 disabled for it
//
// The rule is therefore stated the way the file actually works: an OpenRC
// service file is pure configuration, so EVERY assignment in one is a value
// OpenRC reads, and anything else is a mistake. That is a stronger claim than
// SC2034 makes and it needs no whitespace rules or brace counting to hold. If
// one of these ever genuinely needs a local variable, the disable has to stop
// being file-scoped first -- and this failing is what says so.
//
// `export` and `readonly` are consumed first because they are assignments too,
// and a regexp that only knew the bare form would MISS a typo rather than
// report it -- the failure direction that matters here, since the whole point
// of this check is that nothing else is looking.
func unknownOpenRCNames(body string) []string {
	assign := regexp.MustCompile(`(?m)^[ \t]*(?:export |readonly )?([A-Za-z_][A-Za-z0-9_]*)=`)
	var out []string
	for _, m := range assign.FindAllStringSubmatch(body, -1) {
		if !openRCReads[m[1]] {
			out = append(out, m[1])
		}
	}
	return out
}

// openRCReads is what openrc-run and supervise-daemon consume out of a service
// file.
//
// READ OUT OF OPENRC, not remembered. Every name here is dereferenced by
// Alpine's own openrc package, in
//
//	/usr/libexec/rc/sh/openrc-run.sh
//	/usr/libexec/rc/sh/start-stop-daemon.sh
//	/usr/libexec/rc/sh/supervise-daemon.sh
//
// which is where a service file's variables actually get turned into flags:
// `${directory:+--chdir} $directory`, `${command_user+--user} $command_user`.
// To check or extend this list, grep those three files for the name. That is a
// two-minute job and it is the difference between a list and a guess.
//
// It matters because a name that is on this list and NOT read by OpenRC makes
// the check weaker than the SC2034 it stands in for: the typo it exists to
// catch would sail through. `command_group` was on an earlier draft of this
// list for exactly that reason -- `command_user` takes "user:group", there is
// no separate group variable, and OpenRC's shell does not mention the name once.
//
// Deliberately NOT the whole of OpenRC's vocabulary -- the internals
// (`start_time`, `child_pid`) and the rc.conf settings (`rc_ulimit`,
// `rc_cgroup_cleanup`) are left off. It is what these three files use plus the
// near neighbours somebody would reach for next, so adding one is a moment of
// thought rather than a lookup that always succeeds. A missing name fails
// loudly and is one line to fix; a wrong name fails silently forever.
var openRCReads = map[string]bool{
	// openrc-run.sh: what the service is and how rc-service addresses it.
	"name": true, "description": true, "extra_commands": true,
	"extra_started_commands": true, "extra_stopped_commands": true,
	"required_dirs": true, "required_files": true,
	// start-stop-daemon.sh: what to run, as whom, from where.
	"command": true, "command_args": true, "command_args_background": true,
	"command_args_foreground": true, "command_background": true,
	"command_user": true, "directory": true, "procname": true,
	"pidfile": true, "umask": true, "retry": true, "stopsig": true,
	"start_stop_daemon_args": true,
	// supervise-daemon.sh: the restart policy, which is why this box uses a
	// supervisor at all -- a crashed agent that is not restarted looks exactly
	// like a box that is down.
	"supervisor": true, "respawn_delay": true, "respawn_max": true,
	"respawn_period": true, "supervise_daemon_args": true,
	"healthcheck_timer": true, "healthcheck_delay": true,
	// Where the daemon's own output goes, read by both.
	"output_log": true, "error_log": true,
	"output_logger": true, "error_logger": true,
}

// NOTHING WRITES A SCRIPT THROUGH AN UNQUOTED HEREDOC.
//
// shippedTemplates matches a QUOTED heredoc only, so an unquoted one is
// invisible to every check built on it -- the lint, the parse, the OpenRC
// names. That is a deliberate limit and this is what stops it being a hole.
//
// Unquoted is the wrong tool for shell anyway, and embed.go's own comments say
// why in stronger terms than this could: the outer shell expands every `$` in
// the body as it writes the file, so `$APP_DIR` inside the template resolves at
// INSTALL time to whatever the outer script had, silently, in the most
// security-sensitive file on the box. alpine.sh was written that way once, with
// every `$` hand-escaped, and "one missed backslash silently moved an expansion
// from deploy time to install time".
//
// So a `#!` after an unquoted heredoc is two bugs at once: a script that will
// be mangled, and a script nothing lints. Reported as both.
//
// `<<-` COUNTS. It is a different operator, not a different spelling, and an
// earlier version of this test said `<<-` was worth excluding because nothing
// used it -- which was false when it was written: alpine.sh uses `<<-EOF` three
// times. The three are a doas block, a config append and a terminal message,
// none of them shell; the other unquoted heredocs in this package are a Caddy
// route, a compose.yml and more messages. None declares itself a script, which
// is the same rule shippedTemplates uses to decide what is shell.
func TestNoShellIsWrittenThroughAnUnquotedHeredoc(t *testing.T) {
	// No quotes around the tag, and the quoted form cannot match: after `<<`
	// and an optional `-` the next character must be `[A-Z_]`, and in the
	// quoted spelling it is an apostrophe. An earlier version of this test
	// carried a "was the match preceded by a quote?" guard for that case; it
	// was dead code describing something the regexp already makes impossible.
	unquoted := regexp.MustCompile(`<<(-?)([A-Z_]+)\n`)
	checked := 0
	for name, src := range all(t) {
		for _, m := range unquoted.FindAllStringSubmatchIndex(src, -1) {
			checked++
			dash, tag := src[m[2]:m[3]] == "-", src[m[4]:m[5]]
			body, ok := heredocBody(src[m[1]:], tag, dash)
			if !ok {
				t.Errorf("%s: unquoted heredoc %s is never closed", name, tag)
				continue
			}
			if strings.HasPrefix(body, "#!") {
				t.Errorf("%s writes a script through an UNQUOTED heredoc (<<%s%s).\n"+
					"  The outer shell expands every $ in it at install time -- see embed.go --\n"+
					"  and shippedTemplates cannot see it, so nothing lints or parses it.\n"+
					"  Quote the tag: <<%s%c%s%c",
					name, src[m[2]:m[3]], tag, src[m[2]:m[3]], '\'', tag, '\'')
			}
		}
	}
	// The package does use unquoted heredocs, for a Caddy route, a compose.yml,
	// a doas block and some messages. Finding none means the scan stopped
	// matching, and a loop over nothing passes. komizo-be docs/checks.md #1.
	if checked == 0 {
		t.Fatal("no unquoted heredocs found at all -- this scan has stopped matching, so it is no longer checking anything")
	}
}
