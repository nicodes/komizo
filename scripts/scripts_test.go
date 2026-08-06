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
	heredoc := regexp.MustCompile(`<<'([A-Z_]+)'\n`)
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
			tag := src[m[2]:m[3]]
			rest := src[m[1]:]
			j := strings.Index(rest, "\n"+tag+"\n")
			if j < 0 {
				t.Errorf("%s: heredoc %s is never closed", name, tag)
				continue
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
	if len(out) == 0 {
		t.Fatal("no shell templates found -- the heredoc scan has stopped matching, and every check built on it is now vacuous")
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
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck is not installed")
	}
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
// So the exemption is not a hole, it is a swap. This check knows what OpenRC
// reads, which SC2034 does not, and refuses a name that is not on the list. It
// is strictly stronger than the rule it replaces: SC2034 would have accepted
// `comand_args` the moment anything in the file mentioned it.
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
				"  Nothing in the file uses it either -- SC2034 is disabled there -- so it would be\n"+
				"  silently ignored on the box. If OpenRC really does read it, add it to\n"+
				"  openRCReads with where that is documented.", name, n)
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
respawn_delay=5

depend() {
	local unrelated=1
	need net
}
`)
	want := []string{"comand_args", "respwan_delay"}
	if !slices.Equal(got, want) {
		t.Errorf("unknownOpenRCNames = %v, want %v.\n"+
			"  A local inside a function is not a service variable; `export` and `readonly`\n"+
			"  are assignments and must not hide one; and the real names must not be reported.", got, want)
	}
}

// unknownOpenRCNames is every top-level assignment in an OpenRC service file
// that OpenRC does not read.
//
// TOP LEVEL ONLY -- anchored to the start of the line with no leading space.
// Assignments inside depend() and the like are ordinary shell variables in an
// ordinary function, used by the code around them, and SC2034 is not disabled
// on their account.
//
// `export` and `readonly` are consumed first because they are assignments too,
// and a regexp that only knew the bare form would MISS a typo rather than
// report it -- the failure direction that matters here, since the whole point
// of this check is that nothing else is looking.
func unknownOpenRCNames(body string) []string {
	assign := regexp.MustCompile(`(?m)^(?:export |readonly )?([A-Za-z_][A-Za-z0-9_]*)=`)
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
// shippedTemplates matches `<<'TAG'` only, so an unquoted heredoc is invisible
// to every check built on it -- the lint, the parse, the OpenRC names. That is
// a deliberate limit and this is what stops it being a hole.
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
// The other unquoted heredocs in this package are fine and stay fine: a Caddy
// route, a compose.yml, and several `cat <<EOF` blocks that print a message to
// the terminal. None of them declares itself a script, which is the same rule
// shippedTemplates uses to decide what is shell.
func TestNoShellIsWrittenThroughAnUnquotedHeredoc(t *testing.T) {
	// No quotes around the tag, and not `<<-`, which strips tabs and would need
	// the same argument made separately if anything ever used it.
	unquoted := regexp.MustCompile(`<<([A-Z_]+)\n`)
	checked := 0
	for name, src := range all(t) {
		for _, m := range unquoted.FindAllStringSubmatchIndex(src, -1) {
			// `<<'TAG'` also ends in TAG\n, so skip anything whose match is
			// preceded by a quote -- that is the quoted form, already covered.
			if m[0] > 0 && src[m[0]-1] == '\'' {
				continue
			}
			checked++
			tag := src[m[2]:m[3]]
			rest := src[m[1]:]
			j := strings.Index(rest, "\n"+tag+"\n")
			if j < 0 {
				t.Errorf("%s: unquoted heredoc %s is never closed", name, tag)
				continue
			}
			if strings.HasPrefix(rest[:j+1], "#!") {
				t.Errorf("%s writes a script through an UNQUOTED heredoc (%s).\n"+
					"  The outer shell expands every $ in it at install time -- see embed.go --\n"+
					"  and shippedTemplates cannot see it, so nothing lints or parses it.\n"+
					"  Quote the tag: <<'%s'", name, tag, tag)
			}
		}
	}
	// The package does use unquoted heredocs, for a Caddy route, a compose.yml
	// and some messages. Finding none means the scan stopped matching, and a
	// loop over nothing passes.
	if checked == 0 {
		t.Fatal("no unquoted heredocs found at all -- this scan has stopped matching, so it is no longer checking anything")
	}
}
