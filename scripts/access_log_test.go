package scripts

import (
	"regexp"
	"strings"
	"testing"
)

// EVERY SITE BLOCK KOMIZO GENERATES WRITES AN ACCESS LOG.
//
// nicodes/komizo-be#163. `log` is a per-SITE-BLOCK directive in Caddy: the
// global `log` option configures the RUNTIME log -- TLS renewals, ACME, startup
// -- and there is no global switch for access logs. So a site block without one
// records nothing about requests, and a box generating three kinds of site block
// had it on one of them.
//
// The two that were silent are the two nobody thinks of as traffic:
//
//   - `_catchall.caddy`, where a hostname pointed at this box with no app behind
//     it lands. That is where a scan or a misdirected DNS record shows up, and it
//     is the block whose entire subject is requests nobody expected.
//   - `_komizo.caddy`, the agent's own API. Reads of somebody's server, with no
//     record of who asked or when.
//
// AND IT WAS FOUND BY A CLAIM RATHER THAN BY A FAILURE. alpine-proxy.sh said
// "the access log is a file and rotates itself, see the Caddyfile" beside a
// block that wrote no such thing. Prose asserting wiring that does not exist is
// the shape docs/checks.md keeps recording -- so this file exists to make the
// claim fail rather than to make it read better.
//
// STRUCTURAL, NOT A LIST. It finds site blocks by parsing the Caddy config
// komizo ships, so a NEW route added to any script is held to the rule without
// anybody remembering to add it here. A list is what let the original gap
// through: the per-app route had a log directive and the other two were simply
// never considered.

// caddyBlocks is every Caddy config komizo writes through a heredoc, by the
// script and tag that write it.
//
// Heredoc bodies that declare themselves scripts are skipped -- scripts_test.go
// owns those, and "starts with a shebang" is the same self-describing rule it
// uses rather than a second exception list.
//
// A SLICE, NOT A MAP KEYED BY TAG. Review 1 on this change: alpine-proxy.sh
// already writes two heredocs tagged EOF, so a map keyed name+":"+tag silently
// replaced one with the other. Adding a NEW logged route and deleting the
// catch-all's whole log block left the file green and the count unchanged --
// growing the set shrank the check, which is the shape docs/checks.md records.
func caddyBlocks(t *testing.T) []namedConfig {
	t.Helper()
	heredoc := regexp.MustCompile(`<<(-?)'?([A-Z_][A-Z0-9_]*)'?\n`)
	var out []namedConfig
	for name, src := range all(t) {
		for _, m := range heredoc.FindAllStringSubmatchIndex(src, -1) {
			dash, tag := src[m[2]:m[3]] == "-", src[m[4]:m[5]]
			body, ok := heredocBody(src[m[1]:], tag, dash)
			if !ok || strings.HasPrefix(body, "#!") {
				continue
			}
			// A site block is `<address> {` at column zero. `{` alone is
			// Caddy's global options block, which takes no `log` of this kind.
			if !siteBlocks(body).any() {
				continue
			}
			out = append(out, namedConfig{where: name + ":" + tag, cfg: body})
		}
	}
	if len(out) == 0 {
		t.Fatal("no generated Caddy config found -- either the routes moved or this " +
			"test stopped being able to find them, and either way it is asserting nothing")
	}
	return out
}

// namedConfig is one generated Caddy config and where it came from.
type namedConfig struct {
	where string
	cfg   string
}

// uncommented is shell source with its comments removed, so a check for a call
// cannot be satisfied by a mention of one.
//
// Line-wise and deliberately crude: this reads komizo's own scripts, where a
// `#` inside a string is rare and a false negative costs a spurious red rather
// than a missed mutation. The direction matters more than the precision.
func uncommented(src string) string {
	var out []string
	for _, ln := range strings.Split(src, "\n") {
		if i := strings.Index(ln, "#"); i >= 0 {
			ln = ln[:i]
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

type blocks []string

func (b blocks) any() bool { return len(b) > 0 }

// siteBlocks splits Caddy config into its top-level site blocks, by brace depth.
//
// Depth rather than a regexp for the closing brace: every block in these files
// nests (`log { output file { ... } }`), so "the next line that is `}`" finds
// the wrong one and would let a `log` inside one block satisfy the next.
func siteBlocks(cfg string) blocks {
	var out blocks
	var cur []string
	depth := 0
	for _, ln := range strings.Split(cfg, "\n") {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "#") && depth == 0 {
			continue
		}
		if depth == 0 {
			// The global options block opens with a bare `{` and is not a site.
			if !strings.HasSuffix(trimmed, "{") || trimmed == "{" {
				continue
			}
			cur = nil
		}
		if depth > 0 {
			cur = append(cur, ln)
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if depth == 0 && cur != nil {
			out = append(out, strings.Join(cur, "\n"))
			cur = nil
		}
	}
	return out
}

func TestEveryGeneratedSiteBlockWritesAnAccessLog(t *testing.T) {
	seen := 0
	for _, c := range caddyBlocks(t) {
		for i, b := range siteBlocks(c.cfg) {
			name := c.where
			seen++
			if !strings.Contains(b, "log {") {
				t.Errorf("%s: site block %d writes no access log, so nothing that reaches it "+
					"leaves a trace on the box:\n%s", name, i, b)
				continue
			}
			// AND IN THE FORM box/access.go PARSES. A block that logs in Caddy's
			// console format is a file Probe.Metrics reads and finds nothing in
			// -- a log that exists and answers no question, which is worse than
			// none because it looks like an answer.
			if !strings.Contains(b, "format json") {
				t.Errorf("%s: site block %d logs in a format box/access.go cannot parse:\n%s", name, i, b)
			}
			// AND BOUNDED. This is somebody's disk.
			if !strings.Contains(b, "roll_size") || !strings.Contains(b, "roll_keep") {
				t.Errorf("%s: site block %d writes an unbounded log onto a disk that is not ours:\n%s", name, i, b)
			}
		}
	}
	if seen < 2 {
		t.Errorf("found %d site blocks, want at least the catch-all and the agent's own route -- "+
			"a parser that finds nothing passes this whole file", seen)
	}
}

// THE PER-APP ROUTE IS BUILT WITH printf RATHER THAN A HEREDOC, so the parser
// above cannot see it. It is the route that carries real traffic and the one
// komizo#80's metrics are actually counted from, so it is asserted by name.
func TestThePerAppRouteWritesAnAccessLog(t *testing.T) {
	src := AlpineScript
	if !strings.Contains(src, "access_log()") {
		t.Fatal("alpine.sh no longer defines access_log, so the per-app route's logging moved " +
			"somewhere this test cannot see")
	}
	body, ok := shellFunc(src, "access_log")
	if !ok {
		t.Fatal("could not read access_log's body")
	}
	for _, want := range []string{"output file", "roll_size", "roll_keep", "format json"} {
		if !strings.Contains(body, want) {
			t.Errorf("access_log does not emit %q:\n%s", want, body)
		}
	}
	// AND IT IS CALLED. A generator that defines the block and never emits it is
	// the same empty file, one indirection later -- and that is exactly the
	// mistake #163 was filed about, in the other direction.
	site, ok := shellFunc(src, "site")
	if !ok {
		t.Fatal("could not read site's body")
	}
	// COMMENTS STRIPPED FIRST. Review 1 on this change: `strings.Contains`
	// matched "# access_log", so commenting the call out left the file green
	// under a header that says AND IT IS CALLED. Deleting the line was caught;
	// one `#` was not. docs/checks.md names this mutation by hand, twice.
	if !strings.Contains(uncommented(site), "access_log") {
		t.Errorf("the per-app site block does not call access_log:\n%s", site)
	}
}

// shellFunc is a `name() { ... }` body, to the closing brace at its own
// indentation.
func shellFunc(src, name string) (string, bool) {
	re := regexp.MustCompile(`(?m)^(\t*)` + regexp.QuoteMeta(name) + `\(\) \{\n`)
	loc := re.FindStringSubmatchIndex(src)
	if loc == nil {
		return "", false
	}
	indent := src[loc[2]:loc[3]]
	rest := src[loc[1]:]
	end := strings.Index(rest, "\n"+indent+"}\n")
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// NOTHING TURNS THE REDACTION OFF.
//
// Caddy logs Authorization, Proxy-Authorization, Cookie and Set-Cookie as
// REDACTED by default, and the global `log_credentials` option is what disables
// that. Every request to the agent's own route carries a device token in
// Authorization -- a live credential for this server -- so setting it would
// write those tokens onto the machine they open.
//
// The person most likely to reach for it is somebody debugging a token problem,
// which is why this is a check rather than a comment.
func TestNothingDisablesCaddysCredentialRedaction(t *testing.T) {
	for name, src := range all(t) {
		for _, ln := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(ln)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, "log_credentials") {
				t.Errorf("%s enables log_credentials, which writes device tokens for this "+
					"server onto this server:\n\t%s", name, trimmed)
			}
		}
	}
}
