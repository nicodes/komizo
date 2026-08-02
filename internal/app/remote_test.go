package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/internal/box"
)

// Everything komizo displays about a box was written by something on the far
// end, and the far end includes anyone who can make a request to a hosted app.

func TestRemoteTextCannotDriveTheTerminal(t *testing.T) {
	// A log line with an OSC 52 clipboard write, a screen clear and a title
	// change in it -- all things a request path or user agent can carry into an
	// app's own log, which komizo then renders.
	nasty := "GET /\x1b]52;c;aGVsbG8=\x07 \x1b[2J\x1b]0;pwned\x07 ok"
	got := scrub(nasty)
	for _, bad := range []string{"\x1b", "\x07"} {
		if strings.Contains(got, bad) {
			t.Errorf("scrub left %q in %q", bad, got)
		}
	}
	if !strings.Contains(got, "GET /") || !strings.Contains(got, "ok") {
		t.Errorf("scrub ate the readable text: %q", got)
	}
}

func TestScrubKeepsTheCharactersTheFormatIsMadeOf(t *testing.T) {
	// Logs are lines and a log line can hold a tab. Scrubbing either would
	// mangle the one thing this is most often applied to.
	in := "app\tblog\tkomizo-blog\nnext\tline"
	if got := scrub(in); got != in {
		t.Errorf("scrub altered a clean record: %q -> %q", in, got)
	}
}

// Everything in a report is written by the far end. A container name is
// docker's, and docker's is whatever the image or a compose file called it --
// so an escape sequence can arrive in one, and JSON carries it through
// perfectly well. The adapter is the one place that can stop it.
func TestReportFieldsAreScrubbedBeforeAnythingRendersThem(t *testing.T) {
	inv := invOf(oneApp(box.App{
		Name: "blog", User: "komizo-blog", Dir: "/srv/blog", Version: "abc",
		ConfigImage: "ghcr.io/x/\x1b]0;pwned\x07y",
		Hosts:       []box.Host{{Name: "blog.\x1b[2Jexample.com"}},
		Containers: []box.Container{{
			Service: "web", Name: "blog-\x1b[2Jweb-1", State: "running",
			Status: "Up \x1b[31m3 hours", Image: "img",
		}},
	}))
	apps := inv.apps
	if len(apps) != 1 || len(apps[0].containers) != 1 {
		t.Fatalf("expected one app with one container, got %+v", apps)
	}
	c := apps[0].containers[0]
	for what, got := range map[string]string{
		"container name": c.name,
		"status":         c.status,
		"config image":   apps[0].image,
		"hostname":       apps[0].hosts[0].name,
		"route":          apps[0].routes[0].sites,
	} {
		if strings.ContainsAny(got, "\x1b\x07") {
			t.Errorf("an escape survived into the %s: %q", what, got)
		}
	}
}

// A value that reaches a remote command line must not be able to end the quote
// it is inside.
func TestShQuoteClosesTheValueItIsGiven(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"blog", `'blog'`},
		{"", `''`},
		{"a'b", `'a'\''b'`},
		{"'; rm -rf /; '", `''\''; rm -rf /; '\'''`},
	} {
		if got := shQuote(c.in); got != c.want {
			t.Errorf("shQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAQuoteInAContainerNameCannotEscapeTheCommand(t *testing.T) {
	cmd := containerCmd("evil'; touch /tmp/pwned; '", "stop")
	if strings.Contains(cmd, "; touch /tmp/pwned; ") && !strings.Contains(cmd, `'\''`) {
		t.Errorf("the name broke out of its quoting: %s", cmd)
	}
	// And the shell agrees about how many words that is.
	if n := strings.Count(cmd, "'")%2 != 0; n {
		t.Errorf("unbalanced quoting: %s", cmd)
	}
}

func TestEnvPrefixQuotesValuesRatherThanTrustingThem(t *testing.T) {
	got := envPrefix(map[string]string{"KNOWN_AS": "a'b", "APP_NAME": "blog"})
	if !strings.Contains(got, `APP_NAME='blog'`) {
		t.Errorf("ordinary value not quoted as expected: %s", got)
	}
	if strings.Contains(got, `KNOWN_AS='a'b'`) {
		t.Errorf("a quote in a value was passed through unescaped: %s", got)
	}
	// Sorted, so two transcripts of the same operation compare.
	if strings.Index(got, "APP_NAME") > strings.Index(got, "KNOWN_AS") {
		t.Errorf("not sorted: %s", got)
	}
}

// --- what an absent value means --------------------------------------------

// A proxy that has never been created has no timestamps and no status worth
// printing. It is still INSTALLED, and reading it otherwise makes the interface
// offer to install the one already there.
func TestAnInstalledProxyIsSeenEvenWithNoTimestamps(t *testing.T) {
	r := oneApp(box.App{Name: "blog"})
	r.Proxy = &box.Proxy{State: "stopped", Network: "edge", Image: "caddy:2", Status: "not created"}
	proxy := invOf(r).proxy
	if !proxy.installed {
		t.Fatal("an installed proxy with no start time was dropped entirely")
	}
	if proxy.state != "stopped" || proxy.network != "edge" || proxy.image != "caddy:2" {
		t.Errorf("fields did not survive: %+v", proxy)
	}
	if !proxy.startedAt.IsZero() {
		t.Errorf("a missing timestamp should be zero, got %v", proxy.startedAt)
	}
}

// The mirror of it: no proxy at all must read as not installed rather than as
// an empty-but-present one. The report says so by omitting the object, which is
// why Proxy is a pointer.
func TestNoProxyRecordMeansNotInstalled(t *testing.T) {
	if proxy := invOf(oneApp(box.App{Name: "blog"})).proxy; proxy.installed {
		t.Errorf("no proxy should mean not installed, got %+v", proxy)
	}
}

// A container that has never run has no start time and no listening ports --
// it has no network namespace to read. It still appears, because a stack that
// will not start is exactly what somebody is looking for.
func TestAContainerWithNoRecordedTimestampsStillAppears(t *testing.T) {
	inv := invOf(oneApp(box.App{
		Name: "blog", User: "komizo-blog", Dir: "/srv/blog", Version: "abc",
		Containers: []box.Container{{Service: "web", Name: "blog-web-1", State: "created", Status: "Created"}},
	}))
	apps := inv.apps
	if len(apps) != 1 || len(apps[0].containers) != 1 {
		t.Fatalf("a container with no timestamps was dropped: %+v", apps)
	}
	c := apps[0].containers[0]
	if c.state != "created" || c.ports != "" {
		t.Errorf("unexpected container: %+v", c)
	}
	if !c.startedAt.IsZero() || !c.finishedAt.IsZero() {
		t.Errorf("absent timestamps should be zero: %+v", c)
	}
}

// --- typing ----------------------------------------------------------------

func TestBackspaceRemovesACharacterNotAByte(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"abc", "ab"},
		{"café", "caf"},
		{"日本", "日"},
		{"a", ""},
		{"", ""},
	} {
		got := trimLastRune(c.in)
		if got != c.want {
			t.Errorf("trimLastRune(%q) = %q, want %q", c.in, got, c.want)
		}
		if !isValidUTF8(got) {
			t.Errorf("trimLastRune(%q) left invalid UTF-8: %q", c.in, got)
		}
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}

// --- known_hosts -----------------------------------------------------------

// Accepting the same host twice happens whenever a first connection is retried,
// and used to append the whole scan again each time.
func TestAcceptingAHostTwiceDoesNotDuplicateItsKeys(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	scan := []byte("example.com ssh-ed25519 AAAAC3Nz\nexample.com ssh-rsa AAAAB3Nz\n")

	for i := 0; i < 3; i++ {
		if _, err := writeKnownHosts(scan); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	b, err := os.ReadFile(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("expected 2 lines after three accepts, got %d:\n%s", n, b)
	}
}

func TestANewKeyIsStillAppendedBesideTheOldOnes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if _, err := writeKnownHosts([]byte("a.example.com ssh-ed25519 AAAA\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeKnownHosts([]byte("b.example.com ssh-ed25519 BBBB\n")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".ssh", "known_hosts"))
	for _, want := range []string{"a.example.com", "b.example.com"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s missing from known_hosts:\n%s", want, b)
		}
	}
}

// A failing agent can print a page; the line that says what went wrong is the
// last one, and the rest is context nobody reads in a status bar.
func TestLastLineIsWhatWentWrong(t *testing.T) {
	for in, want := range map[string]string{
		"one line":                      "one line",
		"context\nmore\nthe real error": "the real error",
		"trailing newline\n":            "trailing newline",
		"":                              "",
	} {
		if got := lastLine(in); got != want {
			t.Errorf("lastLine(%q) = %q, want %q", in, got, want)
		}
	}
}
