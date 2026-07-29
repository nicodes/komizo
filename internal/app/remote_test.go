package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	// Records are tab-separated and logs are lines. Scrubbing either would
	// destroy every parser downstream of this.
	in := "app\tblog\tkomizo-blog\nnext\tline"
	if got := scrub(in); got != in {
		t.Errorf("scrub altered a clean record: %q -> %q", in, got)
	}
}

func TestInventoryFieldsAreScrubbedBeforeAnythingRendersThem(t *testing.T) {
	// The container name is docker's, but docker's is whatever the image or a
	// compose file called it.
	out := "server\tready\tDocker 27\n" +
		"app\tblog\tkomizo-blog\t/srv/blog\tabc\t1\tghcr.io/x/y\t\n" +
		"container\tblog\tweb\tblog-\x1b[2Jweb-1\trunning\tUp 3 hours\t\t\t0\timg\t80\n"
	apps, _, _, _, _ := parseInventory(out)
	if len(apps) != 1 || len(apps[0].containers) != 1 {
		t.Fatalf("expected one app with one container, got %+v", apps)
	}
	if strings.Contains(apps[0].containers[0].name, "\x1b") {
		t.Errorf("an escape survived into a container name: %q", apps[0].containers[0].name)
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

// --- the inventory's own robustness ----------------------------------------

// A proxy that has never been created reports no timestamps, so its record is
// two fields short. An exact-length match dropped the whole row, and the
// interface then offered to install a proxy that was already installed.
func TestAnInstalledProxyIsSeenEvenWithNoTimestamps(t *testing.T) {
	_, _, proxy, _, _ := parseInventory(
		"proxy\tstopped\tedge\tcaddy:2\tnot created\t")
	if !proxy.installed {
		t.Fatal("an installed proxy with no start time was dropped entirely")
	}
	if proxy.state != "stopped" || proxy.network != "edge" || proxy.image != "caddy:2" {
		t.Errorf("fields did not survive the padding: %+v", proxy)
	}
	if !proxy.startedAt.IsZero() {
		t.Errorf("a missing timestamp should be zero, got %v", proxy.startedAt)
	}
}

func TestAContainerWithNoRecordedTimestampsStillAppears(t *testing.T) {
	out := "app\tblog\tkomizo-blog\t/srv/blog\tabc\t0\tghcr.io/x/y\t\n" +
		"container\tblog\tweb\tblog-web-1\tcreated\tCreated\t"
	apps, _, _, _, _ := parseInventory(out)
	if len(apps) != 1 || len(apps[0].containers) != 1 {
		t.Fatalf("a container short of its timestamp fields was dropped: %+v", apps)
	}
	if c := apps[0].containers[0]; c.state != "created" || c.ports != "" {
		t.Errorf("unexpected container: %+v", c)
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
