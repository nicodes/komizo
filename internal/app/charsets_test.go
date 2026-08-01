package app

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// The same value is charset-checked in two places: here, and again in the shell
// this pipes to the server. That redundancy is deliberate and stays -- alpine.sh
// is documented as hand-runnable with environment variables, so it cannot trust
// the CLI to have checked anything.
//
// What was NOT deliberate is that the two were unrelated string literals with
// nothing asserting they agree. They had already drifted: hostChars allowed a
// colon and the server's KNOWN_AS pattern did not, so
//
//	komizo add --known-as 'box:2222'
//
// passed every check on this machine, opened an SSH connection, ran the
// preflight, and died on the far end with a message about commas.
//
// So the shell stays the enforcement point and this becomes the agreement
// point: each Go constant is compared against the pattern grepped out of the
// script that mirrors it. A change to either side that is not made to both
// fails here, naming both.

// shellCharset pulls the character class out of a `case` pattern of the form
//
//	*[!A-Za-z0-9._-]*) die "APP_DIR contains characters that are not allowed" ;;
//
// and returns the runes it allows. Located by the error message beside it
// rather than by line number, so the scripts stay editable.
//
// Searched BACKWARDS from the message, because in a `case` arm the pattern
// comes first: looking forward finds whichever class happens to be next in the
// file, which is a different rule that may well agree with the wrong constant.
func shellCharset(t *testing.T, script, marker string) string {
	t.Helper()
	i := strings.Index(script, marker)
	if i < 0 {
		t.Fatalf("could not find %q in the script -- has it been renamed?", marker)
	}
	all := regexp.MustCompile(`\*\[!([^]]+)\]\*`).FindAllStringSubmatch(script[:i], -1)
	if len(all) == 0 {
		t.Fatalf("no negated character class before %q", marker)
	}
	return expandClass(t, all[len(all)-1][1])
}

// expandClass turns "A-Za-z0-9._-" into the set of runes it matches.
//
// Ranges only, plus literals. Deliberately not a general bracket-expression
// parser: the scripts use exactly this form, and anything richer appearing in
// one is a thing to look at rather than to silently accept.
func expandClass(t *testing.T, class string) string {
	t.Helper()
	var out []rune
	r := []rune(class)
	for i := 0; i < len(r); i++ {
		// A hyphen at either end is a literal hyphen, not a range.
		if i+2 < len(r) && r[i+1] == '-' {
			if r[i] > r[i+2] {
				t.Fatalf("inverted range %c-%c in %q", r[i], r[i+2], class)
			}
			for c := r[i]; c <= r[i+2]; c++ {
				out = append(out, c)
			}
			i += 2
			continue
		}
		if r[i] == '\\' && i+1 < len(r) {
			i++
		}
		out = append(out, r[i])
	}
	return string(out)
}

func sameRunes(a, b string) (onlyA, onlyB string) {
	in := func(s string, r rune) bool { return strings.ContainsRune(s, r) }
	for _, r := range a {
		if !in(b, r) && !in(onlyA, r) {
			onlyA += string(r)
		}
	}
	for _, r := range b {
		if !in(a, r) && !in(onlyB, r) {
			onlyB += string(r)
		}
	}
	return onlyA, onlyB
}

func TestTheCharsetsAgreeWithTheServerScripts(t *testing.T) {
	for _, c := range []struct {
		what   string
		goSet  string
		script string
		marker string
		// why names what the two are guarding, so a failure says what is at
		// stake rather than only which characters differ.
		why string
	}{
		{
			what:   "app name",
			goSet:  appChars,
			script: scripts.AlpineScript,
			marker: "APP_NAME must be letters",
			why:    "the app name becomes a directory, two command paths and a deploy account",
		},
		{
			what:   "app name (removal)",
			goSet:  appChars,
			script: scripts.AlpineRemoveScript,
			marker: "APP_NAME must be letters",
			why:    "removal targets the same paths the setup created",
		},
		{
			what:   "deploy account",
			goSet:  appChars,
			script: scripts.AlpineScript,
			marker: "CI_USER must be letters",
			why:    "the account is written verbatim into doas.conf and an sshd Match block",
		},
		{
			what:   "deploy account (removal)",
			goSet:  appChars,
			script: scripts.AlpineRemoveScript,
			marker: "CI_USER must be letters",
			why:    "it is used as a sed -E pattern to find the blocks to delete",
		},
		{
			what:   "config image",
			goSet:  imageChars,
			script: scripts.AlpineScript,
			marker: "CONFIG_IMAGE contains characters",
			why:    "it is the trust anchor: which image root will accept config from",
		},
		{
			what:   "proxy image",
			goSet:  imageChars,
			script: scripts.AlpineProxyScript,
			marker: "PROXY_IMAGE contains characters",
			why:    "it is substituted into the generated proxy compose.yml",
		},
		{
			what:   "app directory",
			goSet:  pathChars,
			script: scripts.AlpineScript,
			marker: "APP_DIR contains characters",
			why:    "it is a sed replacement delimited by '|', and later an rm -rf target",
		},
		{
			what:   "shared network",
			goSet:  userChars,
			script: scripts.AlpineInitScript,
			marker: "SHARED_NETWORK must be letters",
			why:    "it names the docker network every app joins",
		},
	} {
		t.Run(c.what, func(t *testing.T) {
			shell := shellCharset(t, c.script, c.marker)
			onlyGo, onlyShell := sameRunes(c.goSet, shell)
			if onlyGo != "" || onlyShell != "" {
				t.Errorf("the %s charsets disagree (%s)\n"+
					"  the CLI allows, the server does not: %q\n"+
					"  the server allows, the CLI does not: %q\n"+
					"  fix BOTH -- the server is the enforcement point, this is the agreement point",
					c.what, c.why, onlyGo, onlyShell)
			}
		})
	}
}

// --known-as is the one that had actually drifted.
//
// Its entries are validated with validateHost here and land in the server's
// KNOWN_AS, which additionally has to hold the commas between them -- so the
// two are not the same set and cannot be compared directly. What must hold is
// containment: anything this accepts, the server must accept.
func TestEveryHostnameTheCLIAcceptsTheServerAlsoAccepts(t *testing.T) {
	shell := shellCharset(t, scripts.AlpineScript, "KNOWN_AS must be hostnames")

	for _, r := range hostChars {
		if !strings.ContainsRune(shell, r) {
			t.Errorf("validateHost accepts %q but the server's KNOWN_AS refuses it -- "+
				"--known-as with that character passes every local check and then fails "+
				"on the far end", string(r))
		}
	}
	// The comma is the server's alone: it separates the names, and a single
	// name containing one would produce two.
	if strings.ContainsRune(hostChars, ',') {
		t.Error("validateHost accepts a comma, which the server reads as a separator")
	}
}

// The regression that motivated all of the above, stated as behaviour rather
// than as a set comparison.
func TestAHostnameWithAPortIsRefused(t *testing.T) {
	for _, s := range []string{"box.example.com:2222", "[box.example.com]:2222", "::1"} {
		if err := validateHost(s); err == nil {
			t.Errorf("validateHost(%q) was accepted; ssh takes user@host as one argv "+
				"element, so a port in the hostname never resolves", s)
		}
	}
}
