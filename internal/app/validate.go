package app

import (
	"fmt"
	"strings"

	"github.com/nicodes/komizo/scripts"
)

// Everything here ends up either single-quoted into a remote command line or
// used as a path component on the server. Constraining the character sets is
// what makes that quoting sufficient, so these run before anything connects.

func onlyChars(s, allowed string) bool {
	for _, r := range s {
		if !strings.ContainsRune(allowed, r) {
			return false
		}
	}
	return true
}

// scrub removes control characters from text that came off a server.
//
// Everything komizo displays about a box is written by something on the far
// end: docker's status prose, container and image names, an error's last line,
// and -- the one that matters -- log lines, which anyone who can make a request
// to a hosted app can put text into.
//
// Rendered raw, an escape sequence in any of that can move the cursor, clear
// the screen, retitle the window, or write the local clipboard through OSC 52.
// The display would stop being a report about the server and start being
// something the server writes. Truncating ANSI-aware, which the frame already
// does, is not the same thing: it counts escapes correctly and then passes them
// straight through.
//
// Tab and newline survive, because logs are lines and a log line can hold a
// tab. Everything else below 0x20, DEL, and the C1 range that some
// terminals still decode as escape introducers becomes a space -- a space
// rather than nothing, so a value padded with them does not silently close up
// into a different-looking value.
func scrub(s string) string {
	clean := true
	for _, r := range s {
		if isControl(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isControl(r) {
			return ' '
		}
		return r
	}, s)
}

func isControl(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	}
	return false
}

// shQuote wraps a value for a remote command line.
//
// One line, because the rule lives in the scripts package -- the one that
// builds shell -- and two implementations of "how do you make a value safe in
// sh" is exactly the kind of near-duplicate that drifts apart and is only
// noticed by whatever it lets through.
//
// It stays named here so the twenty call sites read the same as they always
// did: the quoting is a property of the command being built, not of which
// package happens to own the helper.
func shQuote(s string) string { return scripts.ShQuote(s) }

const (
	appChars  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	userChars = appChars + "."
	// No colon. It bought nothing and cost a divergence: addr() hands ssh
	// "user@host" as ONE argv element, so "example.com:2222" reaches it as a
	// literal hostname and fails to resolve, and a bare IPv6 literal is never
	// bracketed for addr() either. Meanwhile the server script's KNOWN_AS
	// charset has never allowed one -- so --known-as 'box:2222' passed every
	// check on this machine, opened a connection, and died on the far end with
	// a message about commas. See TestTheCharsetsAgreeWithTheServerScripts.
	hostChars  = userChars
	imageChars = userChars + ":/"
	pathChars  = userChars + "/"
)

func validateApp(s string) error {
	if s == "" || !onlyChars(s, appChars) {
		return fmt.Errorf("--app must be letters, digits, underscore or hyphen; got %q", s)
	}
	// Reserved for komizo's own directories under /srv -- /srv/_proxy today, and
	// room for more without another round of renaming. Refusing the whole prefix
	// rather than the single name means the inventory can tell an app from an
	// internal directory by its name alone.
	if strings.HasPrefix(s, "_") {
		return fmt.Errorf("app names starting with %q are reserved for komizo; got %q", "_", s)
	}
	return nil
}

// validateUser is the deploy account name. No dot: it is written verbatim into
// doas.conf and an sshd Match block, and it is used as a sed -E delimiter body
// on the server, where a dot is a regex metacharacter that could match an
// unrelated account's block. Letters, digits, underscore and hyphen is all a
// komizo-<app> account ever needs.
func validateUser(s string) error {
	if s == "" || !onlyChars(s, appChars) {
		return fmt.Errorf("--user must be letters, digits, underscore or hyphen; got %q", s)
	}
	return nil
}

// validateLoginUser is the SSH login on the far end (usually root), the part
// before the @ in --host. It is unvalidated nowhere else and ends up as one argv
// element `user@host` handed to ssh -- so a value beginning with '-' is parsed
// by OpenSSH as an option (-oProxyCommand=..., -F, -i), which is local command
// execution. Reject a leading hyphen, and constrain the charset so no option can
// be formed at all.
func validateLoginUser(s string) error {
	if s == "" || strings.HasPrefix(s, "-") || !onlyChars(s, userChars) {
		return fmt.Errorf("login user contains characters that are not allowed: %q", s)
	}
	return nil
}

func validateHost(s string) error {
	// A leading hyphen would let the hostname be read as an option by ssh or
	// ssh-keyscan (`ssh-keyscan -f`), the same argv-injection class as the login
	// user above. No real hostname begins with one.
	if s == "" || strings.HasPrefix(s, "-") || !onlyChars(s, hostChars) {
		return fmt.Errorf("hostname contains unexpected characters: %q", s)
	}
	return nil
}

func validateAppDir(s string) error {
	if s == "" {
		return nil
	}
	if !strings.HasPrefix(s, "/") {
		return fmt.Errorf("--app-dir must be an absolute path, got %q", s)
	}
	if !onlyChars(s, pathChars) {
		return fmt.Errorf("--app-dir contains characters that are not allowed: %q", s)
	}
	// No "..": the path is recorded and later handed to `rm -rf` on removal, and
	// the removal guard refuses a fixed set of literal paths -- which /srv/../etc
	// slips straight past. A traversal component also lets `chmod`/`chown` on the
	// dir reach somewhere it was never meant to.
	if s == ".." || strings.HasPrefix(s, "../") || strings.HasSuffix(s, "/..") || strings.Contains(s, "/../") {
		return fmt.Errorf("--app-dir must not contain a \"..\" path component, got %q", s)
	}
	return nil
}

func validateNetwork(s string) error {
	if s == "" {
		return nil
	}
	if !onlyChars(s, userChars) {
		return fmt.Errorf("--network must be letters, digits, dot, underscore or hyphen; got %q", s)
	}
	return nil
}

// validateConfigImage rejects a tag or digest. The deploy supplies the tag; one
// baked in here would silently pin every deploy to a single version.
//
// A tag is a colon AFTER the last slash -- a colon before it is a registry
// port, as in registry.internal:5000/app-config, which is legitimate.
func validateConfigImage(s string) error {
	if s == "" {
		return fmt.Errorf("--config is required, e.g. --config ghcr.io/you/myapp-config\n" +
			"\n" +
			"    It is where the host looks for each deploy's compose.yml. Pinning it\n" +
			"    on the server is what stops a leaked deploy key redirecting the host\n" +
			"    at an image an attacker controls.")
	}
	if strings.Contains(s, "@") {
		return fmt.Errorf("--config must not include a digest, got %q", s)
	}
	if !onlyChars(s, imageChars) {
		return fmt.Errorf("--config contains characters that are not valid in an image reference: %q", s)
	}
	last := s
	if i := strings.LastIndex(s, "/"); i >= 0 {
		last = s[i+1:]
	}
	if strings.Contains(last, ":") {
		return fmt.Errorf("--config must not include a tag (got %q); the deploy supplies it", s)
	}
	return nil
}
