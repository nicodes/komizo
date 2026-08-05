package app

import (
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

// A THIRD COPY OF THE RULES, pinned to the other two.
//
// charsets_test.go exists because the CLI's constants and the shell script's
// patterns were "unrelated string literals with nothing asserting they agree",
// and had already drifted. app.add adds a third set, in box/command.go, over
// the same fields -- and the drift it produced was the same shape: `--user Web`
// was a value `komizo add` took and a signed command could not carry.
//
// That direction is the one that matters. The CLI is the reference because
// app-only.md keeps it ENTIRE: every capability, over SSH, as root. A field the
// CLI accepts and the app cannot is the app being less than the product it
// replaces, which is the thing §9 cannot delete the interface over.
//
// So: for every rune, both ends must agree about whether it belongs in a value.
// Compared rune by rune rather than constant to constant, because the two are
// written in different forms -- a string of allowed characters on one side, a
// switch on the other -- and comparing the source would only prove they were
// spelled the same way.
func TestASignedCommandTakesWhatTheCLITakes(t *testing.T) {
	// Every ASCII character, plus a few that are not, since one side iterates
	// runes and the other indexes bytes.
	var corpus []rune
	for r := rune(0x21); r < 0x7f; r++ {
		corpus = append(corpus, r)
	}
	corpus = append(corpus, 'é', 'ß', '数', '​')

	for _, f := range []struct {
		field string
		// cli reports whether `komizo add` would take this value.
		cli func(string) error
		// signed reports whether an app.add envelope would.
		signed func(string) error
		// why says what the two are guarding, so a failure names the stake.
		why string
	}{
		{
			field:  "app",
			cli:    validateApp,
			signed: func(v string) error { return addWith(map[string]string{"app": v}) },
			why:    "the app name becomes a directory, two command paths and a deploy account",
		},
		{
			field:  "user",
			cli:    validateUser,
			signed: func(v string) error { return addWith(map[string]string{"user": v}) },
			why:    "the account is written verbatim into doas.conf and an sshd Match block",
		},
		{
			field:  "config",
			cli:    validateConfigImage,
			signed: func(v string) error { return addWith(map[string]string{"config": v}) },
			why:    "it is the trust anchor: which image root will accept config from",
		},
		{
			field:  "app_dir",
			cli:    validateAppDir,
			signed: func(v string) error { return addWith(map[string]string{"app_dir": v}) },
			why:    "it is chown'd and chmod'd as root, and later handed to rm -rf",
		},
		{
			field: "known_as",
			// A LIST on both sides, split the same way. Compared as a list
			// rather than as one name because the comma is a separator here and
			// an illegal character inside a name -- and per-name comparison
			// reports it as the envelope being looser, which is the opposite of
			// what it is.
			cli:    knownAsList,
			signed: func(v string) error { return addWith(map[string]string{"known_as": v}) },
			why:    "host keys are pinned per name, so CI trusts exactly these",
		},
	} {
		for _, r := range corpus {
			v := probe(f.field, r)
			cliOK := f.cli(v) == nil
			signedOK := f.signed(v) == nil
			if cliOK == signedOK {
				continue
			}
			if cliOK {
				t.Errorf("%s: the CLI takes %q and a signed command does not.\n"+
					"    %s\n"+
					"    The app can do less than the CLI with this field, which is the\n"+
					"    direction app-only.md does not allow. Fix box/command.go.",
					f.field, v, f.why)
				continue
			}
			t.Errorf("%s: a signed command takes %q and the CLI does not.\n"+
				"    %s\n"+
				"    The internet-reachable trigger is the looser of the two. Fix box/command.go.",
				f.field, v, f.why)
		}
	}
}

// knownAsList is what runAdd does with --known-as, in one function so this can
// compare against it rather than against a copy of it.
func knownAsList(v string) error {
	for _, a := range strings.Split(v, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if err := validateHost(a); err != nil {
			return err
		}
	}
	return nil
}

// probe puts one rune inside an otherwise-ordinary value for the field.
//
// Inside rather than alone, so what is being compared is the CHARACTER SET
// rather than each side's separate opinion about shape -- an absolute path, a
// dotted hostname, a registry path with no tag. Those differences are real and
// are asserted elsewhere; mixing them in here would report every rune as a
// disagreement.
func probe(field string, r rune) string {
	switch field {
	case "app", "user":
		return "web" + string(r) + "app"
	case "config":
		return "ghcr.io/you/cfg" + string(r) + "x"
	case "app_dir":
		return "/srv/web" + string(r) + "x"
	case "known_as":
		return "a" + string(r) + "b.example.com"
	}
	panic("unknown field " + field)
}

// addWith is one app.add envelope, ordinary except for the field under test.
func addWith(over map[string]string) error {
	args := map[string]string{
		"app":    "web",
		"config": "ghcr.io/you/cfg",
		"pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKD5vgfqmUVHAJDT5uZ6P+O/YBmR8hjj12T4jFnhrtqy deploy@web",
	}
	for k, v := range over {
		args[k] = v
	}
	c := box.Command{V: box.CommandVersion, ID: "abc123", Srv: "srv_mine",
		Exp: time.Now().Add(time.Minute).Unix(), Op: box.OpAppAdd, Args: args}
	_, err := c.AddOf()
	return err
}

// SHAPES, not only characters.
//
// The rune probe above puts one character inside an otherwise-ordinary value,
// so it can never produce a trailing separator, an empty segment or a bare
// punctuation mark -- and that is exactly where the two sides drifted: the CLI
// took everything after the last "/" and the box used path.Base, which disagree
// on "ghcr.io/a/web:1/". One accepted it and the other refused.
//
// So this is a second corpus of whole VALUES, chosen to be awkward at the edges
// rather than in the middle.
func TestASignedCommandTakesTheSameSHAPESTheCLITakes(t *testing.T) {
	for _, v := range []string{
		"ghcr.io/a/web",
		"ghcr.io/a/web/",
		"ghcr.io/a/web:1/",
		"ghcr.io/a:b/web",
		"reg.example.com:5000/a/web",
		"web",
		"web/",
		"/web",
		"a//b",
		".",
		"..",
		"a.b",
	} {
		cliOK := validateConfigImage(v) == nil
		signedOK := addWith(map[string]string{"config": v}) == nil
		if cliOK == signedOK {
			continue
		}
		if cliOK {
			t.Errorf("config: the CLI takes %q and a signed command does not.\n"+
				"    The app can do less than the CLI with this field, which is the\n"+
				"    direction app-only.md does not allow.", v)
			continue
		}
		t.Errorf("config: a signed command takes %q and the CLI does not.\n"+
			"    The internet-reachable trigger is the looser of the two.", v)
	}
}

// And the one place they are deliberately NOT the same, stated out loud so it
// cannot be mistaken for drift.
//
// The CLI does not bound an account's length; `adduser` does, on the far end,
// minutes later and over SSH. The signed path refuses it up front instead.
func TestTheOneDivergenceIsTheAccountLengthBound(t *testing.T) {
	long := strings.Repeat("a", 33)
	if err := validateUser(long); err != nil {
		t.Fatalf("the CLI has grown a length bound: %v.\n"+
			"    If it now refuses this too, delete this test -- the divergence is gone.", err)
	}
	if err := addWith(map[string]string{"user": long}); err == nil {
		t.Error("a signed command accepted a 33-character account, which adduser will refuse")
	}
	// And the default, which is derived from the app name and so can exceed the
	// bound without anybody typing an account at all.
	if err := addWith(map[string]string{"app": strings.Repeat("a", 30)}); err == nil {
		t.Error("a 30-character app name yields komizo-<30>, which is not an account name")
	}
}
