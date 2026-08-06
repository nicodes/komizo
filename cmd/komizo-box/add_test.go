package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
)

func addCmd(args map[string]string) box.Command {
	return box.Command{V: box.CommandVersion, ID: "abc123", Srv: "srv_mine",
		Exp: time.Now().Add(time.Minute).Unix(), Op: box.OpAppAdd, Args: args}
}

func good() map[string]string {
	return map[string]string{
		"app":    "web",
		"config": "ghcr.io/you/myapp-config",
		"pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKD5vgfqmUVHAJDT5uZ6P+O/YBmR8hjj12T4jFnhrtqy deploy@web",
	}
}

// NOTHING HERE GENERATES, HOLDS OR RETURNS A PRIVATE KEY.
//
// That is the whole reason app.add carries a key rather than making one: a
// result file lives where the account that talks to the internet reads it, and
// report.go says never, in anything it can read, "registry tokens, private
// keys".
func TestAddCarriesOnlyThePublicHalf(t *testing.T) {
	// A private key is not a thing this envelope has a place for. Asserted so
	// that adding one later has to argue with a test.
	//
	// The spec must come back CLEAN rather than merely not come back: this used
	// to `continue` on any error, so a future refusal -- of anything, for any
	// reason -- made every case pass without the claim ever being checked. An
	// unknown argument is ignored by AddOf, so nil is the right answer and
	// demanding it is what keeps the check reachable.
	for _, k := range []string{"privkey", "private_key", "key", "pubkey_private"} {
		c := addCmd(good())
		c.Args[k] = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
		s, err := c.AddOf()
		if err != nil {
			t.Errorf("%q made an otherwise-valid add fail: %v", k, err)
			continue
		}
		if strings.Contains(s.PubKey+s.Config+s.User+s.AppDir+strings.Join(s.KnownAs, ""), "PRIVATE") {
			t.Errorf("a private key reached the spec through %q", k)
		}
	}
}

// Every value is checked as what it claims to be. A signature says a device
// this box trusts sent it; it says nothing about whether "web; rm -rf /" is an
// app name.
func TestAddRefusesArgumentsThatAreNotWhatTheyClaim(t *testing.T) {
	// The no-key case asserts the MESSAGE, because an empty key is also refused
	// by the ed25519 check one line later -- so "it errored" passes with the
	// requirement itself deleted.
	noKey := good()
	delete(noKey, "pubkey")
	if _, err := addCmd(noKey).AddOf(); err == nil || !strings.Contains(err.Error(), "needs the public half") {
		t.Errorf("no key = %v, want it named as missing", err)
	}

	// Same shape, same reason: an absent config is ALSO refused by the charset
	// check one line later -- which returns false for the empty string -- so
	// "it errored" passes with the requirement itself deleted, and the operator
	// is told their empty field is not a registry path.
	noConfig := good()
	delete(noConfig, "config")
	if _, err := addCmd(noConfig).AddOf(); err == nil || !strings.Contains(err.Error(), "needs the image") {
		t.Errorf("no config = %v, want it named as missing", err)
	}

	for name, mutate := range map[string]func(map[string]string){
		"two keys":                   func(a map[string]string) { a["pubkey"] += "\nssh-ed25519 AAAA second" },
		"an rsa key":                 func(a map[string]string) { a["pubkey"] = "ssh-rsa AAAAB3Nza" },
		"a key that is a flag":       func(a map[string]string) { a["pubkey"] = "-oProxyCommand=x" },
		"an app that is a path":      func(a map[string]string) { a["app"] = "../etc" },
		"an app that is a flag":      func(a map[string]string) { a["app"] = "-rf" },
		"a tagged config":            func(a map[string]string) { a["config"] = "ghcr.io/you/cfg:latest" },
		"a config with a space":      func(a map[string]string) { a["config"] = "ghcr.io/you/c fg" },
		"a relative app dir":         func(a map[string]string) { a["app_dir"] = "srv/web" },
		"an app dir that is a flag":  func(a map[string]string) { a["app_dir"] = "--tlsverify" },
		"an account that is a flag":  func(a map[string]string) { a["user"] = "-rf" },
		"a hostname that is not one": func(a map[string]string) { a["known_as"] = "not a host" },

		// TRAVERSAL. Each of these is chown'd and chmod'd as root on the way in
		// and handed to `rm -rf` on the way out, and the removal guard refuses a
		// fixed set of LITERAL paths that every one of them walks past.
		"an app dir that climbs":        func(a map[string]string) { a["app_dir"] = "/srv/../etc" },
		"an app dir that climbs twice":  func(a map[string]string) { a["app_dir"] = "/srv/web/../../etc/ssh" },
		"an app dir that ends climbing": func(a map[string]string) { a["app_dir"] = "/srv/web/.." },
		"an app dir with a space":       func(a map[string]string) { a["app_dir"] = "/srv/my app" },

		// The shell script refuses all four of these, so before this they were
		// accepted, claimed, and then died mid-provision as a shell error --
		// which a caller cannot tell from a box that broke.
		"a reserved app name": func(a map[string]string) { a["app"] = "_proxy" },
		"no config at all":    func(a map[string]string) { delete(a, "config") },
		"root as the account": func(a map[string]string) { a["user"] = "root" },
		"an app so long its default account is not one": func(a map[string]string) {
			a["app"] = strings.Repeat("a", 30)
		},
	} {
		args := good()
		mutate(args)
		if _, err := addCmd(args).AddOf(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// And an ordinary one is not refused, so this is not simply saying no.
	args := good()
	args["known_as"] = "myapp.example.com, other.example.com"
	args["app_dir"] = "/opt/web"
	spec, err := addCmd(args).AddOf()
	if err != nil {
		t.Fatalf("an ordinary add was refused: %v", err)
	}
	if len(spec.KnownAs) != 2 {
		t.Errorf("known_as = %v", spec.KnownAs)
	}
	// The deploy account is defaulted rather than demanded, the same as the CLI.
	if spec.User != "komizo-web" {
		t.Errorf("user = %q, want the CLI's default", spec.User)
	}

	// AND THE NAMES CI ACTUALLY USES ARE ACCEPTED. known_as was validated by
	// ValidateAPIHost, which exists to decide whether THIS BOX's endpoint can
	// carry a public certificate -- so it refused every one of these, all of
	// which `komizo add --known-as` takes. A field the CLI accepts and the app
	// cannot is a parity break, and the operator got a paragraph about
	// certificate authorities for a field that has nothing to do with them.
	for _, host := range []string{"box", "my_host.example.com", "10.0.0.5", "deploy.example.com"} {
		args := good()
		args["known_as"] = host
		if _, err := addCmd(args).AddOf(); err != nil {
			t.Errorf("known_as %q was refused: %v", host, err)
		}
	}

	// A directory whose name merely begins with dots is not traversal, and
	// refusing it would be refusing a legal path.
	args = good()
	args["app_dir"] = "/srv/..web"
	if _, err := addCmd(args).AddOf(); err != nil {
		t.Errorf("a leading-dots directory name was refused: %v", err)
	}
}

// A FAILURE ALWAYS SAYS SOMETHING.
//
// The script's own last words are what say why, and the error from running it
// was being discarded -- so a script killed by a signal, or one that died
// before printing anything, produced Detail: "". That field is omitempty, so
// what reached the app was ok:false and no reason at all, which is the one
// state §4 says a result exists to prevent.
func TestAFailedProvisionSaysWhyEvenWhenTheScriptDoesNot(t *testing.T) {
	orig := execProvision
	execProvision = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// Exits non-zero, prints nothing. `false` is the smallest thing that
		// behaves like a script killed before its first line of output.
		return exec.CommandContext(ctx, "false")
	}
	defer func() { execProvision = orig }()

	err := perform(context.Background(), addCmd(good()), testBy)
	if err == nil {
		t.Fatal("a script that exited non-zero was reported as success")
	}
	if strings.TrimSpace(err.Error()) == "" {
		t.Fatal("the failure has no detail, so the app is shown ok:false with no reason")
	}
	if !strings.Contains(err.Error(), "without saying why") {
		t.Errorf("detail = %q, want it to say the script gave no reason", err)
	}
}

// BOTH TRIGGERS END IN ONE IMPLEMENTATION.
//
// app-only.md §8's condition: the script a signed command runs is the script
// `komizo add` pipes over SSH, so there is never a second opinion about what
// adding an app means.
func TestAddRunsTheSameScriptTheCLIRuns(t *testing.T) {
	var held *exec.Cmd
	var gotName string
	var gotArgs []string
	orig := execProvision
	execProvision = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName, gotArgs = name, args
		// The pointer is kept, and read AFTER runProvision has set Stdin and
		// Env on it -- a stub that reads them when it is called sees neither,
		// which is what the first version of this did.
		held = exec.CommandContext(ctx, "true")
		return held
	}
	defer func() { execProvision = orig }()

	args := good()
	args["known_as"] = "myapp.example.com"
	args["app_dir"] = "/opt/web"
	args["harden_ssh"] = "1"
	if err := perform(context.Background(), addCmd(args), testBy); err != nil {
		t.Fatalf("perform = %v", err)
	}

	if gotName != "/bin/sh" || strings.Join(gotArgs, " ") != "-s" {
		t.Fatalf("ran %q %v, want the script piped to sh -s", gotName, gotArgs)
	}

	// The SCRIPT itself, not a copy of it: the same bytes `komizo add` pipes.
	buf := make([]byte, len(scripts.AlpineScript))
	if r, ok := held.Stdin.(*strings.Reader); !ok {
		t.Fatal("the script was not piped over stdin")
	} else if _, err := r.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	if string(buf) != scripts.AlpineScript {
		t.Error("a signed add runs something other than the script `komizo add` runs")
	}

	// And its values arrive in the ENVIRONMENT, not on a command line that
	// every account on the box can read from the process table.
	env := map[string]string{}
	for _, kv := range held.Env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	for k, want := range map[string]string{
		"APP_NAME":     "web",
		"CI_USER":      "komizo-web",
		"CONFIG_IMAGE": "ghcr.io/you/myapp-config",
		"KNOWN_AS":     "myapp.example.com",
		"APP_DIR":      "/opt/web",
		"HARDEN_SSH":   "1",
	} {
		if env[k] != want {
			t.Errorf("%s = %q, want %q", k, env[k], want)
		}
	}
	if !strings.HasPrefix(env["CI_PUBKEY"], "ssh-ed25519 ") {
		t.Errorf("CI_PUBKEY = %q", env["CI_PUBKEY"])
	}

	// AND NOTHING ELSE. The assertions above name six keys and check their
	// VALUES, which says nothing about what else is in there -- and the
	// environment of a shell script running as root is the whole injection
	// surface of this op. Handing the raw args map to the child passed every
	// test on this branch until this loop existed; a signed argument reaching
	// LD_PRELOAD, PATH or IFS would have shipped green.
	//
	// Compared against the environment this process ALREADY had, because
	// runProvision inherits it deliberately -- the script needs a PATH.
	inherited := map[string]bool{}
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok {
			inherited[k] = true
		}
	}
	added := map[string]bool{
		"APP_NAME": true, "CI_PUBKEY": true, "CI_USER": true,
		"CONFIG_IMAGE": true, "KNOWN_AS": true, "APP_DIR": true, "HARDEN_SSH": true,
	}
	for k := range env {
		if !inherited[k] && !added[k] {
			t.Errorf("performAdd put %q into the environment of a root shell", k)
		}
	}
}
