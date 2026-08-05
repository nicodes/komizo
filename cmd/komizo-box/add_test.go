package main

import (
	"context"
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
	spec, err := addCmd(good()).AddOf()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(spec.PubKey, "ssh-ed25519 ") {
		t.Errorf("pubkey = %q", spec.PubKey)
	}
	// A private key is not a thing this envelope has a place for. Asserted so
	// that adding one later has to argue with a test.
	for _, k := range []string{"privkey", "private_key", "key"} {
		c := addCmd(good())
		c.Args[k] = "-----BEGIN OPENSSH PRIVATE KEY-----"
		s, err := c.AddOf()
		if err != nil {
			continue
		}
		if strings.Contains(s.PubKey+s.Config+s.User+s.AppDir, "PRIVATE") {
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
	if err := perform(context.Background(), addCmd(args)); err != nil {
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
	// Nothing on the command line at all beyond -s.
	for _, a := range gotArgs {
		if strings.Contains(a, "ssh-ed25519") || strings.Contains(a, "web") {
			t.Errorf("a value reached the command line: %q", a)
		}
	}
}
