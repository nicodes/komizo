package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// runRemove is the non-interactive counterpart to the TUI's remove. It refuses
// to run without --yes, because unlike everything else here it deletes data.
func runRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.Usage = func() { usageRemove(fs) }
	var host, app string
	var port int
	var yes, keepData bool
	fs.StringVar(&host, "host", "", "server, [user@]HOST")
	fs.StringVar(&app, "app", "", "which app to remove")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&yes, "yes", false, "required: confirms you mean it")
	fs.BoolVar(&keepData, "keep-data", false, "leave the app directory and its volumes in place")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	if host == "" {
		return fmt.Errorf("--host is required")
	}
	if err := validateApp(app); err != nil {
		return err
	}

	tgt, err := parseTarget(host)
	if err != nil {
		return err
	}
	tgt.port = port
	tgt.portExplicit = portWasSet(fs)
	tgt.resolvePort()
	if err := validateHost(tgt.host); err != nil {
		return err
	}

	if !yes {
		return fmt.Errorf("this deletes %s, its volumes, its deploy account and its rules.\n"+
			"    Other apps on the box are untouched, and images stay in your registry.\n"+
			"    Re-run with --yes if that is what you want, or use the interface:\n"+
			"        komizo %s", "/srv/"+app, host)
	}

	if !tgt.reachable() {
		return fmt.Errorf("cannot SSH in as %s without a password", tgt.user)
	}

	env := map[string]string{"APP_NAME": app}
	if keepData {
		env["KEEP_DATA"] = "1"
	}
	c := exec.Command("ssh", tgt.sshArgs(envPrefix(env)+"sh -s")...)
	c.Stdin = strings.NewReader(AlpineRemoveScript)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("removal failed -- see the output above")
	}
	return nil
}

// runScript prints one of the embedded server-side scripts.
func runScript(args []string) error {
	which := "add"
	if len(args) > 0 {
		which = args[0]
	}
	switch which {
	case "init":
		fmt.Print(AlpineInitScript)
	case "add":
		fmt.Print(AlpineScript)
	case "remove":
		fmt.Print(AlpineRemoveScript)
	case "proxy":
		fmt.Print(AlpineProxyScript)
	default:
		return fmt.Errorf("no such script %q -- try 'init', 'add', 'remove' or 'proxy'", which)
	}
	return nil
}

func usageRemove(fs *flag.FlagSet) {
	fmt.Print(`komizo remove - tear one app off a server

  komizo remove --host root@myhost --app blog --yes

Stops its containers and deletes its directory and volumes, its deploy
account, its doas rules, its sshd restrictions and its privileged commands.
Every step targets that app's own name, so an app sharing the box is untouched.

Its images stay in your registry, and the deploy key on your machine is left
alone -- delete SSH_DEPLOY_KEY from the repo's secrets yourself if the app is
gone for good.

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}
