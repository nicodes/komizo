package app

import (
	"flag"
	"fmt"

	"github.com/nicodes/komizo/scripts"
)

// runRemove is the non-interactive counterpart to the TUI's remove. It refuses
// to run without --yes, because unlike everything else here it deletes data.
func RunRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.Usage = func() { usageRemove(fs) }
	var host, app string
	var port int
	var yes, keepData, acceptHostKey bool
	fs.StringVar(&host, "host", "", "server, [user@]HOST")
	fs.StringVar(&app, "app", "", "which app to remove")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&yes, "yes", false, "required: confirms you mean it")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	fs.BoolVar(&keepData, "keep-data", false, "leave the app directory and its volumes in place")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if err := validateApp(app); err != nil {
		return err
	}

	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}

	if !yes {
		return fmt.Errorf("this deletes %s, its volumes, its deploy account and its rules.\n"+
			"    Other apps on the box are untouched, and images stay in your registry.\n"+
			"    Re-run with --yes if that is what you want, or use the interface:\n"+
			"        komizo %s", "/srv/"+app, host)
	}

	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	env := map[string]string{"APP_NAME": app}
	if keepData {
		env["KEEP_DATA"] = "1"
	}
	if err := tgt.runScript(scripts.AlpineRemoveScript, env); err != nil {
		return fmt.Errorf("removal failed -- see the output above")
	}
	return nil
}

// runScript prints one of the embedded server-side scripts.
func RunScript(args []string) error {
	which := "add"
	if len(args) > 0 {
		which = args[0]
	}
	switch which {
	case "-h", "--help", "help":
		fmt.Print(`komizo script - print the shell komizo runs on your server

  komizo script [init|add|remove|proxy]

It is piped over SSH and run as root, so this is how you read it before it
runs. "add" is the default because it is the one that creates the deploy
account, the doas rules and the sshd restrictions.

  init     prepare a fresh box: Docker, the shared network
  add      set an app up, or update one
  remove   tear one app back off
  proxy    install the one shared reverse proxy
`)
		return nil
	case "init":
		fmt.Print(scripts.AlpineInitScript)
	case "add":
		fmt.Print(scripts.AlpineScript)
	case "remove":
		fmt.Print(scripts.AlpineRemoveScript)
	case "proxy":
		fmt.Print(scripts.AlpineProxyScript)
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
alone -- delete KOMIZO_DEPLOY_KEY from the repo's secrets yourself if the app is
gone for good.

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}
