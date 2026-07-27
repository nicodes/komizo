package main

import (
	"flag"
	"fmt"
)

// Setting a server up is its own command, not something that happens to a box
// as a side effect of adding the first app. That split is what lets the
// interface say "connected, not set up yet" rather than presenting an empty
// list that looks the same as a server with no apps on it.

type initOpts struct {
	host    string
	network string
	image   string
	port    int
	// See addOpts.acceptHostKey.
	acceptHostKey bool
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() { usageInit(fs) }
	var o initOpts
	fs.StringVar(&o.host, "host", "", "server to set up, [user@]HOST (user defaults to root)")
	fs.StringVar(&o.network, "network", defaultNetwork, "docker network apps join to be reachable")
	fs.StringVar(&o.image, "proxy-image", defaultProxy, "caddy image to run")
	fs.BoolVar(&o.acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	fs.IntVar(&o.port, "port", 22, "SSH port")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if o.host == "" {
		return fmt.Errorf("--host is required, e.g. --host root@myapp.example.com")
	}
	if err := validateNetworkName(o.network); err != nil {
		return err
	}
	if !onlyChars(o.image, imageChars) {
		return fmt.Errorf("--proxy-image contains characters that are not valid in an image reference: %q", o.image)
	}

	tgt, err := parseTarget(o.host)
	if err != nil {
		return err
	}
	tgt.port = o.port
	tgt.portExplicit = portWasSet(fs)
	tgt.resolvePort()
	if err := validateHost(tgt.host); err != nil {
		return err
	}

	step("Checking %s:%d", tgt.addr(), tgt.port)
	if r := tgt.probe(); !r.ok() {
		if r.kind == reachUnknownHost && o.acceptHostKey {
			if err := acceptHostKey(tgt, true); err != nil {
				return err
			}
			r = tgt.probe()
		}
		if !r.ok() {
			return r.explain(tgt)
		}
	}
	note("reachable.")

	step("Setting up %s", tgt.host)
	if err := tgt.runScript(AlpineInitScript, map[string]string{"SHARED_NETWORK": o.network}); err != nil {
		return fmt.Errorf("the server-side script failed -- see the output above")
	}

	step("Installing the shared reverse proxy")
	if err := tgt.runScript(AlpineProxyScript, proxyEnv(proxyOpts{
		network: o.network,
		image:   o.image,
	})); err != nil {
		return fmt.Errorf("Docker is installed, but the proxy failed -- see the output above.\n" +
			"    Re-run 'komizo proxy' once you have fixed it; the server itself is ready.")
	}
	return nil
}

func usageInit(fs *flag.FlagSet) {
	fmt.Print(`komizo init - prepare a fresh server

  komizo init --host root@myhost

Installs Docker, enables it at boot, creates the network apps share, and starts
the one reverse proxy that terminates TLS for all of them. Nothing app-specific:
no accounts, nothing under /srv.

Certificates need no configuration -- Caddy obtains and renews them on its own,
for whatever hostnames your apps publish.

The proxy is always installed. On a box that serves no HTTP, stop it afterwards
-- 't' on the server screen -- rather than deciding here, on a machine with
nothing on it yet.

Safe to re-run. Then add apps with 'komizo add', or just 'komizo root@myhost'.

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}
