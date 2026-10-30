package app

import (
	"flag"
	"fmt"

	"github.com/nicodes/komizo/scripts"
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

func RunInit(args []string) error { return runInit(args, true) }

func runInit(args []string, receipt bool) (err error) {
	validation := localInput(&err)
	defer validation.finish()
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(commandFlags())
	fs.Usage = func() { usageInit(fs) }
	var o initOpts
	fs.StringVar(&o.host, "host", "", "server to set up, [user@]HOST (user defaults to root)")
	fs.StringVar(&o.network, "network", defaultNetwork, "docker network apps join to be reachable")
	fs.StringVar(&o.image, "proxy-image", defaultProxy, "caddy image to run")
	fs.BoolVar(&o.acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	fs.IntVar(&o.port, "port", 22, "SSH port")
	if err := fs.Parse(args); err != nil {
		return silentFlagError(err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if err := validateNetworkName(o.network); err != nil {
		return err
	}
	if !onlyChars(o.image, proxyImageChars) {
		return fmt.Errorf("--proxy-image contains characters that are not valid in an image reference: %q", o.image)
	}

	tgt, err := resolveTarget(fs, o.host, o.port)
	if err != nil {
		return err
	}

	step("Checking %s:%d", tgt.addr(), tgt.port)
	validation.complete = true
	if err := ensureReachable(tgt, o.acceptHostKey); err != nil {
		return err
	}
	note("reachable.")

	step("Setting up %s", tgt.host)
	if err := tgt.runScript(scripts.AlpineInitScript, map[string]string{"SHARED_NETWORK": o.network}); err != nil {
		return fmt.Errorf("the server-side script failed -- see the output above")
	}

	step("Installing the komizo agent")
	if err := installAgent(tgt); err != nil {
		return fmt.Errorf("the server is ready, but the agent failed to install:\n    %w\n\n"+
			"    komizo reads a server through that agent, so `komizo list` and\n"+
			"    the app will not work against this box until it is fixed.", err)
	}

	// SSH bootstrap provisions the shared proxy without hosted registration.
	step("Installing the shared reverse proxy")
	if err := tgt.runScript(scripts.AlpineProxyScript, proxyEnv(proxyOpts{
		network: o.network,
		image:   o.image,
	})); err != nil {
		return fmt.Errorf("Docker is installed, but the proxy failed -- see the output above.\n" +
			"    Re-run 'komizo proxy' once you have fixed it; the server itself is ready.")
	}
	if !receipt {
		return nil
	}
	return managementReceipt("init", tgt, "", map[string]any{"network": o.network})
}

func usageInit(fs *flag.FlagSet) {
	fmt.Fprint(commandOutput(), `komizo setup - prepare a fresh server

  komizo setup --host root@myhost

Installs Docker, enables it at boot, creates the network apps share, and starts
the one reverse proxy that terminates TLS for all of them. Nothing app-specific:
no hosted account or application registration is required.

Certificates need no configuration -- Caddy obtains and renews them on its own,
for whatever hostnames your apps publish.

The proxy is installed with finite limits. To stop it explicitly afterward, use
komizo stop --host root@HOST --proxy.

SSH is sufficient; bootstrap does not contact a registration service.

For a checked setup flow use 'komizo setup --host root@HOST'. Then register
apps with 'komizo setup --definition app.json' or 'komizo add'.

Flags:
`)
	fs.PrintDefaults()
	fmt.Fprintln(commandOutput())
}
