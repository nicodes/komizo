package app

import (
	"flag"
	"fmt"

	"github.com/nicodes/komizo/box"
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
	name          string
	apiHost       string
	deviceKeys    box.DeviceKeyList
	forgetDevices bool
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
	fs.StringVar(&o.name, "name", "", "what to call this server in the app (default: the host you connect to)")
	fs.StringVar(&o.apiHost, "api-host", "", "hostname the app reads this box on (default: the host you connect to, if it is a name)")
	fs.IntVar(&o.port, "port", 22, "SSH port")
	fs.Var(&o.deviceKeys, "device-key", box.DeviceKeyUsage)
	fs.BoolVar(&o.forgetDevices, "forget-devices", false, "drop the devices this box already takes orders from")
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

	// THE PROXY GOES IN BEFORE ENROLMENT, and the order is the whole of the fix.
	//
	// It was the other way round, and the consequence was not a rare race: on
	// every fresh box, every time, `komizo init` published NO ROUTE for the box's
	// own name. agent-enrol.sh writes that route only when /srv/_proxy/routes
	// exists, and the proxy script below is what creates it -- so enrolling first
	// meant the guard was always false, the route was skipped in silence, and the
	// box came up enrolled, reporting, and unreachable at its own hostname.
	//
	// The symptom was three steps from the cause: the app showed komizo's stored
	// copy of the report with "could not reach this box" over the top, so it read
	// as DNS, or a certificate, or a box that was down. Nothing said a step had
	// been skipped, because from the script's point of view nothing went wrong.
	//
	// Nothing about enrolment needs the proxy to be absent, and nothing about the
	// proxy needs the box to be enrolled -- it is the shared, app-agnostic half,
	// installed on every box whether or not it ever joins a registry. So the
	// dependency runs one way and the steps now run in that direction.
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
	fmt.Fprint(commandOutput(), `komizo init - prepare a fresh server

  komizo setup --host root@myhost

Installs Docker, enables it at boot, creates the network apps share, and starts
the one reverse proxy that terminates TLS for all of them. Nothing app-specific:
no accounts, nothing under /srv.

Certificates need no configuration -- Caddy obtains and renews them on its own,
for whatever hostnames your apps publish.

The proxy is installed with finite limits. To stop it explicitly afterward, use
komizo stop --host root@HOST --proxy.

	The komizo service is decommissioned, so init no longer files the box under
	an account: the box is yours and the CLI manages it directly. --name,
	--api-host, --device-key and --forget-devices are accepted and ignored --
	they only ever fed that registration.

For a checked setup flow use 'komizo setup --host root@HOST'. Then register
apps with 'komizo setup --definition app.json' or 'komizo add'.

Flags:
`)
	fs.PrintDefaults()
	fmt.Fprintln(commandOutput())
}
