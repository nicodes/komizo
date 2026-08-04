package app

import (
	"flag"
	"fmt"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
)

// Bringing a server up to this komizo, from the command line.
//
// This is the `u` on the interface's komizo row, and it exists here because the
// two surfaces do the same things: the interface is what most people use, and
// it is not allowed to be the only way to reach a capability. A TUI-only
// operation cannot be scripted, cannot run in CI, and cannot be the answer when
// something has gone wrong with the interface itself.
//
// It also gave the errors nothing to name. "not installed -- press u" is advice
// that only works if you are already looking at a full-screen program, which is
// exactly not the case for whoever is reading it out of a log.
//
// ONE operation, re-running the whole setup rather than only replacing the
// agent binary. Docker, the shared network and the agent are what komizo puts
// on a box, and they are versioned together -- so there is no separate thing to
// update and no order to get wrong. Every script it runs is safe to re-run.

type updateOpts struct {
	host    string
	network string
	image   string
	port    int
	// See addOpts.acceptHostKey.
	acceptHostKey bool
	proxy         bool
	noProxy       bool
}

func RunUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.Usage = func() { usageUpdate(fs) }
	var o updateOpts
	fs.StringVar(&o.host, "host", "", "server to update, [user@]HOST (user defaults to root)")
	fs.StringVar(&o.network, "network", defaultNetwork, "docker network apps join to be reachable")
	fs.StringVar(&o.image, "proxy-image", defaultProxy, "caddy image to run")
	fs.BoolVar(&o.acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	fs.BoolVar(&o.proxy, "proxy", false, "update the shared proxy even if this box has none")
	fs.BoolVar(&o.noProxy, "no-proxy", false, "leave the shared proxy alone")
	fs.IntVar(&o.port, "port", 22, "SSH port")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if o.proxy && o.noProxy {
		return fmt.Errorf("--proxy and --no-proxy ask for opposite things")
	}
	if err := validateNetworkName(o.network); err != nil {
		return err
	}
	if !onlyChars(o.image, imageChars) {
		return fmt.Errorf("--proxy-image contains characters that are not valid in an image reference: %q", o.image)
	}

	tgt, err := resolveTarget(fs, o.host, o.port)
	if err != nil {
		return err
	}

	step("Checking %s:%d", tgt.addr(), tgt.port)
	if err := ensureReachable(tgt, o.acceptHostKey); err != nil {
		return err
	}
	note("reachable.")

	// Asked BEFORE anything is changed, and tolerated when it fails.
	//
	// The proxy is only updated on a box that already has one -- reinstalling
	// it on a box that deliberately has none would be this command deciding
	// something the operator did not ask for. But a box whose agent is broken
	// cannot answer, and that is precisely the box this command exists to fix,
	// so an unreadable box does not stop the update. It only means the proxy is
	// left alone unless --proxy says otherwise.
	hasProxy := o.proxy
	if !o.proxy && !o.noProxy {
		if rep, err := fetchBox[box.Report](tgt, "report"); err == nil {
			hasProxy = rep.Proxy != nil
		} else {
			note("could not read this box, so the proxy is being left alone.")
		}
	}

	step("Updating %s", tgt.host)
	if err := tgt.runScript(scripts.AlpineInitScript, map[string]string{"SHARED_NETWORK": o.network}); err != nil {
		return fmt.Errorf("the server-side script failed -- see the output above")
	}

	step("Installing the komizo agent")
	if err := installAgent(tgt, nil); err != nil {
		return fmt.Errorf("the server is set up, but the agent failed to install:\n    %w\n\n"+
			"    komizo reads a server through that agent, so `komizo list` and the\n"+
			"    interface will not work against this box until it is fixed.", err)
	}

	if o.noProxy || !hasProxy {
		return nil
	}
	step("Updating the shared reverse proxy")
	if err := tgt.runScript(scripts.AlpineProxyScript, proxyEnv(proxyOpts{
		network: o.network,
		image:   o.image,
	})); err != nil {
		return fmt.Errorf("the server updated, but the proxy failed -- see the output above.\n" +
			"    Re-run 'komizo proxy' once you have fixed it; the server itself is ready.")
	}
	return nil
}

func usageUpdate(fs *flag.FlagSet) {
	fmt.Fprint(fs.Output(), `komizo update -- bring a server up to this komizo

Re-runs everything komizo puts on a box: Docker, the shared network and the
agent, plus the proxy if the box already has one. Safe to re-run, and the way to
repair a box whose agent is missing or out of date.

This is what "u" does on the komizo row in the interface.

  komizo update --host root@box

Flags:
`)
	fs.PrintDefaults()
}
