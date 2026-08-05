package app

import (
	"context"
	"flag"
	"fmt"
	"os/signal"
	"syscall"

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
}

func RunInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() { usageInit(fs) }
	var o initOpts
	fs.StringVar(&o.host, "host", "", "server to set up, [user@]HOST (user defaults to root)")
	fs.StringVar(&o.network, "network", defaultNetwork, "docker network apps join to be reachable")
	fs.StringVar(&o.image, "proxy-image", defaultProxy, "caddy image to run")
	fs.BoolVar(&o.acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	fs.StringVar(&o.name, "name", "", "what to call this server in the app (default: the host you connect to)")
	fs.StringVar(&o.apiHost, "api-host", "", "hostname the app reads this box on (default: the host you connect to, if it is a name)")
	fs.IntVar(&o.port, "port", 22, "SSH port")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
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

	step("Setting up %s", tgt.host)
	if err := tgt.runScript(scripts.AlpineInitScript, map[string]string{"SHARED_NETWORK": o.network}); err != nil {
		return fmt.Errorf("the server-side script failed -- see the output above")
	}

	step("Installing the komizo agent")
	if err := installAgent(tgt, nil); err != nil {
		return fmt.Errorf("the server is ready, but the agent failed to install:\n    %w\n\n"+
			"    komizo reads a server through that agent, so `komizo list` and the\n"+
			"    monitor will not work against this box until it is fixed.", err)
	}

	step("Filing this server under your account")
	if err := registerAndEnrol(tgt, o.name, o.apiHost); err != nil {
		// NOT fatal. The box is set up and works; what failed is the half that
		// needs the service, and komizo enrol does exactly this later. Failing
		// the whole command would make a service outage look like a broken
		// server.
		note("could not register this server: %v", err)
		note("the box is set up. Run `komizo enrol --host %s` when the service is reachable.", tgt.host)
	}

	step("Installing the shared reverse proxy")
	if err := tgt.runScript(scripts.AlpineProxyScript, proxyEnv(proxyOpts{
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

// registerAndEnrol files a box under whoever is signed in, and enrols it.
//
// The point of the CLI having an account. The enrolment token is minted and
// spent inside this one command, so nothing is carried between two surfaces --
// and the server appears in the app the moment the box is genuinely ready,
// rather than as a pending row that may never become anything.
//
// Called AFTER the box is set up, deliberately. A failure before this point
// leaves nothing behind, which is what design/enrolment.md §3 promises and what
// creating the row first would quietly break.
// signalContextCLI cancels on ctrl-c, so a slow service call does not have to
// be waited out.
func signalContextCLI() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func registerAndEnrol(t target, name, apiHost string) error {
	s, err := requireSession()
	if err != nil {
		return err
	}
	if name == "" {
		name = t.host
	}
	endpoint, err := box.APIHostFor(t.host, apiHost)
	if err != nil {
		return err
	}

	ctx, stop := signalContextCLI()
	defer stop()
	created, err := createServer(ctx, s, name)
	if err != nil {
		return err
	}

	// The token goes over stdin as part of the script rather than on the remote
	// command line: a command line is visible in the box's process table to
	// every account on it, for as long as the command runs.
	if err := t.runScript(scripts.AgentEnrol(s.API, created.Token, endpoint), nil); err != nil {
		return fmt.Errorf("the server was created but did not enrol -- run `komizo enrol --host %s` to retry", t.host)
	}
	note("this server is in your app as %q.", name)
	if endpoint == "" {
		note("no endpoint: %s is an address, not a name, so the app cannot open it.", t.host)
	}
	return nil
}
