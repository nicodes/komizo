package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"

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
	fs.Var(&o.deviceKeys, "device-key", box.DeviceKeyUsage)
	fs.BoolVar(&o.forgetDevices, "forget-devices", false, "drop the devices this box already takes orders from")
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
	if err := registerAndEnrol(tgt, o.name, o.apiHost, o.deviceKeys, o.forgetDevices, nil); err != nil {
		// NOT fatal. The box is set up and works; what failed is the half that
		// needs the service, and komizo enrol does exactly this later. Failing
		// the whole command would make a service outage look like a broken
		// server.
		note("could not register this server: %v", err)
		note("the box is set up. %s", enrolAdvice(err, tgt.host))
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

// enrolAdvice says what to do about a registration that did not happen.
//
// Two causes with two different remedies, and telling them apart matters now
// that operating a box needs no account: "not signed in" is fixed by signing in,
// and waiting for a service that is already up would be waiting forever.
func enrolAdvice(err error, host string) string {
	if errors.Is(err, errNotSignedIn) {
		return fmt.Sprintf("run `komizo login`, then `komizo enrol --host %s`, to file it under your account.", host)
	}
	return fmt.Sprintf("run `komizo enrol --host %s` when the service is reachable.", host)
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

func registerAndEnrol(t target, name, apiHost string, keys []string, forget bool, ch chan tea.Msg) error {
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

	// A box that has enrolled before already HAS a row, and its id is in the
	// credential root wrote there. Re-enrolling one must reissue against that
	// row rather than create a second: a duplicate is a server in somebody's
	// app that will never report again, beside the one that does, with the same
	// name and no way to tell them apart.
	//
	// Asked of the BOX rather than remembered here, because this laptop is not
	// the only thing that ever enrols it.
	created, err := reuseOrCreate(ctx, t, s, name)
	if err != nil {
		return err
	}

	// The token goes over stdin as part of the script rather than on the remote
	// command line: a command line is visible in the box's process table to
	// every account on it, for as long as the command runs.
	sh := scripts.AgentEnrol(s.API, created.Token, endpoint, keys, forget)
	if ch == nil {
		if err := t.runScript(sh, nil); err != nil {
			return fmt.Errorf("the server was created but did not enrol -- run `komizo enrol --host %s` to retry", t.host)
		}
	} else if err := stream(ch, exec.Command("ssh", t.sshArgs("sh -s")...), sh); err != nil {
		return fmt.Errorf("the server was created but did not enrol -- press u to retry")
	}

	say(ch, fmt.Sprintf("this server is in your app as %q.", name))
	if endpoint == "" {
		say(ch, fmt.Sprintf("no endpoint: %s is an address, not a name, so the app cannot open it.", t.host))
	}
	return nil
}

// reuseOrCreate reissues for the server this box is already filed under, or
// creates one if it is not filed under anything.
//
// A failure to READ the existing id is not a failure to enrol -- an unreadable
// credential means a box that has never enrolled, or one whose file is gone,
// and both of those want a new row.
func reuseOrCreate(ctx context.Context, t target, s Session, name string) (createdServer, error) {
	if id := existingServerID(t); id != "" {
		c, err := reissueEnrolmentFor(ctx, s, id)
		if err == nil {
			return c, nil
		}
		// The row may have been removed in the app, or belong to another
		// account now. Creating one is the right answer to both, and is what
		// somebody re-running this expects.
		note("this box named a server that could not be reissued; filing it as a new one.")
	}
	return createServer(ctx, s, name)
}

// existingServerID reads what enrolment last wrote on the box.
func existingServerID(t target) string {
	var stdout bytes.Buffer
	c := exec.Command("ssh", t.sshArgs("cat "+box.AgentConfPath+" 2>/dev/null")...)
	c.Stdout = &stdout
	if err := c.Run(); err != nil {
		return ""
	}
	out := stdout.Bytes()
	var conf box.AgentConf
	if err := json.Unmarshal(out, &conf); err != nil {
		return ""
	}
	return conf.ServerID
}

// say reports progress to whichever surface asked for the work.
//
// The two are not interchangeable: note() writes to stdout, which under a
// full-screen interface lands in the middle of the frame. This is the same
// split installAgent already makes, and forgetting it is how the interface
// ended up not registering a server at all -- the capability was written for
// one surface and the other was never given it.
func say(ch chan tea.Msg, line string) {
	if ch == nil {
		note("%s", line)
		return
	}
	ch <- runOutputMsg(line)
}
