package app

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
)

// `komizo enrol` -- point a box at a komizo service.
//
// This command carries two values to a machine and runs one command there. It
// deliberately does no more than that: the exchange happens on the BOX, as
// root, so the long-lived credential is written where it belongs and never
// exists on the operator's laptop. See design/enrolment.md §3.
//
// It is also optional, permanently. A box that has never heard of the service
// works exactly as it does today -- appify.md §10 requires that, and it is what
// keeps the CLI free and unlimited.

func RunEnrol(args []string) error {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	fs.Usage = func() { usageEnrol(fs) }
	var host, api, token, apiHost, name string
	var port int
	var acceptHostKey, undo bool
	fs.StringVar(&host, "host", "", "server to enrol, [user@]HOST -- must be root")
	fs.StringVar(&api, "api", "", "the service to enrol against (required with --token; there is no default -- the komizo service is decommissioned)")
	fs.StringVar(&token, "token", "", "the single-use enrolment token issued by that service")
	fs.StringVar(&apiHost, "api-host", "", "hostname the app reads this box on (default: the host you connect to, if it is a name)")
	fs.StringVar(&name, "name", "", "what to call this server in the app (default: the host you connect to)")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	fs.BoolVar(&undo, "remove", false, "stop reporting, and forget the credential")
	var keys box.DeviceKeyList
	fs.Var(&keys, "device-key", box.DeviceKeyUsage)
	var forgetDevices bool
	fs.BoolVar(&forgetDevices, "forget-devices", false, "drop the devices this box already takes orders from")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	// REFUSED FIRST, and before a target is resolved or a box is reached.
	//
	// Without a token this command minted one itself, from the komizo service,
	// which is decommissioned -- so that path is gone, gated rather than ripped
	// out, and it refuses without touching the network. --token and --remove
	// are service-free by design and stay: the exchange happens on the BOX.
	if !undo && token == "" {
		return errServiceDecommissioned
	}

	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if !undo {
		// A token enrolment points the box's agent at a service, and with the
		// komizo service decommissioned there is no default to point at --
		// so the address is required, and must name one the operator runs.
		if api == "" {
			return fmt.Errorf("--api is required with --token: the komizo service is decommissioned, " +
				"so there is no default to enrol against. Point it at a service you run, " +
				"or manage the box from the CLI -- enrolment is optional and always was.")
		}
		// Checked HERE as well as on the box, so a typo fails before anything
		// connects rather than after.
		if _, err := box.ValidateAPI(api); err != nil {
			return err
		}
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	// Which name the app will read this box on, or none.
	//
	// Defaulted from the SSH target rather than asked: reaching a box by name
	// means a record already points at it, and https://<that name> reaches the
	// Caddy on it. An IP target has no endpoint at all -- see box/endpoint.go,
	// and the note below, which exists because a box that reports perfectly and
	// shows nothing in the app is otherwise a mystery.
	endpoint, err := box.APIHostFor(tgt.host, apiHost)
	if err != nil {
		return err
	}

	if undo {
		step("Removing %s from the komizo service", tgt.host)
		if err := tgt.runScript(scripts.AgentUnenrol(), nil); err != nil {
			return fmt.Errorf("could not remove the credential -- see the output above")
		}
		note("revoke this server on the dashboard too; removing the file does not.")
		return nil
	}

	step("Enrolling %s", tgt.host)
	// The token goes over stdin as part of the script rather than on the remote
	// command line: a command line is visible in the box's process table to
	// every account on it, for as long as the command runs.
	if err := tgt.runScript(scripts.AgentEnrol(api, token, endpoint, keys, forgetDevices), nil); err != nil {
		return fmt.Errorf("enrolment failed -- see the output above.\n\n" +
			"    An enrolment token is single-use and expires in fifteen minutes.\n" +
			"    Issue a fresh one and try again.")
	}
	note("this server now reports to %s.", api)

	// Said plainly, because it is the difference between a box the app can open
	// and one it can only list. A server that reports perfectly and shows
	// nothing when you tap it is otherwise a mystery, and the reason is a
	// certificate rather than anything wrong with the machine.
	if endpoint == "" {
		note("no endpoint: %s is an address, not a name, so no certificate authority", tgt.host)
		note("will issue for it. This box reports and is readable with komizo, but the")
		note("app cannot open it. Point a DNS record at it and re-run with --api-host.")
	} else {
		note("the app reads this box at https://%s -- point that name here if it does not already.", endpoint)
	}
	return nil
}

func usageEnrol(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, strings.TrimLeft(`
komizo enrol -- point a server at a komizo service

  komizo enrol --host root@server --token kmz_enr_... --api https://service-you-run
  komizo enrol --host root@server --remove

Optional, and reversible. A server that is not enrolled works exactly as it
does otherwise; enrolling adds a dashboard, not a dependency -- deploys never
consult the service.

The komizo service is decommissioned (board decision), so the tokenless form of
this command is gone: it refuses without touching the network, and there is no
default --api any more. The two forms that remain are service-free by design --
the exchange happens on the box, so they work against a service you run. The
token is single-use and expires in fifteen minutes; the long-lived credential
it becomes is written by root on the server and never touches this machine.

Flags:
`, "\n"))
	fs.PrintDefaults()
}
