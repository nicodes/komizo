package app

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
)

// RunEnrol removes a legacy hosted registration. New registrations refuse
// before target resolution, credentials or network access.

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
	if !undo {
		return errServiceDecommissioned
	}

	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	step("Removing legacy registration from %s", tgt.host)
	if err := tgt.runScript(scripts.AgentUnenrol(), nil); err != nil {
		return fmt.Errorf("could not remove the credential -- see the output above")
	}
	note("revoke this server on the old service too; removing the file does not.")
	return nil
}

func usageEnrol(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, strings.TrimLeft(`
komizo enrol -- remove a legacy hosted registration

  komizo enrol --host root@server --remove

New hosted registrations are unsupported and refuse before credentials or
network access. Manage boxes directly through SSH and komizo init.

Removal stops the legacy reporting and read API, drops its route and removes
that registration's credentials and device keys. Use it only to retire an
existing registration. Revoke its credential on the old service separately.

Flags:
`, "\n"))
	fs.PrintDefaults()
}
