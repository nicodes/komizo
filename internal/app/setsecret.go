package app

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// RunSetSecret puts a secret on a box from an operator's machine.
//
// WHY IT EXISTS. Until now the only writer of the secret store was CI, through
// `doas set-secret-<app>` on the deploy account, and it could only write an
// env value: the setter refuses "a value that contains a newline, which an env
// file cannot represent". Everything that does not fit that shape -- an OpenAI
// key that has to be MOUNTED rather than exported, an age backup identity, a
// PEM, a postgres owner password the database reads before the app exists --
// was therefore put on the box by hand over SSH. Ten such files across five
// apps in one portfolio: delivered by nothing, rotated by nothing, and
// invisible to every komizo command.
//
// That is the largest remaining source of hand-placed state on these servers,
// and the only reason it existed was that komizo had no way to deliver it.
//
// AN OPERATOR COMMAND, like unset-secret and for the same reason: it runs as
// root over the operator's own connection. CI keeps the narrower grant it
// already has -- the set-secret-<app> binary on the box, which this command
// invokes rather than reimplements, so there is exactly one piece of code that
// decides where a secret lands and what mode it lands with.
//
// The value never appears in argv. It is read from a file or from stdin and
// piped to the remote command, because arguments are visible in the host's
// process list to every other user on the box -- the same rule the box-side
// setter has always followed.
func RunSetSecret(args []string) error {
	fs := flag.NewFlagSet("set-secret", flag.ContinueOnError)
	fs.Usage = func() { usageSetSecret(fs) }
	var host, app, name, from, uid string
	var port int
	var asFile, acceptHostKey bool
	fs.StringVar(&host, "host", "", "server, [user@]HOST")
	fs.StringVar(&app, "app", "", "which app")
	fs.StringVar(&name, "name", "", "the secret's name")
	fs.BoolVar(&asFile, "file", false, "write it as a file under secrets/ instead of a key in secrets.env")
	fs.StringVar(&from, "from", "", "read the value from this path (default: stdin)")
	fs.StringVar(&uid, "uid", "", "with --file: numeric owner, for a secret a non-root container must read")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if err := validateApp(app); err != nil {
		return err
	}
	remote, err := setSecretCommand(app, name, uid, asFile)
	if err != nil {
		return err
	}

	// Read it all before connecting. A half-delivered secret is worse than an
	// undelivered one -- the box-side setter renames a complete temp file into
	// place, and handing it a stream that dies midway would defeat that.
	value, err := readSecretValue(from)
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return fmt.Errorf("the value is empty -- refusing to write an empty secret.\n" +
			"    If you mean to remove it, that is `komizo unset-secret`.")
	}

	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}
	if err := tgt.runPiped(remote, bytes.NewReader(value), os.Stdout); err != nil {
		return fmt.Errorf("set-secret failed -- see the output above")
	}
	return nil
}

// setSecretCommand builds the remote command, validating every part of it
// here rather than trusting the box to refuse.
//
// The box-side setter validates too, and that is the check that matters --
// this one exists so a mistake is a message on the operator's terminal
// instead of a failed SSH round trip, and so that nothing this function
// assembles can be anything but a command name and two safe words.
func setSecretCommand(app, name, uid string, asFile bool) (string, error) {
	if name == "" {
		return "", fmt.Errorf("--name is required: the secret to write")
	}
	if asFile {
		switch {
		case name == "." || name == "..":
			return "", fmt.Errorf("--name %q is not a file name", name)
		case strings.HasPrefix(name, "."), strings.HasPrefix(name, "-"):
			return "", fmt.Errorf("a file secret's name must not start with '.' or '-': %q", name)
		case strings.ContainsAny(name, "/ \t\n"):
			return "", fmt.Errorf("a file secret's name must not contain a slash or whitespace: %q", name)
		}
		for _, r := range name {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
				return "", fmt.Errorf("a file secret's name may use letters, digits, dot, underscore and hyphen: %q", name)
			}
		}
	} else {
		if uid != "" {
			return "", fmt.Errorf("--uid applies only to --file: an env value has no owner of its own")
		}
		for _, r := range name {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
				return "", fmt.Errorf("an env secret's name may use letters, digits and underscore: %q.\n"+
					"    A name like this usually wants --file.", name)
			}
		}
	}
	cmd := "/usr/local/bin/set-secret-" + app
	if uid != "" {
		if _, err := strconv.Atoi(uid); err != nil {
			return "", fmt.Errorf("--uid must be numeric: %q", uid)
		}
		cmd += " --uid " + uid
	}
	if asFile {
		cmd += " --file"
	}
	return cmd + " " + name, nil
}

// readSecretValue takes the bytes from a path, or from stdin when there is no
// path. Bytes, not text: a file secret may be a PEM or a binary identity, and
// its trailing newline is part of it.
func readSecretValue(from string) ([]byte, error) {
	if from == "" || from == "-" {
		value, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading the value from stdin: %w", err)
		}
		return value, nil
	}
	value, err := os.ReadFile(from)
	if err != nil {
		return nil, fmt.Errorf("reading the value from %s: %w", from, err)
	}
	return value, nil
}

func usageSetSecret(fs *flag.FlagSet) {
	fmt.Fprint(fs.Output(), `komizo set-secret --host HOST --app NAME --name SECRET [--file] [--from PATH]

Put one secret on a box. The value comes from --from, or from stdin.

Two shapes. Without --file the value becomes a key in the app's secrets.env,
which is what CI writes and what most credentials are. With --file it becomes
a file under the app's secrets/ directory -- for the ones an env file cannot
carry: a PEM, an age identity, anything multi-line, and anything a container
has to MOUNT rather than read from the environment.

    komizo set-secret --host root@box --app cazper --name CLERK_SECRET_KEY
    komizo set-secret --host root@box --app cazper --name openai_api_key \
        --file --from ./key.txt --uid 65534

--uid is for the second case: a mounted secret is read by the container's
user, and a 0600 root file is unreadable to a container running as nobody.

The value is never an argument and is never echoed, here or on the box. Use
--from for anything you would rather not have in your shell history.

Removing one is 'komizo unset-secret'; '--list' there prints the names an app
has, of both shapes.

`)
	fs.PrintDefaults()
}
