package app

import (
	"flag"
	"fmt"
	"strings"

	"github.com/nicodes/komizo/scripts"
)

// RunUnsetSecret takes secrets off a box: the counterpart set-secret never had.
//
// set-secret writes a key and never deletes one, which is deliberate on the
// write side -- it is what lets CI rotate a credential without being able to
// read the ones already there. What it left missing was any way to take a
// value OFF a box. A key dropped from a workflow stayed in secrets.env
// indefinitely: referenced by nothing, rotated by nothing, and still readable
// by every container that reads the file. One portfolio had twelve of them on
// three servers, including a PocketBase admin password for a PocketBase
// removed months earlier, and clearing them meant hand-editing secrets.env
// over SSH -- the unaccountable write the secret store exists to prevent.
//
// AN OPERATOR COMMAND, not a deploy one. It runs as root over the same
// connection `komizo remove` uses, and installs nothing on the box: there is
// no unset-secret-<app> beside set-secret-<app> and no doas rule for one. A
// pipeline able to delete a secret is a pipeline able to take an app down by
// deleting the one it needs to start, and no workflow has ever needed to.
//
// --yes for the same reason `komizo remove` needs it: alone among the secret
// commands, this destroys a value. Overwriting a secret with set-secret can be
// undone by setting it again from GitHub; deleting one that was only ever on
// the box cannot be undone at all, which is why the box keeps a dated 0600
// copy beside the original.
func RunUnsetSecret(args []string) error {
	fs := flag.NewFlagSet("unset-secret", flag.ContinueOnError)
	fs.Usage = func() { usageUnsetSecret(fs) }
	var host, app, names, keep string
	var port int
	var list, yes, acceptHostKey bool
	fs.StringVar(&host, "host", "", "server, [user@]HOST")
	fs.StringVar(&app, "app", "", "which app")
	fs.StringVar(&names, "name", "", "secret to remove; repeat with commas for several")
	fs.StringVar(&keep, "keep", "", "instead, the only names to KEEP -- everything else goes")
	fs.BoolVar(&list, "list", false, "print the names this app has and change nothing")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&yes, "yes", false, "required to delete: confirms you mean it")
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

	env, err := unsetPlan(app, host, names, keep, list, yes)
	if err != nil {
		return err
	}

	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	if err := tgt.runScript(scripts.AlpineUnsetSecretScript, env); err != nil {
		return fmt.Errorf("unset-secret failed -- see the output above")
	}
	return nil
}

// unsetPlan turns the flags into the environment the box script reads, or into
// the reason not to run it at all.
//
// Separated from RunUnsetSecret because everything it decides must be settled
// BEFORE a connection opens, and a check that can only be reached by opening
// one cannot be tested without a server. It was not separate at first, and the
// gap showed up the first time the command ran against a real box: `--list`
// fell through to the name parser and was refused with "no secret names
// given", having asked for none.
func unsetPlan(app, host, names, keep string, list, yes bool) (map[string]string, error) {
	// --name and --keep are opposite descriptions of the same edit, and a
	// caller who passed both would have written down two intentions without
	// saying which wins. Guessing here decides, on somebody's server, which
	// credentials survive.
	if names != "" && keep != "" {
		return nil, fmt.Errorf("pass --name (what to remove) or --keep (what survives), not both")
	}
	if list && (names != "" || keep != "") {
		return nil, fmt.Errorf("--list only reads; drop --name/--keep, or drop --list")
	}
	if list {
		return map[string]string{"APP_NAME": app, "LIST": "1"}, nil
	}
	if names == "" && keep == "" {
		return nil, fmt.Errorf("nothing to do -- pass --name, --keep, or --list to see what is there")
	}

	wanted := names
	if keep != "" {
		wanted = keep
	}
	parsed, err := secretNames(wanted)
	if err != nil {
		return nil, err
	}

	if !yes {
		what := fmt.Sprintf("removes %s from", strings.Join(parsed, ", "))
		if keep != "" {
			what = fmt.Sprintf("removes everything except %s from", strings.Join(parsed, ", "))
		}
		return nil, fmt.Errorf("this %s %s on %s, and a deleted value may be the only copy.\n"+
			"    The box keeps a dated root-only backup beside the file.\n"+
			"    Re-run with --yes if that is what you want.", what, "/srv/"+app+"/secrets.env", host)
	}

	env := map[string]string{"APP_NAME": app, "NAMES": strings.Join(parsed, " ")}
	if keep != "" {
		env["KEEP"] = "1"
	}
	return env, nil
}

// secretNames splits and checks a comma-separated list of secret names.
//
// The same charset set-secret enforces on the way in, checked again here so a
// bad name is refused on the operator's machine rather than becoming a grep
// pattern on the box. A name carrying a regex metacharacter would otherwise
// match keys nobody asked about -- and this is the command that deletes them.
func secretNames(list string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(list, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if !onlyChars(name, secretChars) {
			return nil, fmt.Errorf("secret names are letters, digits and underscore; got %q", name)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no secret names given")
	}
	return out, nil
}

func usageUnsetSecret(fs *flag.FlagSet) {
	fmt.Print(`komizo unset-secret - take secrets off a server

  komizo unset-secret --host root@myhost --app blog --list
  komizo unset-secret --host root@myhost --app blog --name OLD_API_KEY --yes
  komizo unset-secret --host root@myhost --app blog --keep DATABASE_URL,CLERK_SECRET_KEY --yes

set-secret writes a key and never deletes one, so a name dropped from a
workflow stays in the host's secrets.env indefinitely -- delivered by nothing,
rotated by nothing, and still read by whichever containers read that file.
This is how you take one off.

--list prints the names the app has, and only the names: no komizo command
prints a secret's value, which is what makes holding the deploy key different
from holding production.

--keep is the other direction, for when the list of what should survive is
shorter than the list of what should not. Everything else in the file goes.

This runs as root from your machine. It installs nothing on the box: there is
no unset-secret command beside set-secret and no doas rule for one, because a
pipeline that can delete a secret can take an app down by deleting the one it
needs to start.

The box writes a dated root-only copy of the file beside it first. Delete that
once a deploy has proved the app still starts. Running containers keep the
values they started with -- the next deploy is what recreates them without
these.

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}
