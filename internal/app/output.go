package app

import (
	"fmt"
	"os"
	"strings"
)

func step(format string, a ...any) {
	fmt.Printf("\n==> "+format+"\n", a...)
}

func note(format string, a ...any) {
	fmt.Printf("    "+format+"\n", a...)
}

func warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", a...)
}

// stdoutIsTTY reports whether stdout is a terminal rather than a pipe, a file or
// a CI log. `komizo add` uses it to refuse printing the private key anywhere it
// would persist. A character device is what a terminal is; a redirected or
// piped stdout is not.
func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// progress is where a shared operation reports what it is doing. The CLI writes
// to the terminal; the interface streams into its run pane. Having the two
// differ only here is what lets `komizo add` and the interface's add be one
// implementation instead of two that drift.
type progress interface {
	step(format string, a ...any)
	note(format string, a ...any)
}

type cliProgress struct{}

func (cliProgress) step(format string, a ...any) { step(format, a...) }
func (cliProgress) note(format string, a ...any) { note(format, a...) }

const rule = "---------------------------------------------------------------------------"

// printNextSteps ends `add` with the two values GitHub needs and a workflow
// step to paste.
//
// The private key is printed only when there is nowhere else for it to go. It
// is generated in memory now and never written unless --key says where (see
// keys.go), so a non-interactive run without --key has stdout and nothing else
// -- and a key nobody can read is a deploy account nobody can use.
//
// This output is the sort of thing that ends up in a chat window when something
// goes wrong, so --key is the better habit for anything scripted: it keeps the
// value out of the scrollback and out of any log the run is piped into.
func printNextSteps(o addOpts, t target, knownHosts, key string) {
	fmt.Printf("\n%s\n Add these under Settings -> Secrets and variables -> Actions\n%s\n", rule, rule)

	fmt.Printf("\n 1. SECRET    KOMIZO_DEPLOY_KEY\n\n")
	if o.keyPath != "" {
		// The VALUE is the file's contents. Spelled out because "cat <path>" on
		// a line of its own reads like a value, and pasting that literal string
		// into the secret produces a deploy that fails much later with an
		// unhelpful authentication error.
		fmt.Printf("        the private key in this file (contents not shown here):\n"+
			"        %s\n", o.keyPath)
		if clipboardAvailable() {
			fmt.Printf("\n        To put it on the clipboard without printing it:\n"+
				"        %s < %s\n", strings.Join(clipboardCmd(), " "), o.keyPath)
		}
	} else {
		fmt.Printf("        Not written to disk. This is the only copy:\n\n")
		for _, ln := range strings.Split(strings.TrimRight(key, "\n"), "\n") {
			fmt.Printf("        %s\n", ln)
		}
		fmt.Printf("\n        Pass --key PATH to write it somewhere instead of printing it.\n")
	}
	fmt.Printf("\n 2. VARIABLE  KOMIZO_KNOWN_HOSTS\n\n")
	for _, ln := range strings.Split(knownHosts, "\n") {
		fmt.Printf("        %s\n", ln)
	}
	fmt.Printf("\n    A variable, not a secret: it needs integrity, not secrecy, and leaving\n" +
		"    it unmasked keeps a host-key mismatch readable in the log.\n")

	// The address CI dials, as a variable rather than a line in the workflow.
	// Moving an app to another box, or reaching this one by a different name
	// while its public DNS is mid-cutover, is then a settings change instead of
	// a commit and a deploy.
	fmt.Printf("\n 3. VARIABLE  KOMIZO_SERVER_URL\n\n        %s\n", t.knownHostsField())

	// The app name selects the deploy account, both privileged commands, and the
	// gateway the shared proxy is pointed at. Hold this one more loosely than
	// the three above: it is also written into the app's own compose.yml -- the
	// service must be named <app>-gateway -- and into its image names, all
	// committed. This variable is where CI reads it, not where it is decided.
	fmt.Printf("\n 4. VARIABLE  KOMIZO_APP_NAME\n\n        %s\n", o.app)
	fmt.Printf("\n%s\n", rule)

	if o.rotateKey {
		fmt.Printf("\n The old key stopped working the moment this ran -- keys are matched on\n" +
			" their comment, so the rotation replaced it rather than adding a second.\n" +
			" Update KOMIZO_DEPLOY_KEY before your next deploy.\n\n")
		return
	}

	if !o.hardenSSHD {
		fmt.Printf("\n Only %q was restricted in sshd -- no forwarding, no password auth.\n"+
			" Every other account, including root, is untouched. To also disable\n"+
			" password login machine-wide, re-run with --harden-sshd.\n", o.user)
	}

	portLine := ""
	if t.port != 22 {
		portLine = fmt.Sprintf("\n          port: \"%d\"", t.port)
	}

	// No app, host or key in the snippet: all four settings above are read from
	// the environment by name. Each secret the app needs is one more line under
	// env:, named KOMIZO_SECRET_<NAME>, and arrives on the host as <NAME>.
	fmt.Printf(`
 Then in your app repo: a compose.yml with a service named %s-gateway --
 your own Caddy, nginx, whatever -- listening on :80 and joined to the shared
 network. That container owns everything about how requests reach your app.

 Beside it, a hostnames file: one name per line. That is all this server is
 told; it writes the route itself, so nothing you ship can break another app.

 Both in a directory of their own (deploy/ by convention), then a workflow.
 Your deploy step:

   - uses: nicodes/komizo-actions/deploy@v0
     env:
          KOMIZO_APP_NAME: ${{ vars.KOMIZO_APP_NAME }}
          KOMIZO_SERVER_URL: ${{ vars.KOMIZO_SERVER_URL }}
          KOMIZO_DEPLOY_KEY: ${{ secrets.KOMIZO_DEPLOY_KEY }}
          KOMIZO_KNOWN_HOSTS: ${{ vars.KOMIZO_KNOWN_HOSTS }}

          KOMIZO_SECRET_DATABASE_URL: ${{ secrets.DATABASE_URL }}
     with:
          version: ${{ github.sha }}%s
          config-compose: deploy/compose.yml
          config-hostnames: deploy/hostnames
          config-image: %s
          registry-user: ${{ github.actor }}
          registry-token: ${{ secrets.GITHUB_TOKEN }}

`, o.app, portLine, o.config)
}
