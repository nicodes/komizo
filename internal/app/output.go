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

	fmt.Printf("\n 1. SECRET    SSH_DEPLOY_KEY\n\n")
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
	fmt.Printf("\n 2. VARIABLE  SSH_KNOWN_HOSTS\n\n")
	for _, ln := range strings.Split(knownHosts, "\n") {
		fmt.Printf("        %s\n", ln)
	}
	fmt.Printf("\n    A variable, not a secret: it needs integrity, not secrecy, and leaving\n" +
		"    it unmasked keeps a host-key mismatch readable in the log.\n")
	fmt.Printf("\n%s\n", rule)

	if o.rotateKey {
		fmt.Printf("\n The old key stopped working the moment this ran -- keys are matched on\n" +
			" their comment, so the rotation replaced it rather than adding a second.\n" +
			" Update SSH_DEPLOY_KEY before your next deploy.\n\n")
		return
	}

	if !o.hardenSSHD {
		fmt.Printf("\n Only %q was restricted in sshd -- no forwarding, no password auth.\n"+
			" Every other account, including root, is untouched. To also disable\n"+
			" password login machine-wide, re-run with --harden-sshd.\n", o.user)
	}

	appLine := fmt.Sprintf("\n          app: %s", o.app)
	portLine := ""
	if t.port != 22 {
		portLine = fmt.Sprintf("\n          port: \"%d\"", t.port)
	}

	fmt.Printf(`
 Then in your app repo: put compose.yml in a directory of its own
 (deploy/ by convention) and add a workflow. Your deploy step:

   - uses: nicodes/komizo-actions/deploy@v0
     with:
          version: ${{ github.sha }}%s
          host: %s%s
          key: ${{ secrets.SSH_DEPLOY_KEY }}
          known-hosts: ${{ vars.SSH_KNOWN_HOSTS }}
          config-context: deploy
          config-image: %s
          registry-user: ${{ github.actor }}
          registry-token: ${{ secrets.GITHUB_TOKEN }}

`, appLine, t.host, portLine, o.config)
}
