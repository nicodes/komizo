package app

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// `komizo preview` -- ephemeral PR-preview environments, from the command
// line. A thin wrapper, deliberately: the whole lifecycle lives in
// `komizo-box preview` on the box, which is the single implementation, so
// what runs here is resolve-the-target and ask. See box/preview.go for what a
// preview is and may never touch.

// RunPreview handles `komizo preview up|down|ls|gc`.
func RunPreview(args []string) error {
	// The subcommand is the first NON-FLAG argument. Anything starting with a
	// dash goes to the flag parser instead, so a bogus flag fails there --
	// with the same ErrSilent every other command answers a bad flag with,
	// which the dispatch test pins.
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("preview "+sub, flag.ContinueOnError)
	fs.Usage = func() { usagePreview(fs, sub) }
	var host, app string
	var pr, port int
	var acceptHostKey bool
	fs.StringVar(&host, "host", "", "server, [user@]HOST (user defaults to root)")
	fs.StringVar(&app, "app", "", "the app this is a preview of")
	fs.IntVar(&pr, "pr", 0, "the pull request number")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	switch sub {
	case "up", "down", "ls", "gc":
	default:
		return fmt.Errorf("preview what -- up, down, ls or gc, not %q", sub)
	}

	// Checked HERE as well as on the box, so a typo fails before anything
	// connects -- the box's check is the one that matters, this one is the
	// one that saves the round trip.
	if sub == "up" || sub == "down" {
		if err := validateApp(app); err != nil {
			return err
		}
		if pr < 1 {
			return fmt.Errorf("--pr must be a positive integer, got %d", pr)
		}
	}
	if sub == "up" && fs.NArg() == 0 {
		return fmt.Errorf("preview up needs at least one image -- a preview is images and nothing else")
	}
	for _, image := range fs.Args() {
		if !onlyChars(image, imageChars+"@=") {
			return fmt.Errorf("image %q contains characters that are not valid in an image reference", image)
		}
	}

	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	remote := []string{"preview", sub}
	if sub == "up" || sub == "down" {
		remote = append(remote, "--app", app, "--pr", strconv.Itoa(pr))
	}
	remote = append(remote, fs.Args()...)

	var sb strings.Builder
	sb.WriteString(BoxBin)
	for _, a := range remote {
		sb.WriteString(" " + shQuote(a))
	}
	if sub == "up" {
		step("Bringing %s PR #%d up on %s", app, pr, tgt.host)
	}
	_, _, err = tgt.runScriptHeardTo(sb.String(), nil, os.Stdout)
	return err
}

func usagePreview(fs *flag.FlagSet, sub string) {
	fmt.Printf(`komizo preview %s - ephemeral PR-preview environments

  komizo preview up   --host root@box --app myapp --pr 12 ghcr.io/you/web:pr-12 [more images...]
  komizo preview down --host root@box --app myapp --pr 12
  komizo preview ls   --host root@box
  komizo preview gc   --host root@box

A preview is an isolated compose project per pull request -- its own
containers, its own database inside the app's postgres (created on up,
dropped on down, never shared, never prod data), its own route at
pr-<N>.preview.gdam.dev, capped memory and cpu, and a ceiling on how many
may exist with least-recently-used eviction. 'up' refuses below the
capacity floors in /etc/komizo/deploy-floors, exactly like a deploy.

The whole lifecycle runs on the box as root, through komizo-box preview --
the single implementation, so this command and rootd's reaper cannot
disagree about what a preview is.

Flags:
`, sub)
	fs.PrintDefaults()
	fmt.Println()
}
