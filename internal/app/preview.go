package app

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/nicodes/komizo/box"
	"os"
	"strconv"
	"strings"
)

// `komizo preview` -- ephemeral PR-preview environments, from the command
// line. A thin wrapper, deliberately: the whole lifecycle lives in
// `komizo-box preview` on the box, which is the single implementation, so
// what runs here is resolve-the-target and ask. See box/preview.go for what a
// preview is and may never touch.

// RunPreview handles `komizo preview up|down|resolve|ls|gc`.
func RunPreview(args []string) (err error) {
	validation := localInput(&err)
	defer validation.finish()
	// The subcommand is the first NON-FLAG argument. Anything starting with a
	// dash goes to the flag parser instead, so a bogus flag fails there --
	// with the same ErrSilent every other command answers a bad flag with,
	// which the dispatch test pins.
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("preview "+sub, flag.ContinueOnError)
	fs.SetOutput(commandFlags())
	fs.Usage = func() { usagePreview(fs, sub) }
	var host, app, profileFile string
	directory := fs.String("directory", ".", "project directory for private target and image defaults")
	var profileBody []byte
	var pr, port int
	var acceptHostKey bool
	fs.StringVar(&host, "host", "", "server, [user@]HOST (user defaults to root)")
	fs.StringVar(&profileFile, "profile-file", "", "operator-reviewed preview profile JSON (configure only)")
	fs.StringVar(&app, "app", "", "the app this is a preview of")
	fs.IntVar(&pr, "pr", 0, "the pull request number")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return silentFlagError(err)
	}
	if sub == "" {
		sub = "up"
	}
	switch sub {
	case "up", "down", "resolve", "ls", "gc", "database", "configure":
	default:
		return fmt.Errorf("preview what -- up, down, resolve, ls, gc or database, not %q", sub)
	}
	if sub == "database" && (app != "" || pr != 0 || fs.NArg() != 0) {
		return fmt.Errorf("preview database accepts only host connection flags")
	}

	projectDefault := host == ""
	m, resolveErr := defaultProjectTarget(*directory, &host, &port, &app, fs)
	if resolveErr != nil {
		return resolveErr
	}
	images := fs.Args()
	if projectDefault && sub == "up" && len(images) == 0 {
		revision, err := projectRevision(*directory)
		if err != nil {
			return err
		}
		for _, image := range m.Images {
			images = append(images, strings.ReplaceAll(image, "{revision}", revision))
		}
	}
	if sub == "configure" {
		if err := validateApp(app); err != nil {
			return err
		}
		if profileFile == "" || pr != 0 || fs.NArg() != 0 {
			return fmt.Errorf("preview configure requires --app and --profile-file only")
		}
		var err error
		profileBody, err = os.ReadFile(profileFile)
		if err != nil {
			return err
		}
		if _, err := box.ParsePreviewProfile(profileBody); err != nil {
			return err
		}
	} else if profileFile != "" {
		return fmt.Errorf("--profile-file is only for preview configure")
	}
	// Checked HERE as well as on the box, so a typo fails before anything
	// connects -- the box's check is the one that matters, this one is the
	// one that saves the round trip.
	if sub == "up" || sub == "down" || sub == "resolve" {
		if err := validateApp(app); err != nil {
			return err
		}
		if pr < 1 {
			return fmt.Errorf("--pr must be a positive integer, got %d", pr)
		}
	}
	if sub == "up" && len(images) == 0 {
		return fmt.Errorf("preview up needs at least one image -- a preview is images and nothing else")
	}
	for _, image := range images {
		if !onlyChars(image, imageChars+"@=") {
			return fmt.Errorf("image %q contains characters that are not valid in an image reference", image)
		}
	}

	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	validation.complete = true
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	remote := []string{"preview", sub}
	if sub == "up" || sub == "down" || sub == "resolve" {
		remote = append(remote, "--app", app, "--pr", strconv.Itoa(pr))
	}
	if sub == "configure" {
		remote = append(remote, "--app", app)
	}
	remote = append(remote, images...)

	var sb strings.Builder
	if sub == "configure" {
		sb.WriteString("printf %s " + shQuote(base64.StdEncoding.EncodeToString(profileBody)) + " | base64 -d | ")
	}
	sb.WriteString(BoxBin)
	for _, a := range remote {
		sb.WriteString(" " + shQuote(a))
	}
	if sub == "up" {
		step("Bringing %s PR #%d up on %s", app, pr, tgt.host)
	}
	if machineMode() && sub == "down" {
		if _, _, err := tgt.runScriptHeardTo(sb.String(), nil, progressOutput()); err != nil {
			return err
		}
		return managementReceipt("preview down", tgt, app, map[string]any{"pr": pr})
	}
	if machineMode() {
		body, err := tgt.runCapture(sb.String())
		if err != nil {
			return err
		}
		return emitProtocol([]byte(body))
	}
	_, _, err = tgt.runScriptHeardTo(sb.String(), nil, commandOutput())
	return err
}

func usagePreview(fs *flag.FlagSet, sub string) {
	fmt.Fprintf(commandOutput(), `komizo preview %s - ephemeral PR-preview environments

  komizo preview up   --host root@box --app myapp --pr 12 ghcr.io/you/web:pr-12 [more images...]
  komizo preview down --host root@box --app myapp --pr 12
  komizo preview resolve --host root@box --app myapp --pr 12 ghcr.io/you/web:pr-12 [more images...]
  komizo preview ls   --host root@box
  komizo preview gc   --host root@box
  komizo preview database --host root@box
  komizo preview configure --host root@box --app myapp --profile-file preview-profile.json

A preview is an isolated compose project per pull request -- its own
containers, its own database inside komizo's private preview server (created on up,
dropped on down, separate from production data), its own route at
the host-configured preview domain, capped memory and cpu, and a ceiling on how many
may exist with least-recently-used eviction. 'up' refuses below the
capacity floors in /etc/komizo/deploy-floors, exactly like a deploy.

The whole lifecycle runs on the box as root, through komizo-box preview --
the single implementation, so this command and rootd's reaper cannot
disagree about what a preview is.

Flags:
`, sub)
	fs.PrintDefaults()
	fmt.Fprintln(commandOutput())
}
