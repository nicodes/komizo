package app

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nicodes/komizo/scripts"
)

type addOpts struct {
	host    string
	app     string
	config  string
	user    string
	appDir  string
	keyPath string
	knownAs string
	// keepKey leaves the deploy key alone, for an edit that is about settings.
	keepKey bool
	// clearKnownAs is whether --known-as was GIVEN, as opposed to what it was
	// given. An empty value means two different things -- "I did not say" and
	// "I say: none" -- and the box needs to be told which. fs.Visit is the only
	// thing that knows.
	clearKnownAs bool
	port         int
	hardenSSHD   bool
	rotateKey    bool
	// acceptHostKey records an unseen server's key instead of refusing. Only
	// ever trust-on-first-use, which is why it is opt-in rather than the
	// default: it is the one moment nothing can verify the box for you.
	acceptHostKey bool
}

func (o *addOpts) bind(fs *flag.FlagSet) {
	fs.StringVar(&o.host, "host", "", "server to set up, [user@]HOST (user defaults to root)")
	fs.StringVar(&o.app, "app", "", "which app on this box; each gets its own account, paths and rules")
	fs.StringVar(&o.config, "config", "", "registry path (NO tag) the host pulls compose.yml from")
	fs.StringVar(&o.user, "user", "", "deploy account (default komizo-<app>)")
	fs.StringVar(&o.appDir, "app-dir", "", "root-owned app directory (default /srv/<app>)")
	fs.StringVar(&o.keyPath, "key", "", "also write the keypair here (default: not written, printed instead)")
	fs.StringVar(&o.knownAs, "known-as", "", "other hostname(s) CI connects by, comma-separated (host keys are pinned per name)")
	fs.IntVar(&o.port, "port", 22, "SSH port")
	fs.BoolVar(&o.hardenSSHD, "harden-sshd", false, "also disable password auth and root password login for EVERY user")
	fs.BoolVar(&o.acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	fs.BoolVar(&o.rotateKey, "rotate-key", false, "replace the deploy key and reprint the values; skip the rest")
	// KEEPING THE KEY IS WHAT A SETTINGS CHANGE WANTS, and it had no flag.
	//
	// Review 1 on nicodes/komizo-be#55: `keepKey` and the box's support for it
	// both survived the interface's deletion, and the only caller did not --
	// the interface's `c`, which said on its own result screen "Nothing in
	// GitHub changed". So re-pointing an app at a new config image issued the
	// repo a deploy key it does not know about, and its next deploy failed for
	// a reason nobody would connect to what they just did.
	//
	// `komizo update` is not the alternative: it keeps the key but reads the
	// image back off the record and cannot change it.
	fs.BoolVar(&o.keepKey, "keep-key", false, "change settings without issuing a new deploy key (CI keeps working)")
}

// deriveUser is the deploy account for an app. It mirrors what the server
// script derives, so messages here name the account the box will actually use.
//
// The hyphen is load-bearing. komizo's own accounts use an underscore --
// komizo_monitor, and anything added later -- so the two namespaces cannot
// collide for ANY app name: character seven is always "-" here and always "_"
// there. A reserved-word list would have grown with every account komizo
// gained, and adding one would have retroactively broken whoever already had an
// app by that name.
func deriveUser(app string) string { return "komizo-" + app }

// stateFile is where the server records what komizo knows about an app: its
// directory, its deploy account, its config image, the names CI dials it by.
// It mirrors alpine.sh, which writes it.
//
// A record rather than code. Everything that needs these values reads this --
// the agent's probes, a key rotation, the deploy script --
// where they used to be recovered by sed-ing them back out of the generated
// deploy script, which made five readers depend on one generator's formatting.
func stateFile(app string) string { return "/var/lib/komizo/apps/" + app + ".env" }

// appState reads one value out of an app's record on the box.
//
// The record, not the generated deploy script. Both hold the config image; only
// one of them is data, and reading komizo's own output back as a database is
// what the state file was introduced to stop.
//
// key is always a constant from this package -- the values are the ones
// alpine.sh writes -- so it is spliced into the sed rather than quoted; app
// comes from the caller and is not.
func appState(t target, app, key string) (string, error) {
	got, err := t.quiet(fmt.Sprintf(`sed -n 's/^%s=//p' %s 2>/dev/null | head -n 1`,
		key, shQuote(stateFile(app))))
	return strings.TrimSpace(got), err
}

func RunAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.Usage = func() { UsageAdd(fs) }
	var o addOpts
	o.bind(fs)
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}

	// Refuse to print the private key into something that is not a terminal -- a
	// CI log, a pipe, a file it gets redirected into -- where it would persist
	// unencrypted. --key is the scripted path: it writes the key to a file of
	// your choosing instead of stdout. Checked before anything touches the box.
	if o.keyPath == "" && !stdoutIsTTY() {
		return fmt.Errorf("refusing to print the private key to a non-terminal;\n" +
			"    pass --key PATH to write it to a file instead")
	}

	if err := validateApp(o.app); err != nil {
		return err
	}
	if o.user == "" {
		o.user = deriveUser(o.app)
	}
	if err := validateUser(o.user); err != nil {
		return err
	}
	// Never point the deploy account at root. Setting it up would rewrite root's
	// key list to hold only the generated deploy key -- turning the key pasted
	// into a GitHub secret into a root login and locking the operator out. The
	// server script enforces this too, for any pre-existing account.
	if o.user == "root" {
		return fmt.Errorf("--user must not be root; the deploy account is a separate, unprivileged user")
	}
	if err := validateAppDir(o.appDir); err != nil {
		return err
	}
	// On a rotation the config image is read back off the box, so an empty value
	// is only an error when setting an app up. A value that IS given is checked
	// either way.
	if !o.rotateKey || o.config != "" {
		if err := validateConfigImage(o.config); err != nil {
			return err
		}
	}

	tgt, err := resolveTarget(fs, o.host, o.port)
	if err != nil {
		return err
	}
	// ASKED OF THE FLAG SET, not inferred from the value. `--known-as ""` is how
	// somebody removes the last extra name, and it is indistinguishable from
	// not passing the flag at all unless the parser is asked. The box reads an
	// empty KNOWN_AS without CLEAR_KNOWN_AS as "unchanged" and restores what it
	// had recorded -- so editing the list down to nothing was the one edit that
	// silently did nothing. Review 1 on nicodes/komizo-be#55.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "known-as" {
			o.clearKnownAs = true
		}
	})

	var knownAs []string
	for _, a := range strings.Split(o.knownAs, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if err := validateHost(a); err != nil {
			return fmt.Errorf("--known-as: %w", err)
		}
		knownAs = append(knownAs, a)
	}

	// --- preflight ---------------------------------------------------------

	step("Checking %s:%d", tgt.addr(), tgt.port)
	if err := ensureReachable(tgt, o.acceptHostKey); err != nil {
		return err
	}
	note("reachable.")

	if !o.rotateKey && o.hardenSSHD {
		if _, err := tgt.quiet("test -s /root/.ssh/authorized_keys"); err != nil {
			return fmt.Errorf("--harden-sshd would disable password login, and root has no\n" +
				"    authorized_keys on the server -- that would leave it unreachable.\n" +
				"    Install your own key first (ssh-copy-id), or drop --harden-sshd.")
		}
		note("root can log in by key; safe to harden sshd.")
	}

	res, err := performAdd(addPlan{
		tgt:     tgt,
		app:     o.app,
		user:    o.user,
		config:  o.config,
		appDir:  o.appDir,
		keyPath: o.keyPath,
		knownAs: knownAs,
		// Only an answer when the flag was given AND resolved to nothing.
		// Passing names and clearing are not the same request.
		clearKnownAs: o.clearKnownAs && len(knownAs) == 0,
		keepKey:      o.keepKey,
		rotate:       o.rotateKey,
		harden:       o.hardenSSHD && !o.rotateKey,
	}, cliProgress{}, tgt.runScript)
	if err != nil {
		return err
	}
	// The config may have been resolved inside -- read back off the box on a
	// rotation -- and printNextSteps prints it.
	o.config = res.config

	printNextSteps(o, tgt, res.knownHosts, res.key)
	return nil
}

// addPlan is one app setup, fully resolved except for the values performAdd
// works out itself.
type addPlan struct {
	tgt     target
	app     string
	user    string // deploy account; deriveUser(app) unless --user overrode it
	config  string // may be empty on a rotation, then read back off the box
	appDir  string // empty means the server script's own default
	keyPath string // write the private key here too; empty means nowhere

	// knownAs is the extra names CI dials THIS app by, on top of the one we
	// connected on. Per app rather than per box: known_hosts matches the exact
	// string the client dialled, and each repo dials one name -- so the value
	// that repo pins should name that one, not every name every app on this
	// box answers to. Empty leaves whatever the box already recorded.
	knownAs []string
	// clearKnownAs says the empty knownAs above is an answer rather than a
	// silence. The server keeps the recorded names when it is not told any,
	// which is what a config-image change means by saying nothing -- so without
	// this, editing the list down to nothing is the one edit that does nothing.
	clearKnownAs bool
	rotate       bool
	harden       bool

	// keepKey leaves the account's existing authorized_keys alone. Changing an
	// app's config image re-runs this whole sequence, and issuing a new deploy
	// key for a setting change would break that repo's next deploy for a reason
	// nobody would connect to what they just did.
	keepKey bool
}

// performAdd is everything `komizo add` does once the connection is known to
// work: settle the config image, produce the keypair, run the server script,
// and read the host keys back.
//
// Shared by the CLI and the interface rather than written twice. They differ
// only in where progress goes and how the script is piped over, so those are
// the two parameters -- everything that actually changes the box is one copy.
// The earlier arrangement had the interface skipping validation the CLI did,
// which is the kind of drift that only shows up on someone else's server.
func performAdd(p addPlan, out progress, runner func(script string, env map[string]string) error) (*addResult, error) {
	if p.config == "" {
		// Rotating a key, or editing the names CI dials this app by, must not
		// change what config the host trusts -- so carry the existing value
		// forward. Read from the app's state file, which is what komizo records
		// about it, not back out of the generated deploy script, which is code
		// that happens to contain the value.
		got, err := appState(p.tgt, p.app, "CONFIG_IMAGE")
		if err != nil || got == "" {
			return nil, fmt.Errorf("could not read the current config image for %q off the\n"+
				"    server -- is that app set up on this box?", p.app)
		}
		p.config = got
		out.note("keeping the configured image: %s", p.config)
	}

	// --- keypair, in memory ------------------------------------------------
	//
	// Generated here and never written down. komizo does not use this key --
	// it connects as you, with your own -- so the private half exists to be
	// pasted into a GitHub secret and for nothing else. Writing it to ~/.ssh
	// was leaving a valid credential on the machine for every app on every box,
	// plus one more for every rotation, none of them ever read again.
	//
	// --key still writes it, for a script that has somewhere to put it.

	out.step("Deploy keypair")
	var kp keypair
	if p.keepKey {
		out.note("keeping the key already on the server")
	} else {
		var err error
		if kp, err = newKeypair(keyComment(p.user, p.tgt.host)); err != nil {
			return nil, err
		}
		out.note("generated an ed25519 key, held in memory only")
		if p.keyPath != "" {
			if err := writeKeyFile(p.keyPath, kp); err != nil {
				return nil, err
			}
			out.note("also written to %s", p.keyPath)
		}
	}

	// --- run the server half -----------------------------------------------

	// The names this app is dialled by, for the box to record. Comma-joined
	// because that is what the script reads back; empty means "unchanged",
	// which is what a config-image change is saying.
	env := map[string]string{
		"KNOWN_AS":     strings.Join(p.knownAs, ","),
		"CI_PUBKEY":    kp.public,
		"CI_USER":      p.user,
		"APP_NAME":     p.app,
		"CONFIG_IMAGE": p.config,
		"HARDEN_SSH":   boolEnv(p.harden),
		// Only ever 1 when the caller means "none", never as a matter of course:
		// the server reads an empty KNOWN_AS as "not mentioned" for every other
		// operation, and that is the reading a config-image change needs.
		"CLEAR_KNOWN_AS": boolEnv(p.clearKnownAs && len(p.knownAs) == 0),
	}
	if p.appDir != "" {
		env["APP_DIR"] = p.appDir
	}

	if p.rotate {
		out.step("Installing the rotated key")
	} else {
		out.step("Setting up %s on %s", p.app, p.tgt.host)
	}
	if err := runner(scripts.AlpineScript, env); err != nil {
		return nil, fmt.Errorf("the server-side script failed -- see the output above.\n" +
			"    Nothing further was changed.")
	}

	// --- host key, straight from the box -----------------------------------

	// Scoped to this app's names. The target carries the one we dialled; the
	// app adds any others its repo uses. Every app on the box shares the KEYS
	// -- they are the machine's -- and differs only in which names they are
	// written against, which is the half that belongs to the repo.
	out.step("Reading the server's host keys")
	kh, err := readKnownHosts(p.tgt.namedFor(p.knownAs))
	if err != nil {
		return nil, err
	}
	// Lines, not keys: a server answering to more than one name gets one line
	// per name per key, so counting keys here would under-report the value.
	out.note("%d known_hosts line(s) captured", len(strings.Split(kh, "\n")))

	return &addResult{
		app:         p.app,
		host:        p.tgt.serverURL(),
		port:        p.tgt.port,
		key:         kp.private,
		keyPath:     p.keyPath,
		knownHosts:  kh,
		config:      p.config,
		rotated:     p.rotate,
		onClipboard: -1,
	}, nil
}

// writeKeyFile is --key: the one way a private key reaches the disk, and only
// because a script asked for it by name.
func writeKeyFile(path string, kp keypair) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// O_EXCL|O_NOFOLLOW rather than WriteFile: the latter sets the mode only when
	// it creates the file, so an existing world-readable file, or a symlink into
	// a shared directory, would take the private key at the wrong permissions or
	// the wrong place. Refuse both -- a private key must land at 0600 on a real,
	// new file.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("could not write the private key: %w", err)
	}
	if _, err := f.WriteString(kp.private); err != nil {
		f.Close()
		return fmt.Errorf("could not write the private key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("could not write the private key: %w", err)
	}
	pf, err := os.OpenFile(path+".pub", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return fmt.Errorf("could not write the public key: %w", err)
	}
	if _, err := pf.WriteString(kp.public + "\n"); err != nil {
		pf.Close()
		return fmt.Errorf("could not write the public key: %w", err)
	}
	if err := pf.Close(); err != nil {
		return fmt.Errorf("could not write the public key: %w", err)
	}
	return nil
}

func boolEnv(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// addResult is what `add` and `rotate` leave the user with: the two things
// GitHub needs.
type addResult struct {
	app string
	// host is the address CI should dial: what KOMIZO_SERVER_URL is set to. Carried
	// on the result because the screen handing over the other two values is
	// where someone is already copying from.
	host string
	// key is the private half, held in memory for as long as this screen is
	// open and written nowhere. See keys.go.
	key string
	// keyPath is set only when --key asked for a copy on disk, which the
	// interface never does.
	keyPath    string
	knownHosts string
	// port is the SSH port CI has to dial. Carried so the screen can say so:
	// KOMIZO_SERVER_URL is the bare hostname (see target.serverURL), and on a box
	// that is not on 22 the port has to reach the workflow some other way -- the
	// deploy action's own `port:` input. It used to be folded into the URL as
	// "[host]:2222", which is a known_hosts pattern that the connect action
	// refuses outright.
	port int
	// config is what the box ended up pinned to -- given on a setup, read back
	// off the server on a rotation.
	config  string
	rotated bool

	// Both values have to reach GitHub, so both are selectable and both are
	// copyable.
	//
	// onClipboard is which one is there NOW, not which have ever been copied.
	// There is one clipboard: ticking every value that had been copied at some
	// point claimed two things were on it at once, and read as the mark being
	// stuck to the first row.
	cursor      int
	onClipboard int // index, or -1 for nothing
	copyErr     string

	// Set when this was a config-image change rather than a fresh setup: the
	// GitHub values are unchanged, so telling someone to paste them again
	// would be wrong.
	changedConfig string

	// Set when this was an edit to the names CI dials the app by.
	//
	// Unlike a config-image change, this one DOES move a value in GitHub:
	// known_hosts entries are written per name, so the app's KOMIZO_KNOWN_HOSTS
	// is a different string afterwards and the repo has to be given it.
	//
	// A flag beside the list rather than "the list is not nil", because clearing
	// the names is one of the edits and an emptied list is indistinguishable
	// from an absent one -- splitNames returns nil for both. Reading the
	// difference off a slice header would have made the emptied case render as a
	// fresh app setup, telling someone to paste a deploy key that was never
	// generated.
	namesChanged bool
	changedNames []string
}
