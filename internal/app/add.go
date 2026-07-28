package app

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nicodes/komizo-be/cli/scripts"
)

type addOpts struct {
	host       string
	app        string
	config     string
	user       string
	appDir     string
	keyPath    string
	knownAs    string
	port       int
	hardenSSHD bool
	rotateKey  bool
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

func deployBin(app string) string { return "/usr/local/bin/deploy-" + app }

func secretBin(app string) string { return "/usr/local/bin/set-secret-" + app }

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

	if o.host == "" {
		return fmt.Errorf("--host is required, e.g. --host root@myapp.example.com")
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
	if err := validateAppDir(o.appDir); err != nil {
		return err
	}
	if o.port < 1 || o.port > 65535 {
		return fmt.Errorf("--port must be 1-65535, got %d", o.port)
	}
	// On a rotation the config image is read back off the box, so an empty value
	// is only an error when setting an app up. A value that IS given is checked
	// either way.
	if !o.rotateKey || o.config != "" {
		if err := validateConfigImage(o.config); err != nil {
			return err
		}
	}

	tgt, err := parseTarget(o.host)
	if err != nil {
		return err
	}
	tgt.port = o.port
	tgt.portExplicit = portWasSet(fs)
	tgt.resolvePort()
	if err := validateHost(tgt.host); err != nil {
		return err
	}
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
		rotate:  o.rotateKey,
		harden:  o.hardenSSHD && !o.rotateKey,
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
	rotate  bool
	harden  bool

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
	if p.rotate && p.config == "" {
		// Rotating a key must not change what config the host trusts, so carry
		// the existing value forward.
		got, err := p.tgt.quiet(fmt.Sprintf(
			`sed -n 's/^CONFIG_IMAGE="\(.*\)"$/\1/p' %s 2>/dev/null`, deployBin(p.app)))
		if err != nil || strings.TrimSpace(got) == "" {
			return nil, fmt.Errorf("could not read the current config image for %q off the\n"+
				"    server -- is that app set up on this box?", p.app)
		}
		p.config = strings.TrimSpace(got)
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
	if err := os.WriteFile(path, []byte(kp.private), 0o600); err != nil {
		return fmt.Errorf("could not write the private key: %w", err)
	}
	if err := os.WriteFile(path+".pub", []byte(kp.public+"\n"), 0o644); err != nil {
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

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(appChars+".", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
