package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
	fs.StringVar(&o.keyPath, "key", "", "where to write the keypair (default ~/.ssh/deploy_<app>_<host>)")
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

func runAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.Usage = func() { usageAdd(fs) }
	var o addOpts
	o.bind(fs)
	if err := fs.Parse(args); err != nil {
		return errSilent
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
	for _, a := range strings.Split(o.knownAs, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if err := validateHost(a); err != nil {
			return fmt.Errorf("--known-as: %w", err)
		}
		tgt.aliases = append(tgt.aliases, a)
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
		rotate:  o.rotateKey,
		harden:  o.hardenSSHD && !o.rotateKey,
	}, cliProgress{}, tgt.runScript)
	if err != nil {
		return err
	}
	// Both may have been resolved inside: the config read back off the box on a
	// rotation, the key path defaulted. printNextSteps prints them.
	o.config, o.keyPath = res.config, res.keyPath

	printNextSteps(o, tgt, res.knownHosts)
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
	keyPath string // empty means the default under ~/.ssh
	rotate  bool
	harden  bool
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

	if p.keyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot find your home directory: %w", err)
		}
		// Includes the app: two apps on one host have separate accounts, and
		// reusing one keypair for both would hand a single key access to all.
		p.keyPath = filepath.Join(home, ".ssh",
			fmt.Sprintf("deploy_%s_%s", p.app, sanitize(p.tgt.host)))
	}

	// --- keypair, generated here -------------------------------------------

	out.step("Deploy keypair")
	if p.rotate || !fileExists(p.keyPath) {
		if fileExists(p.keyPath) {
			backup := fmt.Sprintf("%s.replaced.%s", p.keyPath, time.Now().Format("20060102150405"))
			if err := os.Rename(p.keyPath, backup); err != nil {
				return nil, err
			}
			_ = os.Rename(p.keyPath+".pub", backup+".pub")
			out.note("previous key kept at %s", backup)
		}
		if err := os.MkdirAll(filepath.Dir(p.keyPath), 0o700); err != nil {
			return nil, err
		}
		comment := fmt.Sprintf("komizo:%s@%s", p.user, p.tgt.host)
		gen := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-C", comment, "-f", p.keyPath, "-N", "")
		if msg, err := gen.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("ssh-keygen failed: %s", strings.TrimSpace(string(msg)))
		}
		out.note("generated %s", p.keyPath)
	} else {
		out.note("reusing %s (rotate the key to replace it)", p.keyPath)
	}
	pub, err := os.ReadFile(p.keyPath + ".pub")
	if err != nil {
		return nil, fmt.Errorf("cannot read the public key: %w", err)
	}

	// --- run the server half -----------------------------------------------

	env := map[string]string{
		"CI_PUBKEY":    strings.TrimSpace(string(pub)),
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
	if err := runner(AlpineScript, env); err != nil {
		return nil, fmt.Errorf("the server-side script failed -- see the output above.\n" +
			"    Nothing further was changed.")
	}

	// --- host key, straight from the box -----------------------------------

	out.step("Reading the server's host keys")
	kh, err := readKnownHosts(p.tgt)
	if err != nil {
		return nil, err
	}
	// Lines, not keys: a server answering to more than one name gets one line
	// per name per key, so counting keys here would under-report the value.
	out.note("%d known_hosts line(s) captured", len(strings.Split(kh, "\n")))

	return &addResult{
		app:         p.app,
		keyPath:     p.keyPath,
		knownHosts:  kh,
		config:      p.config,
		rotated:     p.rotate,
		onClipboard: -1,
	}, nil
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
