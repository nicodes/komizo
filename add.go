package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nicodes/ncicd"
)

type addOpts struct {
	host       string
	app        string
	config     string
	user       string
	appDir     string
	keyPath    string
	network    string
	port       int
	hardenSSHD bool
	rotateKey  bool
}

func (o *addOpts) bind(fs *flag.FlagSet) {
	fs.StringVar(&o.host, "host", "", "server to set up, [user@]HOST (user defaults to root)")
	fs.StringVar(&o.app, "app", "", "which app on this box; each gets its own account, paths and rules")
	fs.StringVar(&o.config, "config", "", "registry path (NO tag) the host pulls compose.yml from")
	fs.StringVar(&o.user, "user", "", "deploy account (default cd-<app>, cd-user for the default app)")
	fs.StringVar(&o.appDir, "app-dir", "", "root-owned app directory (default /srv/<app>)")
	fs.StringVar(&o.keyPath, "key", "", "where to write the keypair (default ~/.ssh/deploy_<app>_<host>)")
	fs.StringVar(&o.network, "network", "", "create a shared docker network for a reverse proxy to reach apps over")
	fs.IntVar(&o.port, "port", 22, "SSH port")
	fs.BoolVar(&o.hardenSSHD, "harden-sshd", false, "also disable password auth and root password login for EVERY user")
	fs.BoolVar(&o.rotateKey, "rotate-key", false, "replace the deploy key and reprint the values; skip the rest")
}

// These mirror what the server script derives, so messages here name the same
// account and paths the box will actually use. Every app is named -- there is
// no unsuffixed special case, so a box set up for one app can host a second
// later without renaming what already exists.
func deriveUser(app string) string { return "cd-" + app }

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
	if err := validateNetwork(o.network); err != nil {
		return err
	}
	if o.port < 1 || o.port > 65535 {
		return fmt.Errorf("--port must be 1-65535, got %d", o.port)
	}
	// On a rotation the config image is read back off the box, so it is only
	// required when setting an app up.
	if !o.rotateKey {
		if err := validateConfigImage(o.config); err != nil {
			return err
		}
	} else if o.config != "" {
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

	if o.keyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot find your home directory: %w", err)
		}
		// Includes the app: two apps on one host have separate accounts, and
		// reusing one keypair for both would hand a single key access to all.
		o.keyPath = filepath.Join(home, ".ssh",
			fmt.Sprintf("deploy_%s_%s", o.app, sanitize(tgt.host)))
	}

	// --- preflight ---------------------------------------------------------

	step("Checking %s:%d", tgt.addr(), tgt.port)
	if !tgt.reachable() {
		return fmt.Errorf("cannot SSH in as %s without a password.\n"+
			"    This needs an existing login to work from. If you normally type a\n"+
			"    password, run 'ssh-copy-id -p %d %s' first.", tgt.user, tgt.port, tgt.addr())
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

	if o.rotateKey && o.config == "" {
		// Rotating a key must not change what config the host trusts, so carry
		// the existing value forward.
		out, err := tgt.quiet(fmt.Sprintf(
			`sed -n 's/^CONFIG_IMAGE="\(.*\)"$/\1/p' %s 2>/dev/null`, deployBin(o.app)))
		if err != nil || strings.TrimSpace(out) == "" {
			return fmt.Errorf("could not read the current config image from the server.\n"+
				"    Is %q set up there? Pass --config explicitly.", o.app)
		}
		o.config = strings.TrimSpace(out)
		note("keeping the configured image: %s", o.config)
	}

	// --- keypair, generated here -------------------------------------------

	step("Deploy keypair")
	if o.rotateKey || !fileExists(o.keyPath) {
		if fileExists(o.keyPath) {
			backup := fmt.Sprintf("%s.replaced.%s", o.keyPath, time.Now().Format("20060102150405"))
			if err := os.Rename(o.keyPath, backup); err != nil {
				return err
			}
			_ = os.Rename(o.keyPath+".pub", backup+".pub")
			note("previous key kept at %s", backup)
		}
		if err := os.MkdirAll(filepath.Dir(o.keyPath), 0o700); err != nil {
			return err
		}
		comment := fmt.Sprintf("ncicd:%s@%s", o.user, tgt.host)
		gen := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-C", comment, "-f", o.keyPath, "-N", "")
		gen.Stderr = os.Stderr
		if err := gen.Run(); err != nil {
			return fmt.Errorf("ssh-keygen failed: %w", err)
		}
		note("generated %s", o.keyPath)
	} else {
		note("reusing %s (pass --rotate-key to replace it)", o.keyPath)
	}
	pub, err := os.ReadFile(o.keyPath + ".pub")
	if err != nil {
		return fmt.Errorf("cannot read the public key: %w", err)
	}
	pubkey := strings.TrimSpace(string(pub))

	// --- run the server half -----------------------------------------------

	env := map[string]string{
		"CI_PUBKEY":    pubkey,
		"CI_USER":      o.user,
		"APP_NAME":     o.app,
		"CONFIG_IMAGE": o.config,
		"HARDEN_SSH":   boolEnv(o.hardenSSHD && !o.rotateKey),
	}
	if o.appDir != "" {
		env["APP_DIR"] = o.appDir
	}
	if o.network != "" && !o.rotateKey {
		env["SHARED_NETWORK"] = o.network
	}

	if o.rotateKey {
		step("Installing the rotated key")
	} else {
		step("Setting up %s on %s", o.app, tgt.host)
	}
	if err := tgt.runScript(ncicd.AlpineScript, env); err != nil {
		return fmt.Errorf("the server-side script failed -- see the output above.\n" +
			"    Nothing further was changed.")
	}

	// --- host key, straight from the box -----------------------------------

	step("Reading the server's host keys")
	kh, err := readKnownHosts(tgt)
	if err != nil {
		return err
	}
	note("%d key(s) captured", len(strings.Split(kh, "\n")))

	printNextSteps(o, tgt, kh)
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
