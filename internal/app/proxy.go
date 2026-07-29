package app

import (
	"flag"
	"fmt"
	"strings"

	"github.com/nicodes/komizo-be/cli/scripts"
)

// The shared reverse proxy is per-SERVER, so it gets its own command rather
// than a flag on `add`. It has no app name, no deploy account and no config
// image: nothing from CI ever touches it.
const (
	proxyDir       = "/srv/_proxy"
	proxyContainer = "komizo-proxy"
	defaultNetwork = "edge"
	defaultProxy   = "caddy:2"
)

type proxyOpts struct {
	host    string
	network string
	image   string
	// tlsAsk is the endpoint Caddy asks before issuing an on-demand
	// certificate. A SERVER setting, not an app's: it decides for the whole box
	// who may cause it to request a certificate, and Caddy accepts exactly one
	// such block -- so it cannot live in a config image that a second app might
	// also want to write.
	tlsAsk string
	port   int
	// See addOpts.acceptHostKey.
	acceptHostKey bool
}

func RunProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.Usage = func() { usageProxy(fs) }
	var o proxyOpts
	fs.StringVar(&o.host, "host", "", "server, [user@]HOST (user defaults to root)")
	fs.StringVar(&o.network, "network", defaultNetwork, "docker network apps join to be reachable")
	fs.StringVar(&o.image, "image", defaultProxy, "caddy image to run")
	fs.StringVar(&o.tlsAsk, "tls-ask", "", "URL asked before issuing an on-demand certificate (for wildcard hostnames)")
	fs.IntVar(&o.port, "port", 22, "SSH port")
	fs.BoolVar(&o.acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if err := validateNetworkName(o.network); err != nil {
		return err
	}
	if !onlyChars(o.image, imageChars) {
		return fmt.Errorf("--image contains characters that are not valid in an image reference: %q", o.image)
	}
	if err := validateTLSAsk(o.tlsAsk); err != nil {
		return err
	}

	tgt, err := resolveTarget(fs, o.host, o.port)
	if err != nil {
		return err
	}

	step("Checking %s:%d", tgt.addr(), tgt.port)
	if err := ensureReachable(tgt, o.acceptHostKey); err != nil {
		return err
	}
	note("reachable.")

	step("Installing the shared reverse proxy")
	if err := tgt.runScript(scripts.AlpineProxyScript, proxyEnv(o)); err != nil {
		return fmt.Errorf("the server-side script failed -- see the output above")
	}
	return nil
}

func proxyEnv(o proxyOpts) map[string]string {
	return map[string]string{
		"SHARED_NETWORK": o.network,
		"PROXY_IMAGE":    o.image,
		"TLS_ASK":        o.tlsAsk,
	}
}

// validateTLSAsk constrains the value before it is interpolated into the
// server's Caddyfile. Empty is the normal case: on-demand certificates are only
// needed by a wildcard hostname.
func validateTLSAsk(s string) error {
	if s == "" {
		return nil
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return fmt.Errorf("--tls-ask must be an http:// or https:// URL, got %q", s)
	}
	if !onlyChars(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:/_?=~%&-") {
		return fmt.Errorf("--tls-ask contains characters that are not valid in a URL: %q", s)
	}
	return nil
}

// validateNetworkName is the required form, unlike validateNetwork which allows
// an empty value to mean "no shared network".
func validateNetworkName(s string) error {
	if s == "" {
		return fmt.Errorf("--network cannot be empty")
	}
	return validateNetwork(s)
}

func usageProxy(fs *flag.FlagSet) {
	fmt.Print(`komizo proxy - install the one shared reverse proxy on a server

  komizo proxy --host root@myhost

One Caddy container per server terminates TLS and owns ports 80 and 443, so no
app has to publish one. It routes and nothing else: each hostname is handed to
the app that claimed it, and what happens after that is inside that app.

It holds no app's configuration and no app can write any. An app declares the
names it answers on -- a hostnames file in its config image -- and komizo
generates the route from it on deploy.

Certificates need no configuration -- Caddy obtains and renews them on its own.
The exception is a WILDCARD hostname, which cannot have an ordinary certificate
and needs one issued per name on demand. --tls-ask is the endpoint asked whether
a name is real, without which anyone pointing DNS at this box could make it
request certificates on their behalf.

Safe to re-run -- that is how you update Caddy, move it to another network, or
change the on-demand gate.

For an app to be reachable through it, that app's compose.yml must join the
shared network with a service named <app>-gateway, and its config image must
carry a hostnames file. See docs/proxy.md.

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}
