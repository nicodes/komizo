package main

import (
	"flag"
	"fmt"
)

// The shared reverse proxy is per-SERVER, so it gets its own command rather
// than a flag on `add`. It has no app name, no deploy account and no config
// image: nothing from CI ever touches it.
const (
	proxyDir       = "/srv/_proxy"
	proxyContainer = "komizo-caddy"
	defaultNetwork = "edge"
	defaultProxy   = "caddy:2"
)

type proxyOpts struct {
	host    string
	network string
	image   string
	port    int
}

func runProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.Usage = func() { usageProxy(fs) }
	var o proxyOpts
	fs.StringVar(&o.host, "host", "", "server, [user@]HOST (user defaults to root)")
	fs.StringVar(&o.network, "network", defaultNetwork, "docker network apps join to be reachable")
	fs.StringVar(&o.image, "image", defaultProxy, "caddy image to run")
	fs.IntVar(&o.port, "port", 22, "SSH port")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if o.host == "" {
		return fmt.Errorf("--host is required, e.g. --host root@myapp.example.com")
	}
	if err := validateNetworkName(o.network); err != nil {
		return err
	}
	if !onlyChars(o.image, imageChars) {
		return fmt.Errorf("--image contains characters that are not valid in an image reference: %q", o.image)
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

	step("Checking %s:%d", tgt.addr(), tgt.port)
	if r := tgt.probe(); !r.ok() {
		return r.explain(tgt)
	}
	note("reachable.")

	step("Installing the shared reverse proxy")
	if err := tgt.runScript(AlpineProxyScript, proxyEnv(o)); err != nil {
		return fmt.Errorf("the server-side script failed -- see the output above")
	}
	return nil
}

func proxyEnv(o proxyOpts) map[string]string {
	return map[string]string{
		"SHARED_NETWORK": o.network,
		"PROXY_IMAGE":    o.image,
	}
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
app has to publish one. It holds no per-app configuration: each app ships its
own routes in its own config image, and they are picked up on deploy.

Certificates need no configuration -- Caddy obtains and renews them on its own.

Safe to re-run -- that is how you update Caddy or move it to another network.

For an app to be reachable through it, that app's compose.yml must join the
shared network with a UNIQUE alias, and its config image must carry a fragment
at caddy/<anything>.caddy. See docs/proxy.md.

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}
