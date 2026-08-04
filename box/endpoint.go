package box

import (
	"fmt"
	"net"
	"strings"
)

// Where this box answers for itself, and which boxes can.
//
// komizo-be design/registry.md §6: the app reads a box over HTTPS from the
// box's own endpoint, and whether that can work at all is decided by one thing
// -- a certificate.
//
// The shared proxy uses Caddy's automatic HTTPS. For a hostname that means a
// real certificate; for a bare IP it means Caddy's internal issuer, which is
// self-signed. That is fine in a terminal and fatal in a browser: a fetch from
// the app to a self-signed origin fails outright, and there is no click-through
// for a subresource the way there is for a top-level navigation.
//
// So an IP-addressed box has no endpoint. It reports normally and the CLI reads
// it normally -- SSH does not care about certificates -- and that is the whole
// of the difference. This file is where that rule is enforced once, rather than
// being a comment three commands each half-remember.

// ValidateAPIHost refuses a name that could not carry a public certificate.
//
// Checked here rather than at the moment Caddy fails, because the failure it
// prevents is asymmetric: a bad endpoint is a route on the SHARED proxy, and a
// config the proxy will not load takes every app on the box down with it.
func ValidateAPIHost(s string) error {
	if s == "" {
		return fmt.Errorf("an endpoint cannot be empty")
	}
	if IsIPAddress(s) {
		return fmt.Errorf("%q is an IP address, and no public certificate authority will "+
			"issue for one.\n"+
			"    The box would serve a self-signed certificate, which a browser refuses "+
			"outright for\n"+
			"    an app's requests. Point a DNS record at this box and use that name, or "+
			"leave the\n"+
			"    endpoint unset -- the CLI reads this box over SSH either way.", s)
	}
	// A bare label -- "box", "localhost" -- cannot be issued for publicly
	// either, and would silently become the same self-signed case.
	if !strings.Contains(strings.Trim(s, "."), ".") {
		return fmt.Errorf("%q is not a fully qualified name, so no certificate authority "+
			"will issue for it", s)
	}
	if strings.HasPrefix(s, "-") || !onlyHostChars(s) {
		return fmt.Errorf("%q is not a hostname", s)
	}
	return nil
}

// IsIPAddress is how the endpoint rule is decided, and it is deliberately not a
// guess about what the string looks like.
//
// net.ParseIP handles both families and the forms that only look like names --
// "::1", "2001:db8::1". A regexp over dots and digits would call an IPv6
// address a hostname.
func IsIPAddress(s string) bool {
	return net.ParseIP(strings.Trim(s, "[]")) != nil
}

// APIHostFor picks the endpoint from what is already known.
//
// The override wins. Otherwise the SSH target IS the answer whenever it is a
// name: reaching a box by one means a record already points at it, and
// https://<that name> reaches the Caddy on it. Asking a question whose answer is
// on the command line is how a setup step becomes something people skip.
//
// An IP target returns "" -- no endpoint, no error. That is a supported state,
// not a failure, and the caller is expected to say so out loud.
func APIHostFor(sshHost, override string) (string, error) {
	if override != "" {
		if err := ValidateAPIHost(override); err != nil {
			return "", err
		}
		return override, nil
	}
	if sshHost == "" || IsIPAddress(sshHost) {
		return "", nil
	}
	// A defaulted value is held to the same standard as a given one, but its
	// failure is not the operator's mistake -- so it simply does not default.
	if err := ValidateAPIHost(sshHost); err != nil {
		return "", nil
	}
	return sshHost, nil
}

func onlyHostChars(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}
