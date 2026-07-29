package app

import (
	"fmt"
	"strings"
)

// readKnownHosts builds the known_hosts lines CI will pin, by reading the
// server's own host keys over the session we have already authenticated on.
//
// Deliberately not ssh-keyscan: a keyscan trusts whatever answers on the port,
// so its output has to be compared against the box by hand afterwards. Reading
// the files directly over an authenticated connection removes the step and the
// chance of getting it wrong.
//
// The .pub files are "<type> <base64> <comment>"; known_hosts wants
// "<host> <type> <base64>".
//
// A server answering to more than one name gets a line per name. known_hosts is
// matched on the exact name the client dialled, so a box set up by IP and
// deployed to by hostname would otherwise match nothing, and CI stops with "no
// entry for <name>" while the right keys sit in the value.
func readKnownHosts(t target) (string, error) {
	out, err := t.quiet("cat /etc/ssh/ssh_host_*_key.pub 2>/dev/null")
	if err != nil {
		return "", fmt.Errorf("could not read the server's host keys: %w", err)
	}

	// One line per name per key -- the ordinary shape of a known_hosts file, the
	// same thing ssh writes into ~/.ssh/known_hosts. Comma-joining the names
	// into a single pattern is legal syntax and matches identically, but it is
	// not what anyone has in that file, so it reads as something unusual at the
	// exact moment someone is deciding whether to trust it.
	var keys [][2]string
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		if !strings.HasPrefix(f[0], "ssh-") && !strings.HasPrefix(f[0], "ecdsa-") {
			continue
		}
		keys = append(keys, [2]string{f[0], f[1]})
	}

	if len(keys) == 0 {
		return "", fmt.Errorf("the server reported no host keys -- is /etc/ssh readable as %s?", t.user)
	}
	return formatKnownHosts(t, keys), nil
}

// formatKnownHosts renders the value CI pins: one line per name per key.
func formatKnownHosts(t target, keys [][2]string) string {
	var lines []string
	for _, name := range t.knownHostsNames() {
		for _, k := range keys {
			lines = append(lines, fmt.Sprintf("%s %s %s", name, k[0], k[1]))
		}
	}
	return strings.Join(lines, "\n")
}
