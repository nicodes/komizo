package main

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
func readKnownHosts(t target) (string, error) {
	out, err := t.quiet("cat /etc/ssh/ssh_host_*_key.pub 2>/dev/null")
	if err != nil {
		return "", fmt.Errorf("could not read the server's host keys: %w", err)
	}

	var lines []string
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		if !strings.HasPrefix(f[0], "ssh-") && !strings.HasPrefix(f[0], "ecdsa-") {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %s %s", t.knownHostsField(), f[0], f[1]))
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("the server reported no host keys -- is /etc/ssh readable as %s?", t.user)
	}
	return strings.Join(lines, "\n"), nil
}
