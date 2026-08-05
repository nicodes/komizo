package box

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Recording that an app is down ON PURPOSE.
//
// This is the half that was missing. probe.go has read STOPPED out of an app's
// record since the report existed, diagnose.go keys the app_down problem on it,
// report_cmd.go prints it in the one column that would otherwise read as a
// fault, and komizo-be's appsFromReport defaults it to false -- four readers,
// and until komizo#48 not one writer anywhere in the repository. So `komizo
// stop` really did stop an app and really did leave it reported as broken, for
// as long as it stayed stopped. Every test that read the field also wrote the
// file by hand, which is why a reader with no writer survived a release.
//
// It lives in the app's OWN record under AppsDir rather than anywhere komizo
// serves, because of the constraint design/appify.md §2 puts on the deploy
// path: a deploy must not have to ask komizo anything. A deploy that has to
// consult a service to find out whether it may start the app is a deploy that
// fails when the service is down. A line in a file next to the app's directory
// is readable by the shell that is already reading APP_DIR out of the same
// file.
//
// Nothing here decides WHETHER a stop was deliberate. That decision belongs to
// the one process that saw the instruction arrive -- see runVerb in
// cmd/komizo-box/app.go, which is where both triggers end.

// The keys this writes, and probe.go reads. Named constants on both sides
// would be better still; they are named here because this file writes them and
// a typo in a literal produces a marker no reader ever matches -- which is
// exactly the shape of the defect this file exists to close.
const (
	stoppedKey   = "STOPPED"
	stoppedByKey = "STOPPED_BY"
	stoppedAtKey = "STOPPED_AT"
)

// StoppedByCLI is who stopped an app over SSH.
//
// The ROUTE, not a person, and that is the honest answer rather than a lazy
// one. What actually reaches the box on this path is an SSH session that
// already authenticated as root by key; the box never learns which human sat
// behind it. A laptop could send its local username, but that is a string the
// sender chose about itself -- unverified, and recorded as though it were
// established fact.
//
// What it must NOT be is anything about where the connection came from. This
// value is written into a report that is served over the network to the
// registry and rendered in an app, so an address or a hostname here is a piece
// of somebody's infrastructure travelling further than they asked it to. The
// box knows the route; the route is what it says.
const StoppedByCLI = "cli"

// StoppedByDevice is who stopped an app through a signed command.
//
// The VERIFIED key, which on this path is the one identity the box can assert
// rather than accept. VerifyCommand already returns which key matched, and says
// why in its own words: "a result should be able to say who asked and because
// revoking one device later means knowing that". A stop is exactly that kind of
// act -- somebody will one day want to know which device took an app down, and
// the answer has to survive the process that applied it.
//
// A fingerprint rather than the whole key, and Fingerprint's own reason
// applies: this is the form the app renders and the form a person compares by
// eye. It is public key material either way -- holding it grants nothing, and
// it is not sensitive in a report the same way an address would be.
func StoppedByDevice(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		// Not reachable from a verified command, which is the only caller: a
		// key that did not verify never gets here. Named rather than left to
		// produce an empty STOPPED_BY, because an empty value is omitempty in
		// the report and would show as a stop nobody made.
		return "device (unknown)"
	}
	return "device " + Fingerprint(FormatDeviceKey(pub))
}

// MarkStopped records a deliberate stop in the app's own record.
//
// at is passed in rather than read from the clock here so the caller decides
// the reading, which is the same seam Probe.Now is.
func MarkStopped(root, app, by string, at time.Time) error {
	path, err := appStatePath(root, app)
	if err != nil {
		return err
	}
	return setStateValues(path, map[string]string{
		stoppedKey:   "1",
		stoppedByKey: by,
		// UTC, because this is compared against a laptop in another zone and a
		// duration computed across two of them is wrong by hours in a way that
		// looks like a plausible answer. RFC3339 because probe.go parses
		// exactly that and a value it cannot parse is silently dropped.
		stoppedAtKey: at.UTC().Format(time.RFC3339),
	})
}

// ClearStopped takes the marker off, so the app can page again.
//
// Every key, not just STOPPED. Leaving STOPPED_BY and STOPPED_AT behind would
// leave a running app carrying the record of a stop that is over, and the next
// person to read that file would have no way to tell it from a live one.
func ClearStopped(root, app string) error {
	path, err := appStatePath(root, app)
	if err != nil {
		return err
	}
	return setStateValues(path, map[string]string{
		stoppedKey: "", stoppedByKey: "", stoppedAtKey: "",
	})
}

// setStateValues rewrites one app record, changing only the keys named.
//
// An empty value REMOVES the key rather than writing a blank one, because a
// blank is a value: `STOPPED=` is not the absence of a stop to a reader that
// checks for the key rather than for "1".
//
// Everything else in the file survives byte for byte -- the comment alpine.sh
// writes at the top, APP_DIR, CI_USER, CONFIG_IMAGE, KNOWN_AS, and anything a
// later version of the provisioning script adds. This function must never be
// the reason a field it has never heard of disappears, because the file it is
// editing is the only record of where an app lives and which account deploys
// it.
func setStateValues(path string, set map[string]string) error {
	for k, v := range set {
		// A NEWLINE IN A VALUE FORGES THE NEXT KEY. readState splits on lines
		// and takes the first occurrence of each key, so a `by` containing
		// "\nAPP_DIR=/srv/other" would repoint the app at another directory --
		// and APP_DIR is what resolveSubject hands to `docker compose
		// --project-directory`. The values this file writes today come from a
		// closed set, which is precisely the condition under which this check
		// looks unnecessary and later stops being true.
		if strings.ContainsAny(v, "\n\r") {
			return fmt.Errorf("%s cannot contain a newline", k)
		}
		// Bounded for the same reason. Nothing today is near this; a future op
		// carrying an operator-supplied label into a file root writes should
		// fail loudly here rather than grow the record without limit.
		if len(v) > maxStateValue {
			return fmt.Errorf("%s is longer than %d bytes", k, maxStateValue)
		}
	}

	b, err := os.ReadFile(path)
	if err != nil {
		// The record is missing, which means the app is not one this box knows
		// about. Refused rather than created: writing a state file here would
		// invent an app with no APP_DIR, and paths.go is explicit that a record
		// naming no directory is a box mid-removal or a file somebody edited.
		return err
	}

	var out []string
	for _, ln := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		k, _, ok := strings.Cut(ln, "=")
		if ok {
			if _, managed := set[k]; managed {
				// Dropped wherever it was, and re-appended below if it still
				// has a value. Every occurrence, not just the first: readState
				// takes the first and the deploy shell's `sed -n 's/^KEY=//p' |
				// head -n 1` does too, so a second copy left behind is a value
				// that becomes live the moment the first is removed.
				continue
			}
		}
		out = append(out, ln)
	}
	// Trailing blanks from the split, trimmed so a file edited twice does not
	// grow an empty line each time.
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	// Sorted, so what this writes is the same every time and a test can assert
	// the file rather than parse it.
	keys := make([]string, 0, len(set))
	for k := range set {
		if set[k] != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+set[k])
	}

	// 0640, which is what alpine.sh chmods this file to when it creates it.
	// Restated rather than preserved from the file on disk, so a record
	// somebody widened by hand is narrowed back by the next write instead of
	// having its mode faithfully carried forward. The directory is 0750
	// root:root, and the file names an app's deploy account and directory.
	return writeFileAtomic(path, []byte(strings.Join(out, "\n")+"\n"), 0o640)
}

// maxStateValue bounds one value. See setStateValues.
const maxStateValue = 128

// appStatePath is where one app's record lives, and the one place that decides.
//
// Shared with AppDir rather than duplicated, because this is the check that
// keeps a name out of a path: the name is joined into a filename, and two
// copies of that rule are two chances for one of them to relax.
func appStatePath(root, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/.") {
		// Refused rather than sanitised. A name with a separator in it is not a
		// typo to be helpful about.
		return "", fmt.Errorf("%q is not an app name", name)
	}
	return filepath.Join(root, AppsDir, name+".env"), nil
}
