package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/nicodes/komizo/box"
)

// rootd, doing what it has been told -- and only what it can verify.
//
// komizo-be design/app-only.md §4. The account that serves the box drops a
// signed blob in the inbox; it cannot forge one, because it holds no key. This
// is the half that reads them, and the ORDER inside it is the whole of the
// safety argument:
//
//	1. the signature, against keys an operator planted with root
//	2. the audience, the expiry, the version, the op
//	3. the replay record
//	4. only then, anything that touches the machine
//
// A POLL, NOT A WATCH, and this is a correction to §4 as written. The document
// chose inotify and accepted architecture.md §9's price -- that a watch "lets
// the unprivileged process wake root at will" where a timer does not. That
// trade bought nothing: the latency being avoided was the AGENT's sixty-second
// tick, not the difference between a watch and a short timer. Half a second is
// indistinguishable to somebody who pressed a button, and it keeps root
// un-wakeable by the account that talks to the internet.
//
// It also keeps rootd free of a dependency. There is no inotify in the standard
// library, so a watch means a third-party package inside the one process that
// runs as root on other people's machines -- and appify.md §9 asks that this be
// "small, read-only, and updatable, and it is yours forever".

// applyEvery is how often rootd looks.
//
// Half a second: a stat of a directory on tmpfs, which costs nothing, against a
// product where "press stop, watch nothing happen" is a verdict rather than a
// latency figure.
const applyEvery = 500 * time.Millisecond

// maxPending bounds how much work one pass will do.
//
// The inbox is reachable, through the serving account, from a route on the
// internet. Without this a burst is a burst of public-key operations at root,
// and the ones past the bound are simply left for the next pass rather than
// dropped -- there is no interesting difference to a caller between "applied in
// half a second" and "applied in one".
const maxPending = 32

// applyPending reads the inbox once.
//
// Errors are logged rather than returned: one unreadable command is not a
// reason to stop applying the others, and rootd's job is to keep running.
func applyPending(ctx context.Context, conf box.AgentConf, dir, results string) {
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) == 0 {
		return
	}
	// Oldest first, so a burst is applied in the order it arrived. Names are
	// random ids and carry no order of their own, so this reads mtimes.
	type pending struct {
		name string
		at   time.Time
	}
	var list []pending
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		list = append(list, pending{name: e.Name(), at: info.ModTime()})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
	if len(list) > maxPending {
		list = list[:maxPending]
	}

	keys, err := conf.TrustedKeys()
	if err != nil {
		// A credential carrying a key somebody meant to work. Said once per
		// pass rather than silently refusing everything, because the symptom
		// otherwise is an app whose buttons do nothing.
		fmt.Fprintf(os.Stderr, "komizo-box: %v\n", err)
		return
	}
	for _, p := range list {
		applyOne(ctx, keys, conf.ServerID, filepath.Join(dir, p.name), results)
	}
}

// applyOne verifies one file and does what it says.
//
// The file is REMOVED whatever happens, first and always. A command that cannot
// be verified must not be retried -- retrying it is a way to make an
// unauthorised caller cost root a public-key operation every half second
// forever -- and a command that was applied must not be applied twice.
func applyOne(ctx context.Context, keys []ed25519.PublicKey, serverID, path, results string) {
	raw, err := readBounded(path, box.MaxCommandBytes)
	_ = os.Remove(path)
	if err != nil {
		return
	}

	c, _, err := box.VerifyCommand(keys, raw, serverID, time.Now())
	if err != nil {
		// Logged locally, where the operator is, and never answered to the
		// caller -- the route that accepted this has already replied. This is
		// the one place the reason for a refusal is written down.
		fmt.Fprintf(os.Stderr, "komizo-box: refusing a command: %v\n", err)
		return
	}
	// The replay check, after the signature so that an unsigned id cannot be
	// used to ask what this box has already done.
	if box.Applied(results, c.ID) {
		return
	}

	err = perform(ctx, c)
	res := box.Result{ID: c.ID, Op: c.Op, At: time.Now().UTC(), OK: err == nil}
	if err != nil {
		res.Detail = err.Error()
	}
	if werr := box.WriteResult(results, res); werr != nil {
		fmt.Fprintf(os.Stderr, "komizo-box: could not record the result of %s: %v\n", c.ID, werr)
	}
}

// perform maps a verified command onto the same path the CLI takes.
//
// The op is a NAME and this is where it becomes arguments -- built here, from a
// closed set, never carried in the envelope. app-only.md §4: a signed command
// containing a command line is remote code execution by design, with the
// signature as the thing that authorised it.
func perform(ctx context.Context, c box.Command) error {
	verb, ok := opVerbs[c.Op]
	if !ok {
		// VerifyCommand refuses an unknown op already; this is the second half
		// of the same closed set, so adding one to either without the other is
		// a refusal rather than a silent success.
		return fmt.Errorf("this box does not know how to %q", c.Op)
	}
	name, err := c.AppOf()
	if err != nil {
		return err
	}
	sub, err := resolveSubject(lookupRoot, name, false)
	if err != nil {
		return err
	}
	return runVerb(ctx, verb, sub, 0, "")
}

// lookupRoot prefixes the app lookup. Empty in production; a fixture in tests,
// which is the same seam Probe.Root is and the reason this path is testable
// without a machine that has apps on it.
var lookupRoot = ""

// opVerbs is the closed set, as the box's own verbs.
var opVerbs = map[string]string{
	box.OpAppStart:   "start",
	box.OpAppStop:    "stop",
	box.OpAppRestart: "restart",
}

// readBounded reads a file and refuses one larger than max.
//
// Bounded before it is read rather than after: this is a file an internet-facing
// process created, and an unbounded read is an unbounded allocation at root.
func readBounded(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, fmt.Errorf("that command is larger than %d bytes", max)
	}
	return b, nil
}
