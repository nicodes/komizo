package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
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

// maxInbox bounds how much may WAIT.
//
// maxPending bounds one pass; without this the directory itself grows without
// limit and every pass re-lists all of it. On tmpfs that is RAM, filled by an
// account that only has to be able to create files.
const maxInbox = 256

// commandSweepGrace is how long past its last possible validity a command is
// left before it is swept, so a clock difference does not delete something that
// was about to be applied.
const commandSweepGrace = time.Minute

// applyPending reads the inbox once.
//
// Errors are logged rather than returned: one unreadable command is not a
// reason to stop applying the others, and rootd's job is to keep running.
func applyPending(ctx context.Context, conf box.AgentConf, dir, results string) {
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) == 0 {
		return
	}
	// SWEPT FIRST, and whatever the credential says. A box with no operator keys
	// -- which is every box today -- used to return here without removing
	// anything, so its inbox filled and stayed full. That directory is on tmpfs,
	// which is RAM. Anything past the age a command could still be valid at is
	// removed, and so is anything that is not a file, because a directory left
	// in here is re-listed every half second forever.
	now := time.Now()
	kept := 0
	for _, e := range ents {
		info, ierr := e.Info()
		stale := ierr != nil || now.Sub(info.ModTime()) > box.MaxCommandTTL+commandSweepGrace
		if e.IsDir() || stale || kept >= maxInbox {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
			continue
		}
		kept++
	}
	// Oldest first, so a burst is applied in the order it arrived. Names are
	// random ids and carry no order of their own, so this reads mtimes.
	type pending struct {
		name string
		at   time.Time
	}
	// Re-listed after the sweep, so nothing removed above is acted on.
	ents, err = os.ReadDir(dir)
	if err != nil {
		return
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

	if !conf.CanCommand() {
		// Swept above; nothing here takes orders. Every box is in this state
		// until an operator plants a device key with root.
		return
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
		// Logged locally, where the operator is. A REFUSAL is never answered:
		// whoever sent it is not a device this box trusts, and the route that
		// accepted the blob has already replied.
		fmt.Fprintf(os.Stderr, "komizo-box: refusing a command: %v\n", err)

		// But a version this box does not speak, or an op it does not know, is
		// not a refusal -- it is a signed command from a device this box trusts,
		// asking for something it cannot do. app-only.md §4 promises those "fail
		// with a sentence instead of a silence", and a sentence nobody can read
		// is a silence: the app polls the result and waits forever. So they get
		// one. VerifyCommand returns the command for exactly these two.
		if !errors.Is(err, box.ErrCommandRefused) && c.ID != "" {
			_ = box.WriteResult(results, box.Result{ID: c.ID, Op: c.Op,
				At: time.Now().UTC(), OK: false, Detail: err.Error()})
		}
		return
	}
	// The replay check, after the signature so that an unsigned id cannot be
	// used to ask what this box has already done.
	if box.Applied(results, c.ID) {
		return
	}

	// CLAIMED BEFORE IT IS DONE. The record used to be written afterwards, so a
	// results directory that could not be written to meant the command ran and
	// left no trace -- and then ran again on the next arrival, and the next.
	// Replay protection degraded to nothing, silently, in exactly the case
	// somebody would least notice.
	//
	// A failed claim means NOT ACTING. Doing the work anyway is the behaviour
	// this is here to prevent.
	claim := box.Result{ID: c.ID, Op: c.Op, At: time.Now().UTC(), OK: false, Detail: applyingDetail}
	if werr := box.WriteResult(results, claim); werr != nil {
		fmt.Fprintf(os.Stderr, "komizo-box: could not claim %s, so it was not applied: %v\n", c.ID, werr)
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

// applyingDetail marks a claim that has not finished.
//
// Visible to the app on purpose: "started, no outcome yet" is a real state and
// the alternative is a spinner that cannot tell it from "never arrived". A
// claim that stays this way is a command whose rootd died mid-apply, which is
// worth being able to see.
const applyingDetail = "applying"

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

// readBounded reads a regular file and refuses one larger than max.
//
// EVERY WORD OF THAT IS LOAD-BEARING, because the inbox is owned by the account
// that talks to the internet and this runs as root.
//
// O_NONBLOCK: a plain Open on a FIFO blocks in the kernel until somebody writes,
// and this is called from rootd's loop -- so one `mkfifo` in the inbox stopped
// commands AND the report, forever. A box that stops reporting is
// indistinguishable from a box that is down, which is the failure
// supervise-daemon was chosen to avoid.
//
// O_NOFOLLOW: otherwise the agent points a symlink at any file on the box and
// has root read it. Nothing downstream prints those bytes today, which makes
// this a primitive rather than a disclosure -- and a primitive that only stays
// harmless while nobody adds a log line.
//
// And then it must be a REGULAR file: a device node opened non-blocking is not
// a command, and a directory is not either.
//
// Bounded before it is read rather than after, because an unbounded read at
// root is an unbounded allocation.
func readBounded(path string, max int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, fmt.Errorf("that command is larger than %d bytes", max)
	}
	return b, nil
}
