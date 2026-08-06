package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
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
		over := kept >= maxInbox
		if !e.IsDir() && (stale || over) {
			// DROPPED, and told so. Readdir order is roughly hash order on
			// tmpfs rather than arrival order, so capacity removes arbitrary
			// valid, signed, unapplied commands -- and without a result the app
			// polls a 404 forever for something nothing ever refused out loud.
			// An id that cannot be filed gets nothing, which is the same answer
			// it gets everywhere else.
			//
			// STALE COUNTS TOO, which it did not. This loop is serial and
			// provisionTimeout is fifteen minutes, against a command that stops
			// being valid after six -- so a stop pressed while an app.add was
			// running was deleted in silence, and the screen waited out its own
			// deadline for an answer that had already been thrown away. The
			// command really did expire; what was missing was saying so.
			why := "this box had too many commands waiting"
			if stale {
				why = "this box did not get to this command before it expired"
			}
			if id := e.Name(); box.ValidCommandID(id) == nil && !box.Applied(results, id) {
				_ = box.WriteResult(results, box.Result{ID: id, At: now.UTC(), OK: false,
					Detail: why})
			}
		}
		if e.IsDir() || stale || over {
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
		// DOTFILES ARE NOT COMMANDS. The route writes to `.tmp-*` and renames,
		// which is only atomic if nothing reads the temporary -- and this loop
		// filtered on IsDir alone, so root read files mid-write. Both outcomes
		// were the "silently might have" §4 exists to prevent: a complete but
		// unrenamed temp was APPLIED and then removed, so the rename failed and
		// the caller was told 503 for a command that had run; a partial one was
		// removed, so the caller was told 503 for a command that was discarded.
		//
		// The installer's own .probe file was being handed to root as a command
		// for the same reason.
		//
		// The sweep above still removes a stale temporary, which is the right
		// fallback for a route that died between writing and renaming.
		if e.IsDir() || box.IsTemporary(e.Name()) {
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

	// The signer is kept, not discarded. It is the only identity on this path
	// the box established rather than accepted, and a deliberate stop records
	// which device made it -- see box.StoppedByDevice. VerifyCommand returns it
	// for exactly this: "a result should be able to say who asked".
	c, signer, err := box.VerifyCommand(keys, raw, serverID, time.Now())
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

	err = perform(ctx, c, box.StoppedByDevice(signer))
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
// by is who this is on behalf of, already rendered by the caller. Passed in
// rather than derived here because this function is handed a COMMAND, and the
// command is the half a caller signs -- the identity is the half the box
// established by verifying it, and the two must not be read out of the same
// place.
func perform(ctx context.Context, c box.Command, by string) error {
	// app.add is not a compose verb. It runs the same provisioning script
	// `komizo add` runs -- app-only.md §8's condition that both triggers end in
	// one implementation -- and it is the only op that creates an account.
	if c.Op == box.OpAppAdd {
		return performAdd(ctx, c)
	}
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
	return runVerb(ctx, verb, sub, 0, "", by)
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

// performAdd sets an app up, from a command a device this box trusts signed.
//
// The SAME SCRIPT `komizo add` pipes over SSH, with the same environment. That
// is app-only.md §8's condition stated as code: two triggers, one
// implementation, so there is never a second opinion about what adding an app
// means.
//
// The deploy key arrives already made. `komizo add` generates a keypair on the
// operator's machine and prints the private half; a command carries only the
// public half, because a result file lives where the account that talks to the
// internet can read it. So nothing here generates, holds or returns a private
// key — see box/command.go's OpAppAdd.
func performAdd(ctx context.Context, c box.Command) error {
	spec, err := c.AddOf()
	if err != nil {
		return err
	}
	env := map[string]string{
		"APP_NAME":     spec.App,
		"CI_PUBKEY":    spec.PubKey,
		"CI_USER":      spec.User,
		"CONFIG_IMAGE": spec.Config,
		"KNOWN_AS":     strings.Join(spec.KnownAs, ","),
		"HARDEN_SSH":   boolArg(spec.HardenSSH),
	}
	if spec.AppDir != "" {
		env["APP_DIR"] = spec.AppDir
	}
	return runProvision(ctx, scripts.AlpineScript, env)
}

func boolArg(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// runProvision runs a komizo script here, as root, with its values in the
// ENVIRONMENT rather than on a command line.
//
// A command line is visible in this box's process table to every account on it
// for as long as it runs, which is the argument the CLI already makes about
// piping these over stdin instead of as arguments. The values here include a
// public key and an image reference — not secrets — but the rule is the rule,
// and the next op to use this may carry something that is.
func runProvision(ctx context.Context, script string, env map[string]string) error {
	ctx, cancel := context.WithTimeout(ctx, provisionTimeout)
	defer cancel()

	cmd := execProvision(ctx, "/bin/sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), envPairs(env)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// The script's own last words, which is what says WHY rather than that
		// something failed. Bounded: this ends up in a result the app reads.
		said := lastLines(string(out), 12)
		if strings.TrimSpace(said) == "" {
			// IT SAID NOTHING. `err` was being discarded, so a script killed by
			// a signal or one that died before printing produced Detail: "" --
			// which is omitempty, so the app was shown ok:false with no reason
			// at all. That is the one state §4 says a result exists to prevent.
			return fmt.Errorf("the setup script failed without saying why: %w", err)
		}
		// AND the error, when what came back is only progress. A timeout kill
		// leaves "==> Preparing /srv/web" as the last thing written, which read
		// on its own is an ordinary step presented as the failure.
		return fmt.Errorf("%s\n(%w)", said, err)
	}
	return nil
}

// provisionTimeout bounds it. Generous, because adding an app pulls a config
// image on a box that may be on a slow link; bounded at all, because this is
// reached from a route on the internet.
const provisionTimeout = 15 * time.Minute

// execProvision is a seam, so what this would run can be asserted.
var execProvision = exec.CommandContext

func envPairs(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for _, k := range slices.Sorted(maps.Keys(env)) {
		out = append(out, k+"="+env[k])
	}
	return out
}

// lastLines keeps the end of a script's output, which is where the reason is.
// lastLines is the tail of what something said, bounded in LINES AND BYTES.
//
// Both, because a line is not a bounded quantity: a script that emits a
// megabyte without a newline -- a progress bar, a base64 blob, a compiler --
// produced one "line" that went whole into a result file the app then reads.
//
// THE BYTE BOUND IS box.DetailMax, not a second number here. komizo#68 moved
// the enforcement to WriteResult so a producer that forgets is corrected rather
// than trusted; this one still trims because choosing WHICH lines survive is a
// judgement the writer cannot make. Two numbers for one limit is how they drift.
const detailMax = box.DetailMax

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.Join(lines, "\n")
	if len(out) > detailMax {
		// From the FRONT, so the end -- which is where a script says why it
		// stopped -- is the part that survives.
		out = "…" + out[len(out)-detailMax:]
	}
	return out
}
