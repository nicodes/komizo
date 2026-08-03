package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/nicodes/komizo/box"
)

// The agent: the process that talks to the internet, and the one with no
// privileges at all.
//
// It reads a file root wrote and posts it. That is the whole of it, and the
// smallness is the design -- design/appify.md §3. It cannot probe the machine,
// cannot run anything, cannot read the state directory, and cannot replace its
// own credential. Compromise it and you get the report, which is a document
// that already says nothing secret.
//
// It does NOT queue. A post that fails is dropped and the next one goes; a gap
// in the service's history is therefore a real gap, and the box still holds
// every reading in history.jsonl. See design/enrolment.md §6 -- backfill needs
// the agent to know what the service already has, which is a synchronisation
// protocol for a feature whose value is "the chart looks nicer after an
// outage".

// How the agent paces itself.
const (
	// watchEvery is how often it looks at report.json. rootd rewrites the file
	// every interval whether or not anything changed, so this is a cheap stat
	// and the file's modification time is the trigger.
	//
	// Deliberately shorter than rootd's interval: the agent should notice a new
	// report promptly, not add most of a minute to how stale the service's copy
	// is.
	watchEvery = 5 * time.Second

	// backoffMin and backoffMax bound the retry after a failed post.
	//
	// Doubling from five seconds to five minutes. The ceiling matters more than
	// the floor: an unreachable service must not have every box it has ever
	// enrolled hammering it, and five minutes of staleness is legible on a
	// dashboard as "not reporting since".
	backoffMin = 5 * time.Second
	backoffMax = 5 * time.Minute

	// postTimeout bounds one attempt, so a service that accepts a connection
	// and then never answers costs one interval rather than the process.
	postTimeout = 30 * time.Second
)

// errRevoked is a credential the service refused.
//
// Distinct because it is the one failure that must NOT be retried: a rejected
// credential is not transient, and an agent that retries one turns a removed
// server into a machine quietly hammering an endpoint forever.
var errRevoked = errors.New("this server's credential was refused")

func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	confPath := fs.String("config", box.AgentConfPath, "where enrolment left the credential")
	reportPath := fs.String("report", box.ReportPath, "the report to post")
	watch := fs.Duration("watch", watchEvery, "how often to look for a new report")
	once := fs.Bool("once", false, "post the current report and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil)).With("agent", version)

	conf, err := box.ReadAgentConf(*confPath)
	if err != nil {
		return err
	}
	// Not enrolled is not an error, and not something to retry. komizo works
	// entirely without the service; this box has simply not been pointed at
	// one. Said once, then out -- an OpenRC service that exits cleanly is
	// legible, and one that loops forever logging "not enrolled" is noise.
	if !conf.Enrolled() {
		log.Info("not enrolled -- nothing to report to", "config", *confPath)
		return nil
	}
	log = log.With("server", conf.ServerID, "api", conf.API)

	ctx, stop := signalContext()
	defer stop()

	client := &http.Client{Timeout: postTimeout}
	if *once {
		return postReport(ctx, client, conf, *reportPath)
	}
	return agentLoop(ctx, log, client, conf, *reportPath, *watch)
}

// agentLoop is the agent, minus reading its own configuration.
//
// Separate so it can be driven by a test with its own context and a short
// interval, rather than by signalling the process it is running in -- which is
// what an earlier version of that test did, and which would have taken the
// whole test binary down with it.
func agentLoop(ctx context.Context, log *slog.Logger, client *http.Client,
	conf box.AgentConf, reportPath string, watch time.Duration) error {

	var lastSent time.Time
	backoff := backoffMin
	t := time.NewTicker(watch)
	defer t.Stop()
	for {
		fi, err := os.Stat(reportPath)
		switch {
		case err != nil:
			// rootd has not written one yet, or is not running. Its absence is
			// rootd's problem to report and shows up as a stale last_seen; the
			// agent has nothing to say about it.
		case !fi.ModTime().After(lastSent):
			// Nothing new. The service already has this one.
		default:
			err := postReport(ctx, client, conf, reportPath)
			switch {
			case err == nil:
				lastSent = fi.ModTime()
				backoff = backoffMin
			case errors.Is(err, errRevoked):
				log.Error("stopping: this server is no longer enrolled. " +
					"Re-enrol with `komizo enrol`, or remove the agent.")
				return nil
			case ctx.Err() != nil:
				return nil
			default:
				log.Warn("could not report", "err", err, "retry_in", backoff)
				if !sleepCtx(ctx, backoff) {
					return nil
				}
				if backoff *= 2; backoff > backoffMax {
					backoff = backoffMax
				}
				continue
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// postReport sends one report.
//
// The file is read and posted verbatim rather than decoded and re-encoded. It
// is root's document, and the agent is a courier: re-serialising it would let a
// bug here change what a server said about itself, which is the one thing this
// process must not be able to do.
func postReport(ctx context.Context, c *http.Client, conf box.AgentConf, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, conf.ReportURL(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+conf.Token)
	req.Header.Set("User-Agent", "komizo-box/"+version)

	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	// Drained so the connection can be reused. A per-minute POST that opens a
	// fresh TCP and TLS handshake every time is a lot of ceremony for thirty
	// kilobytes.
	msg, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))

	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return errRevoked
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return nil
	default:
		return fmt.Errorf("%s: %s", res.Status, firstLine(msg))
	}
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	if len(b) > 200 {
		b = b[:200]
	}
	return string(bytes.TrimSpace(b))
}

// sleepCtx waits, and reports false if the wait was cut short by shutdown.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
