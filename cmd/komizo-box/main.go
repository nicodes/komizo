// Command komizo-box is what komizo installs on a server.
//
//	rootd    a daemon, as ROOT. Probes the machine every minute and writes
//	         report.json.
//	agent    a daemon, as KOMIZO_MONITOR. Posts that file to the komizo service.
//	         No privileges: it reads one file and opens one socket.
//	enrol    as root. Exchanges a single-use token for the agent's credential.
//	unenrol  as root. Forgets it.
//
//	report   one reading to stdout. What `komizo report` asks for.
//	poll     a reading plus a window of request counts. The app list.
//	monitor  a range of counts, past readings, and one app's volumes. The charts.
//
// Every mode but rootd prints ONE JSON document and exits. A mode per SCREEN
// rather than per subject is deliberate: each read costs an SSH connection, and
// the connection -- not the probing -- is the expensive part, so a screen that
// needs three things asks once.
//
// rootd and agent are the pair the whole design rests on. Root probes the
// machine and leaves a world-readable file; the agent reads that file and posts
// it, holding no privileges and no way to make root do anything. Nothing dials
// in to ask either of them for anything -- design/appify.md §3.
//
// They must stay separate PROCESSES under separate users. Merging them merges
// the privilege, and the privilege is the whole point: compromise the thing
// that talks to the internet and you get a document that already says nothing
// secret.
//
// The read-only modes run as whoever opened the connection, which is the
// operator over their own root key.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nicodes/komizo/box"
)

// version is stamped at build time by the release, and reported so the
// interface can say a box is running an old agent.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "rootd":
		err = runRootd(os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
	case "poll":
		err = runPoll(os.Args[2:])
	case "monitor":
		err = runMonitor(os.Args[2:])
	case "agent":
		err = runAgent(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "app":
		err = runApp(os.Args[2:])
	case "enrol":
		err = runEnrol(os.Args[2:])
	case "unenrol":
		err = runUnenrol(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "komizo-box: unknown mode %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "komizo-box: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `komizo-box -- the komizo agent, on the server

  komizo-box rootd [--interval 60s] [--report PATH]
  komizo-box report [--cached] [--volumes]
  komizo-box poll --from UNIX --to UNIX
  komizo-box serve [--socket PATH]
  komizo-box monitor --from UNIX --to UNIX [--app NAME]

  komizo-box app start|stop|restart --app NAME      as root
  komizo-box app logs --app NAME [--tail N] [--service S]

  komizo-box enrol --api URL --token kmz_enr_...    as root
  komizo-box agent                                  as komizo_monitor
  komizo-box unenrol                                as root

  komizo-box version
`)
}

// signalContext cancels on interrupt or SIGTERM, which is how OpenRC stops a
// supervised service. Every long-running mode uses it, so `rc-service stop`
// means a clean exit rather than a kill.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// probe is the machine, with the version this binary was built as.
func probe() *box.Probe {
	return &box.Probe{Now: box.Now, Agent: version}
}

// runRootd is the timer. Root runs this; nothing else does.
//
// It PULLS on its own schedule rather than being invoked. That is the property
// design/appify.md §3 is built around: an unprivileged agent reading a file
// cannot make root code run, whenever and as often as it likes, the way a doas
// rule would let it.
func runRootd(args []string) error {
	fs := flag.NewFlagSet("rootd", flag.ContinueOnError)
	interval := fs.Duration("interval", time.Minute, "how often to probe")
	confPath := fs.String("config", box.AgentConfPath, "the credential whose keys commands are verified against")
	inboxDir := fs.String("inbox", box.InboxDir, "where signed commands arrive")
	resultsDir := fs.String("results", box.ResultsDir, "where their outcomes are written")
	logsDir := fs.String("logs", box.LogsDir, "where each app's recent output is kept")
	reportPath := fs.String("report", box.ReportPath, "where to write the current report")
	historyPath := fs.String("history", box.HistoryPath, "where to append readings")
	metricsPath := fs.String("metrics", box.MetricsPath, "where to leave what the access log said")
	volEvery := fs.Int("volumes-every", 15, "measure volumes every Nth reading (0 disables)")
	once := fs.Bool("once", false, "probe once and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Only what this is about to write, and derived from the flags rather than
	// from the constants -- otherwise pointing --report somewhere else still
	// demands /var/lib/komizo, which makes the daemon impossible to run as
	// anyone but root even when it is writing to a temp directory.
	//
	// The two modes differ and both are load-bearing. The report's directory is
	// TRAVERSABLE, because an account with no privileges has to reach the file
	// in it -- that is the whole boundary komizo is built on. The history's is
	// not, because nothing unprivileged needs it.
	//
	// Recreated here as well as by the installer because the report lives on
	// tmpfs: after a reboot the directory is simply gone, and rootd starting at
	// boot is the first thing that could notice.
	//
	// Laying out the REST of the box, PendingDir included, is the installer's
	// job. A daemon that also provisions is a daemon with a reason to need
	// privileges it otherwise would not.
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Dir(*reportPath), 0o755},
	} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		// Explicitly, because MkdirAll leaves an existing directory alone and
		// because umask would otherwise decide the answer.
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
	}
	// The history's directory is NOT one of those. It is 0750 root:agent and
	// setgid, so that the readings root appends here are readable by the account
	// that serves them -- see PrepareServedDir. Made with the generic mode
	// above, it was root:root, and every GET /v1/history answered with nothing.
	// The PARENT first. ServedDir is inside the state directory, which is closed
	// so that apps/<app>.env stays closed -- and a directory whose parent cannot
	// be entered is one nothing can reach, whatever its own mode says.
	if err := box.PrepareStateDir(box.StateDir); err != nil {
		return err
	}
	if err := box.PrepareServedDir(filepath.Dir(*historyPath)); err != nil {
		return err
	}
	// AND THE METRICS' DIRECTORY, which is the history's by default and need
	// not be. Review 1 on komizo#83: only the history's was prepared, so
	// pointing --metrics at another directory wrote into one that may not
	// exist, with the mode this daemon is careful about everywhere else.
	if d := filepath.Dir(*metricsPath); d != filepath.Dir(*historyPath) {
		if err := box.PrepareServedDir(d); err != nil {
			return err
		}
	}
	// The read API's socket directory: owned by the account that binds the
	// socket, grouped to the one the proxy runs as. See PrepareAPISocketDir --
	// the proxy has no CAP_DAC_OVERRIDE, so this is not the formality it looks
	// like.
	if err := box.PrepareAPISocketDir(box.APISocketDir); err != nil {
		return err
	}
	// Where a signed command lands. Made by root, owned by the account that
	// will write into it -- see box/inbox.go. On tmpfs, so it is gone after a
	// reboot and remade here, which is correct: a command carries an expiry in
	// minutes and one that survived a restart would be a machine acting on
	// something somebody asked for before it went down.
	if err := box.PrepareInboxDir(*inboxDir); err != nil {
		return err
	}
	if err := box.PrepareResultsDir(*resultsDir); err != nil {
		return err
	}
	// The same for logs. Created lazily it lands in a usable group only because
	// Linux propagates setgid from ServedDir -- and PrepareServedDir runs every
	// start precisely because an upgrade or a restored backup can leave that
	// without one. A logs directory made in that window is 0750 root:root
	// forever, and every request answers "nothing collected yet".
	if err := box.PrepareServedDir(*logsDir); err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()

	n := 0
	tick := func() {
		// Volumes cost a walk of the whole tree rather than a file read, so they
		// ride a slower cadence. Keyed off the reading COUNT and taken on the
		// first one, because a box set up at 11:07 that waited for a quarter
		// hour would have no storage chart at all until 11:15 -- and would need
		// a second at 11:30 before there were two points to draw a line between.
		// Missing for the first half hour after installing the thing that draws
		// it reads as broken rather than as new.
		wantVols := *volEvery > 0 && n%*volEvery == 0
		n++

		r := probe().Report(ctx)
		if wantVols && r.Server.Ready() {
			r.System.Volumes = probe().Volumes(ctx, "")
		}
		if err := box.WriteReport(*reportPath, r); err != nil {
			fmt.Fprintf(os.Stderr, "komizo-box: writing report: %v\n", err)
		}
		s := box.Sample{At: r.At, System: r.System}
		if err := box.AppendSample(*historyPath, s, box.HistoryMax, box.HistoryKeep); err != nil {
			fmt.Fprintf(os.Stderr, "komizo-box: appending history: %v\n", err)
		}
		// WHERE THE SERVING ACCOUNT CAN READ IT. The access log is the proxy's,
		// 0750 root:root, and the API runs as komizo_monitor -- so the count
		// happens here, where root already is, and the answer is left beside
		// the report and the history. komizo#80.
		to := r.At.Unix()
		if err := box.WriteMetrics(*metricsPath, probe().Metrics(to-box.MetricsWindow, to)); err != nil {
			fmt.Fprintf(os.Stderr, "komizo-box: writing metrics: %v\n", err)
		}
	}

	// Immediately, then on the interval. Waiting a full interval before the
	// first write means a freshly installed box has no report at all for a
	// minute, and the thing that just installed it cannot verify it works.
	tick()
	if *once {
		return nil
	}
	t := time.NewTicker(*interval)
	defer t.Stop()

	// Commands run on their OWN GOROUTINE, not in this loop.
	//
	// Two reasons, and the second is the one that bites. A command is somebody
	// waiting for a button, so it wants a much shorter timer than a measurement
	// on a schedule. And applying one runs `docker compose`, which can take
	// minutes -- inside this select that would stall the report, and a box that
	// stops reporting is indistinguishable from a box that is down. The
	// half-second timer's justification is that a stat on tmpfs costs nothing;
	// that is true of the poll and not of the work it dispatches.
	go commandLoop(ctx, *confPath, *inboxDir, *resultsDir)

	// Logs on their own timer too, and for the opposite reason to commands:
	// this runs a docker command per app, where the command loop stats a
	// directory. Off this goroutine so a slow compose does not stall the
	// report, which is the same argument commands made.
	go func() {
		t := time.NewTicker(collectEvery)
		defer t.Stop()
		collectLogs(ctx, "", *logsDir)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				collectLogs(ctx, "", *logsDir)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			tick()
		}
	}
}

// commandLoop applies what arrives, and sweeps what nobody collected.
//
// The credential is re-read each pass rather than held: `komizo enrol` rewrites
// it while this is running, and a rootd holding the keys it started with would
// keep obeying a device that had just been removed.
//
// The inbox is swept even when the box takes orders from nobody, because it is
// on tmpfs and an account that can create files there should not be able to
// fill memory by doing so.
func commandLoop(ctx context.Context, confPath, inboxDir, resultsDir string) {
	cmds := time.NewTicker(applyEvery)
	defer cmds.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cmds.C:
			conf, err := box.ReadAgentConf(confPath)
			if err != nil {
				continue
			}
			applyPending(ctx, conf, inboxDir, resultsDir)
		case <-prune.C:
			_ = box.PruneResults(resultsDir, time.Now())
		}
	}
}

// runReport prints one reading, measured now.
//
// Measured rather than read from report.json, so it works on a box where rootd
// is not installed -- which is every box, until init puts it there, and is what
// makes this useful before any of the rest of it exists.
func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	volumes := fs.Bool("volumes", false, "measure volume sizes too (slow: walks every volume)")
	cached := fs.Bool("cached", false, "print the last report rootd wrote instead of measuring")
	path := fs.String("report", box.ReportPath, "where the cached report lives")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cached {
		r, err := box.ReadReport(*path)
		if err != nil {
			return err
		}
		return emit(r)
	}
	ctx := context.Background()
	r := probe().Report(ctx)
	if *volumes && r.Server.Ready() {
		r.System.Volumes = probe().Volumes(ctx, "")
	}
	return emit(r)
}

// runPoll is the app list's redraw: the inventory, plus a window of request
// counts for the sparkline on each row.
//
// One command rather than two because every read costs an SSH connection, and
// that -- not the probing -- is what makes polling expensive.
func runPoll(args []string) error {
	fs := flag.NewFlagSet("poll", flag.ContinueOnError)
	from := fs.Int64("from", 0, "start of the sparkline window, unix seconds")
	to := fs.Int64("to", 0, "end of the sparkline window, unix seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := probe()
	out := box.Poll{V: box.Version, Report: p.Report(context.Background())}
	if *from != 0 && *to != 0 {
		out.Metrics = p.Metrics(*from, *to)
	}
	return emit(out)
}

// runMonitor is the charts: a range of request counts and past readings, and
// one app's volume sizes when asked for.
func runMonitor(args []string) error {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	from := fs.Int64("from", 0, "start of the range, unix seconds")
	to := fs.Int64("to", 0, "end of the range, unix seconds")
	app := fs.String("app", "", "also measure this app's volumes (slow)")
	path := fs.String("history", box.HistoryPath, "where readings are kept")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == 0 || *to == 0 {
		return fmt.Errorf("both --from and --to are required")
	}
	p := probe()
	out := box.Monitor{V: box.Version, Metrics: p.Metrics(*from, *to), History: []box.Sample{}}
	if h, err := box.ReadSamples(*path, *from, *to); err == nil && h != nil {
		out.History = h
	}
	if *app != "" {
		out.Volumes = p.Volumes(context.Background(), *app)
	}
	return emit(out)
}

// emit writes one JSON document to stdout.
//
// Compact, on one line, because the reader of this is a program over an SSH
// pipe rather than a person. `komizo report` on the laptop is what formats it
// for reading.
func emit(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(b, '\n'))
	return err
}
