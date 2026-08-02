// Command komizo-box is what runs on a server.
//
// One binary, several modes, run by DIFFERENT USERS -- which is the whole
// design and not a packaging convenience. See design/architecture.md.
//
//	rootd    root. Probes the machine and writes report.json on a timer.
//	report   one reading to stdout. What `komizo report` runs over SSH.
//	metrics  request counts over a range, to stdout.
//	history  past readings over a range, to stdout.
//
// Splitting the modes across separate binaries would make agent updates three
// questions instead of one; running them as one PROCESS would merge root with
// the account that is supposed to have nothing. So: one file on disk, two
// processes, two users.
//
// In v0 only the root half exists. There is no agent yet, because there is
// nothing for it to report to -- see design/appify.md §11.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nicodes/komizo/internal/box"
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
	case "metrics":
		err = runMetrics(os.Args[2:])
	case "history":
		err = runHistory(os.Args[2:])
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
  komizo-box report [--json]
  komizo-box metrics --from UNIX --to UNIX
  komizo-box history --from UNIX --to UNIX
  komizo-box version
`)
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
	reportPath := fs.String("report", box.ReportPath, "where to write the current report")
	historyPath := fs.String("history", box.HistoryPath, "where to append readings")
	volEvery := fs.Int("volumes-every", 15, "measure volumes every Nth reading (0 disables)")
	once := fs.Bool("once", false, "probe once and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Created up front, by root, so the permissions on komizo's state are
	// decided in one place rather than by whichever process happens to write
	// first.
	for _, d := range []string{box.StateDir, box.PendingDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			tick()
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

func runMetrics(args []string) error {
	fs := flag.NewFlagSet("metrics", flag.ContinueOnError)
	from := fs.Int64("from", 0, "start of the range, unix seconds")
	to := fs.Int64("to", 0, "end of the range, unix seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == 0 || *to == 0 {
		return fmt.Errorf("both --from and --to are required")
	}
	return emit(probe().Metrics(*from, *to))
}

func runHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	from := fs.Int64("from", 0, "start of the range, unix seconds")
	to := fs.Int64("to", 0, "end of the range, unix seconds")
	path := fs.String("history", box.HistoryPath, "where readings are kept")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == 0 || *to == 0 {
		return fmt.Errorf("both --from and --to are required")
	}
	s, err := box.ReadSamples(*path, *from, *to)
	if err != nil {
		return err
	}
	if s == nil {
		s = []box.Sample{}
	}
	return emit(s)
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
