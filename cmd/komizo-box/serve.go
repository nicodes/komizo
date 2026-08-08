package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nicodes/komizo/box"
)

// The box answering for itself, over a socket.
//
// komizo-be design/registry.md: a server's data lives on the server. This is
// the process that hands it out -- box.Handler with something underneath it.
//
// A UNIX SOCKET, not a port. The box's Caddy already owns :443 and reaches this
// through a bind mount, so nothing new listens on the network: a machine that
// was not accepting connections for komizo before this still is not. A TCP
// listener on localhost would have been simpler and would have put a port on
// the box that anything else on it could reach.
//
// It runs as komizo_monitor, the account with no shell, no docker group, no
// doas and no read access to the state directory. Compromise it and you get
// what a reader was going to be given anyway -- appify.md §3 is the same
// argument, and this process is the second thing to sit on that side of it.

const (
	// shutdownGrace bounds how long an in-flight read may finish in. These are
	// file reads; a request that has not completed in this long is stuck.
	shutdownGrace = 5 * time.Second

	// socketMode: owner and group only. The group is komizo_monitor's own, and
	// the proxy container connects as root, which is not subject to it. Nothing
	// else on the box has any business opening this.
	socketMode = 0o660
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	sock := fs.String("socket", box.APISocketPath, "unix socket to listen on")
	confPath := fs.String("config", box.AgentConfPath, "the credential to read")
	reportPath := fs.String("report", box.ReportPath, "the report to serve")
	historyPath := fs.String("history", box.HistoryPath, "the history to serve")
	metricsPath := fs.String("metrics", box.MetricsPath, "the measured traffic to serve")
	inboxDir := fs.String("inbox", box.InboxDir, "where to leave a signed command for rootd")
	resultsDir := fs.String("results", box.ResultsDir, "where rootd leaves what happened")
	logsDir := fs.String("logs", box.LogsDir, "where rootd leaves each app's recent output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	conf, err := box.ReadAgentConf(*confPath)
	if err != nil {
		return err
	}
	// Nothing to verify against means every request would be refused, so this
	// says why and exits rather than holding a socket open that can only ever
	// answer 401. Same shape as the agent on an unenrolled box: not an error,
	// a state.
	if !conf.CanServe() {
		fmt.Fprintln(os.Stderr, "this box has no registry key, so it serves nothing.")
		fmt.Fprintln(os.Stderr, "    komizo enrol --host <this box> --token kmz_enr_...")
		return nil
	}
	key, err := box.ParsePublicKey(conf.RegistryKey)
	if err != nil {
		return fmt.Errorf("%s holds an unusable registry key: %w", *confPath, err)
	}
	// The devices this box takes orders from. PUBLIC keys, so holding them
	// grants this process nothing -- verifying with one is not signing with it.
	// An unreadable set is fatal here for the reason it is everywhere else: it
	// is a credential carrying a value somebody meant to work.
	opKeys, err := conf.TrustedKeys()
	if err != nil {
		return fmt.Errorf("%s holds an unusable device key: %w", *confPath, err)
	}
	// THE WARNING THAT USED TO BE HERE IS GONE BECAUSE IT COULD NO LONGER FIRE,
	// and that is worth a paragraph rather than a silent deletion.
	//
	// It said: "this box has no device keys, so it answers nothing -- not reads,
	// not commands", and it was correct twice over. The first version said such
	// a box "serves reads and refuses commands", which was true until
	// komizo-be#72 took away the route that read with the registry's token
	// alone; the second said it answered nothing, which was true until
	// komizo-be#180 made the registry key an authority to command.
	//
	// It is now UNREACHABLE. CanServe above requires a registry key and a server
	// id, and returns early without them. CanCommand requires a server id and
	// EITHER kind of key. So anything that gets past CanServe satisfies
	// CanCommand by construction, and the branch could only ever be skipped.
	//
	// Dead code that prints a false sentence is worse than dead code, because
	// the way it is found is somebody reading it and believing it. The pair of
	// conditions is asserted in serve_test.go instead, where a future change
	// that pulls them apart shows up as a failure rather than as a warning
	// nobody has seen since it was written.

	ln, err := listenUnix(*sock)
	if err != nil {
		return err
	}
	defer ln.Close()

	srv := &http.Server{
		Handler: box.Handler(box.APIConfig{
			ServerID:     conf.ServerID,
			RegistryKey:  key,
			OperatorKeys: opKeys,
			ReportPath:   *reportPath,
			HistoryPath:  *historyPath,
			MetricsPath:  *metricsPath,
			InboxDir:     *inboxDir,
			ResultsDir:   *resultsDir,
			LogsDir:      *logsDir,
		}),
		// Bounded, because the reader is on the other side of a proxy on the
		// internet. An unbounded header read is a connection somebody else
		// decides the lifetime of.
		ReadHeaderTimeout: 10 * time.Second,
		// And the BODY, now that a route reads one. Header timeouts were enough
		// while every route was a bodyless GET; a caller holding a valid read
		// token can otherwise trickle one byte a minute of an eight-kilobyte
		// command and pin a goroutine for as long as it likes. Caddy does not
		// bound it either -- read_body_timeout is unset by default.
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// listenUnix opens the socket, clearing a stale one first.
//
// A socket file outlives the process that made it, so a box that was powered
// off mid-request has one on disk that nothing is listening to. Binding over it
// fails with "address already in use" -- which, for a path rather than a port,
// is a service that will not start until somebody deletes a file by hand.
//
// Removed rather than reused, and only ever this exact path: if something else
// is genuinely listening there, the bind below still fails and says so.
func listenUnix(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("could not clear a stale socket at %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// After Listen, because the socket does not exist until then. Set
	// explicitly rather than left to the umask, which is not this process's to
	// assume.
	if err := os.Chmod(path, socketMode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("could not set permissions on %s: %w", path, err)
	}
	return ln, nil
}
