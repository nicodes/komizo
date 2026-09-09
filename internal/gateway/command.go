package gateway

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Command runs the unprivileged gateway process. Its administration socket and
// routing configuration must be provisioned separately from app-private secrets.
func Command(ctx context.Context, args []string, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("gateway", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	app := flags.String("app", "", "fixed application scope")
	configPath := flags.String("config", "", "durable gateway configuration file")
	socketPath := flags.String("admin-socket", "", "operator-private Unix socket")
	listen := flags.String("listen", "127.0.0.1:8080", "HTTP traffic listener (explicitly bind container interfaces)")
	shutdown := flags.Duration("shutdown-timeout", 0, "explicit HTTP shutdown budget")
	initialize := flags.Bool("initialize", false, "create an empty configuration only if missing")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errors.New("invalid gateway flags")
	}
	if flags.NArg() != 0 || !validID(*app) || !filepath.IsAbs(*configPath) || !filepath.IsAbs(*socketPath) || *shutdown <= 0 {
		return errors.New("gateway requires absolute config/socket paths and a positive shutdown timeout")
	}
	if *initialize {
		if err := os.MkdirAll(filepath.Dir(*configPath), 0o700); err != nil {
			return errors.New("cannot create gateway configuration directory")
		}
		file, err := os.OpenFile(*configPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, writeErr := io.WriteString(file, `{"app":"`+*app+`","generation":"bootstrap","routes":[]}`)
			err = errors.Join(writeErr, file.Sync(), file.Close())
			if err != nil {
				return errors.New("cannot initialize gateway configuration")
			}
		} else if !errors.Is(err, os.ErrExist) {
			return errors.New("cannot initialize gateway configuration")
		}
	}
	info, err := os.Lstat(*configPath)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("gateway config must be an existing regular file")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return errors.New("cannot open gateway configuration")
	}
	config, err := Decode(file)
	file.Close()
	if err != nil {
		return err
	}
	if config.App != *app {
		return errors.New("gateway configuration belongs to another application")
	}
	g, err := New(config, nil)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*socketPath), 0o700); err != nil {
		return errors.New("cannot create private gateway socket directory")
	}
	parent, err := os.Lstat(filepath.Dir(*socketPath))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("gateway admin directory must be private")
	}
	lock, err := socketLock(*socketPath + ".lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	if old, err := os.Lstat(*socketPath); err == nil {
		if old.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to replace a non-socket admin path")
		}
		conn, dialErr := net.DialTimeout("unix", *socketPath, time.Second)
		if dialErr == nil {
			conn.Close()
			return errors.New("gateway admin socket is already in use")
		}
		if !connectionRefused(dialErr) {
			return errors.New("cannot establish stale gateway socket ownership")
		}
		if err := os.Remove(*socketPath); err != nil {
			return errors.New("cannot remove stale gateway socket")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect gateway socket")
	}
	admin, err := net.Listen("unix", *socketPath)
	if err != nil {
		return errors.New("cannot listen on gateway admin socket")
	}
	defer admin.Close()
	if err := os.Chmod(*socketPath, 0o600); err != nil {
		return errors.New("cannot protect gateway admin socket")
	}
	traffic, err := net.Listen("tcp", *listen)
	if err != nil {
		return errors.New("cannot listen on gateway traffic address")
	}
	defer traffic.Close()
	publicServer := &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second}
	adminServer := &http.Server{Handler: g.Admin(), ReadHeaderTimeout: 10 * time.Second}
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- publicServer.Serve(traffic) }()
	go func() { errorsCh <- adminServer.Serve(admin) }()
	select {
	case <-ctx.Done():
	case err = <-errorsCh:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	end, cancel := context.WithTimeout(context.Background(), *shutdown)
	defer cancel()
	shutdownErr := errors.Join(publicServer.Shutdown(end), adminServer.Shutdown(end))
	publicServer.Close()
	adminServer.Close()
	if err != nil || shutdownErr != nil {
		return errors.New("gateway stopped with an incomplete shutdown")
	}
	return nil
}
