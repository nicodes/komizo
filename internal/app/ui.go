package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/ui"
)

// `komizo ui` -- the local web app, served by the box for whoever can reach
// the machine it runs on.
//
// THE CLI IS THE WHOLE PRODUCT, and this is its screen: a SolidJS + Tailwind
// app (the RN-port screens from the archived reference are the design), built
// to a static export, embedded, and served here. It runs ON the box, as root,
// when the operator starts it -- it is not the box daemon, which stays
// deploy-path API only, and nothing here touches it.
//
// Why not the daemon's socket: every route on it requires a read token signed
// by the registry and an envelope signed by a planted device key (box/api.go,
// komizo-be#72). The registry is decommissioned and the CLI holds no signing
// key, so that door cannot be opened without extending the daemon -- which is
// the one thing this command must not do. It does not need to: the files the
// daemon reads ARE the store, and this process may read them directly. Same
// documents, same box package, no second schema.
//
// ZERO AUTH, BY DESIGN: the listener is the boundary. It binds loopback by
// default and may be widened to the tailnet interface with an explicit
// --bind -- Tailscale is the identity. It is NEVER wildcard by accident:
// 0.0.0.0 arrives only when somebody typed it.

// uiActions is the safe-action allowlist, enforced HERE, server-side: a
// request for anything else is refused whatever the page sent. The verbs are
// the lifecycle trio because they run through `komizo-box app`, the single
// implementation a signed command would take -- acting like the CLI is acting
// exactly as much as the CLI does, no more.
var uiActions = map[string]bool{"start": true, "stop": true, "restart": true}

// uiBoxBin is a var so a test points it at a stub; in production it is the
// agent init installed.
var uiBoxBin = BoxBin

// uiServer is the handler and what it reads. The paths default to the box's
// own constants and are fields so a test points them at a fixture.
type uiServer struct {
	reportPath  string
	historyPath string
	metricsPath string
	resultsDir  string
	appsDir     string
	static      fs.FS
}

func defaultUIServer(static fs.FS) *uiServer {
	return &uiServer{
		reportPath:  box.ReportPath,
		historyPath: box.HistoryPath,
		metricsPath: box.MetricsPath,
		resultsDir:  box.ResultsDir,
		appsDir:     box.AppsDir,
		static:      static,
	}
}

func RunUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.Usage = func() { usageUI(fs) }
	bind := fs.String("bind", "127.0.0.1", "address to listen on (default loopback; set the tailnet interface address to reach it from your tailnet)")
	port := fs.Int("port", 8480, "port to listen on")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if err := validateUIBind(*bind); err != nil {
		return err
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("--port must be 1-65535, got %d", *port)
	}

	static, err := ui.Dist()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(*bind, strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	if ip := net.ParseIP(*bind); ip != nil && ip.IsUnspecified() {
		// Reachable only because somebody typed it -- see the header. Said out
		// loud once, because "any interface" is a bigger promise than loopback.
		note("--bind %s listens on every interface. There is no auth: anyone who can reach it can read this box and restart its apps.", *bind)
	} else if *bind != "127.0.0.1" && *bind != "localhost" && *bind != "::1" {
		note("--bind %s: no auth beyond reachability -- that address is the boundary.", *bind)
	}
	fmt.Printf("komizo ui on http://%s\n", ln.Addr())

	srv := &http.Server{
		Handler:           defaultUIServer(static).routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.Serve(ln)
}

// validateUIBind keeps the listen address an address. The wildcard is not
// refused -- refusing an explicit flag is paternalism -- but the default is
// loopback and ui_test.go pins that it stays loopback.
func validateUIBind(bind string) error {
	if bind == "localhost" {
		return nil
	}
	if net.ParseIP(bind) == nil {
		return fmt.Errorf("--bind must be an IP address or localhost, got %q", bind)
	}
	return nil
}

func (s *uiServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/report", s.apiReport)
	mux.HandleFunc("GET /api/history", s.apiHistory)
	mux.HandleFunc("GET /api/metrics", s.apiMetrics)
	mux.HandleFunc("GET /api/events", s.apiEvents)
	mux.HandleFunc("GET /api/backups", s.apiBackups)
	// No method qualifier: the /api/ catch-all would otherwise shadow the
	// method mismatch and a GET here would read as "no such route" rather
	// than "not like that" -- the same 401/404 ambiguity box/api.go refuses.
	mux.HandleFunc("/api/action", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			uiError(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		s.apiAction(w, r)
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		uiError(w, http.StatusNotFound, "no such read")
	})
	mux.HandleFunc("/", s.spa)
	return mux
}

// --- reads -----------------------------------------------------------------
// Every one of them is a file the box already writes, read with the box's own
// package. Nothing is computed here that the box computes elsewhere, so the
// page and `komizo report` can never disagree about what a fact is.

func (s *uiServer) apiReport(w http.ResponseWriter, r *http.Request) {
	rep, err := box.ReadReport(s.reportPath)
	if err != nil {
		uiError(w, http.StatusServiceUnavailable, "no report yet -- the agent writes one on its first tick")
		return
	}
	uiJSON(w, map[string]any{"v": 1, "report": rep})
}

func (s *uiServer) apiHistory(w http.ResponseWriter, r *http.Request) {
	from, to, ok := uiWindow(r)
	if !ok {
		uiError(w, http.StatusBadRequest, "from and to must be unix seconds, and from must not be after to")
		return
	}
	samples, err := box.ReadSamples(s.historyPath, from, to)
	if err != nil {
		samples = nil
	}
	uiJSON(w, map[string]any{"v": 1, "from": from, "to": to, "samples": samples})
}

func (s *uiServer) apiMetrics(w http.ResponseWriter, r *http.Request) {
	from, to, ok := uiWindow(r)
	if !ok {
		uiError(w, http.StatusBadRequest, "from and to must be unix seconds, and from must not be after to")
		return
	}
	m, err := box.ReadMetrics(s.metricsPath, from, to)
	if err != nil {
		uiError(w, http.StatusServiceUnavailable, "could not read what was measured")
		return
	}
	uiJSON(w, map[string]any{"v": 1, "from": from, "to": to, "metrics": m})
}

// An event is a command the box was told and what came of it: the results
// directory is the only box-local record of things happening. Newest first,
// bounded -- the directory is pruned by rootd, and the page wants recentness,
// not the archive.
func (s *uiServer) apiEvents(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.resultsDir)
	if err != nil {
		// Absent is a box nothing has ever been told, not a fault.
		uiJSON(w, map[string]any{"v": 1, "events": []box.Result{}})
		return
	}
	var events []box.Result
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		res, ok, err := box.ReadResult(s.resultsDir, strings.TrimSuffix(e.Name(), ".json"))
		if err != nil || !ok {
			continue
		}
		events = append(events, res)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].At.After(events[j].At) })
	if len(events) > 50 {
		events = events[:50]
	}
	if events == nil {
		events = []box.Result{}
	}
	uiJSON(w, map[string]any{"v": 1, "events": events})
}

// There is no box-local backup state: the CLI never wrote any, and inventing
// a shape nothing writes would put a confident empty screen over a real gap.
// The endpoint exists so the page can say so. Run-backup is deferred to v2
// for the same reason -- there is no clean box-local trigger to call.
func (s *uiServer) apiBackups(w http.ResponseWriter, r *http.Request) {
	uiJSON(w, map[string]any{
		"v":       1,
		"backups": []string{},
		"note":    "backups are not tracked on this box yet -- no box-local backup state exists, so this screen shows the absence rather than a guess. Planned for a later version.",
	})
}

// --- the one write ---------------------------------------------------------

// apiAction runs an allowlisted lifecycle verb against an app, through the
// same komizo-box the CLI's start/stop/restart run. Two checks, both here:
// the verb is in the allowlist, and the app is one this box has a record of.
func (s *uiServer) apiAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		App    string `json:"app"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(boundedBody(r)).Decode(&req); err != nil {
		uiError(w, http.StatusBadRequest, "could not read that request")
		return
	}
	if !uiActions[req.Action] {
		uiError(w, http.StatusForbidden, "not an action this serves: the allowlist is start, stop, restart")
		return
	}
	if err := validateApp(req.App); err != nil {
		uiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := os.Stat(filepath.Join(s.appsDir, req.App+".env")); err != nil {
		uiError(w, http.StatusNotFound, req.App+" is not an app on this box")
		return
	}

	// Bounded, because this blocks a request: a hung compose must not hang the
	// page with it.
	ctx, stop := context.WithTimeout(r.Context(), 2*time.Minute)
	defer stop()
	out, err := exec.CommandContext(ctx, uiBoxBin, "app", req.Action, "--app", req.App).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		uiError(w, http.StatusGatewayTimeout, req.Action+" did not finish in two minutes")
		return
	}
	uiJSON(w, map[string]any{"v": 1, "ok": err == nil, "output": string(out)})
}

// --- the page ----------------------------------------------------------------

// spa serves the embedded export: the exact file when it exists, index.html
// otherwise -- the router is client-side, so /app/web is a route the page
// resolves, not a file the server names.
func (s *uiServer) spa(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name != "" && !strings.Contains(name, "..") {
		if f, err := s.static.Open(name); err == nil {
			_ = f.Close()
			http.FileServerFS(s.static).ServeHTTP(w, r)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	index, err := fs.ReadFile(s.static, "index.html")
	if err != nil {
		uiError(w, http.StatusServiceUnavailable, "this binary was built without the web export")
		return
	}
	_, _ = w.Write(index)
}

// --- helpers -------------------------------------------------------------------

func uiWindow(r *http.Request) (from, to int64, ok bool) {
	to = time.Now().Unix()
	from = time.Now().Add(-time.Hour).Unix()
	if v := r.URL.Query().Get("to"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		to = n
	}
	if v := r.URL.Query().Get("from"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		from = n
	}
	return from, to, from <= to
}

// uiJSON answers with the same two headers the box's own API sets, and for
// the same reason (box/api.go): a JSON document a browser decides to treat as
// HTML is a document that can run.
func uiJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(v)
}

func uiError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"v": 1, "ok": false, "output": msg})
}

// boundedBody bounds a request body the way box/write.go bounds a command: a
// body that does not end is memory.
func boundedBody(r *http.Request) io.Reader {
	return io.LimitReader(r.Body, 1<<20)
}

func usageUI(fs *flag.FlagSet) {
	fmt.Print(`komizo ui - this box, as a web app

  komizo ui
  komizo ui --bind 100.x.y.z    # the tailnet interface address

Runs ON the box, as root, and serves the local web app: what the box is, what
runs on it, what it has been told -- read off the box's own files, through the
same package the daemon reads them with.

There is no sign-in: the listener is the boundary. It binds loopback by
default, so the page is for whoever is already on the machine; --bind the
tailnet interface address to open it to your tailnet, where the network is
the identity. It never listens on every interface by accident -- 0.0.0.0 only
arrives when typed.

The only actions are start, stop and restart for an app, enforced here --
whatever the page asks for, nothing else is done.

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}
