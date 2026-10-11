package main

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

type staticRecord struct {
	box.StaticServing
	DisabledRoute []byte `json:"disabled_route"`
}
type staticOperation struct {
	record         staticRecord
	previous       *staticRecord
	previousRoute  []byte
	previousRetain []byte
	touched        bool
}

func dockerStaticStream(parent context.Context, args []string, consume func(io.Reader) error) error {
	ctx, stop := context.WithTimeout(parent, 120*time.Second)
	defer stop()
	command := exec.CommandContext(ctx, "docker", args...)
	command.WaitDelay = 2 * time.Second
	command.Stderr = io.Discard
	stream, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err = command.Start(); err != nil {
		return err
	}
	err = consume(stream)
	if err == nil {
		// tar EOF need not be pipe EOF. Drain only bounded zero padding so a
		// producer cannot keep Wait blocked or conceal a second archive.
		tail, readErr := io.ReadAll(io.LimitReader(stream, (1<<20)+1))
		if readErr != nil || len(tail) > 1<<20 || strings.Trim(string(tail), "\x00") != "" {
			err = errors.New("unbounded or nonzero archive trailer")
		}
	}
	if err != nil {
		stop() // Kill only this copy subprocess, never a process by name/port.
	}
	return errors.Join(err, command.Wait())
}

func staticDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != mode || !workloadRootOwner(info) {
		return errors.New("unsafe static directory")
	}
	return nil
}
func (h *hostActivation) staticPath(app string) string {
	return filepath.Join(h.root, "/var/lib/komizo/static", app+".json")
}
func (h *hostActivation) staticDirectory(path string, mode os.FileMode) error {
	if h.makeStaticDir != nil {
		return h.makeStaticDir(path, mode)
	}
	return staticDirectory(path, mode)
}
func (h *hostActivation) staticMount(ctx context.Context) error {
	format := `{{range .Mounts}}{{if eq .Destination "/srv/public"}}{"source":{{json .Source}},"read_write":{{json .RW}}}{{end}}{{end}}`
	body, err := h.run(ctx, "inspect", "--format", format, h.policy.Static.Proxy)
	var mount struct {
		Source string `json:"source"`
		RW     bool   `json:"read_write"`
	}
	if err != nil || json.Unmarshal([]byte(body), &mount) != nil || mount.RW || mount.Source != filepath.Join(h.root, workload.StaticRoot) {
		return errors.New("shared proxy requires the isolated read-only public-tree mount")
	}
	return nil
}
func (h *hostActivation) prepareStatic(ctx context.Context, r workload.ActivationRequest) error {
	if r.Proxy != h.policy.Static.Proxy || filepath.Dir(r.RoutePath) != filepath.Join(h.root, box.ProxyDir, "routes") {
		return errors.New("static serving requires the protected standard proxy route")
	}
	if err := h.staticMount(ctx); err != nil {
		return err
	}
	compose, err := h.readBytes(filepath.Join(h.policy.AppDir, "compose.yml"))
	if err != nil {
		return err
	}
	gate, err := workload.StaticGate(compose, r.App)
	if err != nil {
		return err
	}
	route, err := h.readBytes(r.RoutePath)
	if err != nil {
		return err
	}
	previous := new(staticRecord)
	if err := h.readJSON(h.staticPath(r.App), previous); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		previous = nil
	}
	// Deploy staging wrote the new upstream route. Owner verbs reuse the
	// protected disabled route from their already accepted record instead.
	if previous != nil && previous.Revision == r.Candidate && len(previous.DisabledRoute) > 0 &&
		!strings.Contains(string(route), "\treverse_proxy "+r.App+"-gate:80 {") {
		route = previous.DisabledRoute
	}
	active, err := workload.StaticRoute(route, r.App, r.Candidate, h.policy.Static.Hostnames)
	if err != nil {
		return err
	}
	h.static = &staticOperation{record: staticRecord{StaticServing: box.StaticServing{
		Version: 1, Revision: r.Candidate, GateImage: gate, Proxy: r.Proxy}, DisabledRoute: route}, previous: previous}
	h.static.previousRoute, _ = h.readBytes(r.RoutePath + ".prev")
	if h.static.previousRoute == nil {
		h.static.previousRoute, _ = h.readBytes(r.RoutePath)
	}
	h.static.previousRetain, _ = h.readBytes(filepath.Join(h.policy.AppDir, ".komizo-image-retention"))
	public := filepath.Join(h.root, workload.StaticRoot)
	for _, directory := range []string{public, filepath.Join(public, r.App)} {
		if err := h.staticDirectory(directory, 0755); err != nil {
			return err
		}
	}
	volumes, err := h.run(ctx, "image", "inspect", "--format", "{{json .Config.Volumes}}", gate)
	var declared map[string]json.RawMessage
	if err != nil || json.Unmarshal([]byte(volumes), &declared) != nil {
		return errors.New("cannot verify public image volumes")
	}
	for volume := range declared {
		if volume != "/data" && volume != "/config" {
			return errors.New("static image declares an unreviewed volume")
		}
	}
	if err := staticSpace(public); err != nil {
		return err
	}

	cid, err := h.run(ctx, "create", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true", "--mount", "type=tmpfs,destination=/data,tmpfs-size=1048576,tmpfs-mode=0700",
		"--mount", "type=tmpfs,destination=/config,tmpfs-size=1048576,tmpfs-mode=0700", "--entrypoint", "/nonexistent", gate)
	cid = strings.TrimSpace(cid)
	if err != nil || len(cid) != 64 || strings.Trim(cid, "0123456789abcdef") != "" {
		return errors.New("cannot open the admitted public image")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		_, _ = h.run(cleanup, "rm", "-v", cid)
	}()
	stream := h.staticStream
	if stream == nil {
		stream = dockerStaticStream
	}
	err = stream(ctx, []string{"cp", cid + ":/etc/caddy/Caddyfile", "-"}, func(reader io.Reader) error {
		archive := tar.NewReader(io.LimitReader(reader, 128<<10))
		header, err := archive.Next()
		if err != nil || header.Name != "Caddyfile" || header.Typeflag != tar.TypeReg || header.Size > 65536 {
			return errors.New("static profile configuration is not a bounded regular file")
		}
		body, err := io.ReadAll(io.LimitReader(archive, 65537))
		sum := sha256.Sum256(body)
		if err != nil || hex.EncodeToString(sum[:]) != h.policy.Static.GateConfigSHA {
			return errors.New("gate configuration changed; repeat serving parity review")
		}
		if _, err = archive.Next(); err != io.EOF {
			return errors.New("unexpected static profile archive entries")
		}
		return nil
	})
	if err != nil {
		return err
	}
	stage := filepath.Join(public, r.App, ".prepare-"+r.ID)
	defer os.RemoveAll(stage)
	var treeSHA string
	err = stream(ctx, []string{"cp", cid + ":/srv/public/app/.", "-"}, func(reader io.Reader) error {
		var err error
		treeSHA, err = workload.StaticTree(reader, stage)
		return err
	})
	if err != nil {
		return err
	}
	h.boundary("public_copy")
	final := filepath.Join(public, r.App, r.Candidate)
	if info, err := os.Lstat(final); err == nil {
		if !info.IsDir() || h.staticDirectory(final, 0755) != nil {
			return errors.New("unsafe existing public tree")
		}
		existing, err := workload.StaticTreeChecksum(final)
		if err != nil || existing != treeSHA {
			return errors.New("existing public tree differs from its admitted image")
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if err := os.Rename(stage, final); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(final))
	if err != nil {
		return err
	}
	if err := errors.Join(parent.Sync(), parent.Close()); err != nil {
		return err
	}
	h.boundary("public_rename")
	h.static.record.TreeSHA256 = treeSHA
	h.static.touched = true
	return h.staticRoute(active, true)
}
func (h *hostActivation) staticRoute(route []byte, active bool) error {
	if h.static == nil {
		return errors.New("static operation not prepared")
	}
	path := filepath.Join(h.root, box.ProxyDir, "routes", h.policy.App+".caddy")
	if err := writeAtomicText(path, route, 0644); err != nil {
		return err
	}
	sum := sha256.Sum256(route)
	h.static.record.RouteSHA256 = hex.EncodeToString(sum[:])
	h.static.record.Active = active
	h.boundary("route_write")
	return nil
}
func (h *hostActivation) storeStatic() error {
	directory := filepath.Dir(h.staticPath(h.policy.App))
	if err := h.staticDirectory(directory, 0700); err != nil {
		return err
	}
	if err := workload.WritePrivateJSON(h.staticPath(h.policy.App), h.static.record); err != nil {
		return err
	}
	h.boundary("serving_record")
	return nil
}
func (h *hostActivation) staticClient() *http.Client {
	if h.readinessClient != nil {
		return h.readinessClient
	}
	return staticReadinessClient()
}
func staticReadinessClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func (h *hostActivation) prepareStoppedStatic(r workload.ActivationRequest) error {
	route, err := h.readBytes(r.RoutePath)
	if err != nil {
		return err
	}
	compose, err := h.readBytes(filepath.Join(h.policy.AppDir, "compose.yml"))
	if err != nil {
		return err
	}
	gate, err := workload.StaticGate(compose, r.App)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(route)
	h.static = &staticOperation{record: staticRecord{StaticServing: box.StaticServing{
		Version: 1, Revision: r.Candidate, GateImage: gate, Proxy: r.Proxy,
		RouteSHA256: hex.EncodeToString(sum[:])}, DisabledRoute: route}}
	return nil
}
func (h *hostActivation) AbortStatic(ctx context.Context, r workload.ActivationRequest) error {
	if h.static == nil || !h.static.touched || len(h.static.previousRoute) == 0 {
		return nil
	}
	// Preserve a stop arriving during failed validation/readiness. Recovery
	// must never restore a previously active static route over that decision.
	route := h.static.previousRoute
	stopped, err := h.Stopped(ctx, r)
	if err != nil {
		return err
	}
	if stopped {
		route = h.static.record.DisabledRoute
	}
	if err := writeAtomicText(r.RoutePath, route, 0644); err != nil {
		return err
	}
	if err := h.ReloadProxy(ctx, r); err != nil {
		return err
	}
	if len(h.static.previousRetain) > 0 {
		if err := writePrivateText(filepath.Join(h.policy.AppDir, ".komizo-image-retention"), h.static.previousRetain); err != nil {
			return err
		}
	}
	if h.static.previous != nil {
		previous := *h.static.previous
		if stopped {
			previous.Active = false
			sum := sha256.Sum256(route)
			previous.RouteSHA256 = hex.EncodeToString(sum[:])
		}
		return workload.WritePrivateJSON(h.staticPath(r.App), previous)
	}
	if err := os.Remove(h.staticPath(r.App)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil // Absence never establishes readiness.
}

func staticOwnerVerb(ctx context.Context, verb string, sub subject, svc, by string) (bool, error) {
	return staticOwnerWithHost(ctx, verb, sub, svc, by, newHostActivation())
}
func staticOwnerWithHost(ctx context.Context, verb string, sub subject, svc, by string, h *hostActivation) (bool, error) {
	if sub.app == "" || (verb != "start" && verb != "stop" && verb != "restart") {
		return false, nil
	}
	policyPath := filepath.Join(sub.root, workloadPolicyDirectory, sub.app+".json")
	if _, err := os.Lstat(policyPath); os.IsNotExist(err) {
		return false, nil
	}
	var p workload.Policy
	if err := h.readJSON(policyPath, &p); err != nil {
		return true, err
	}
	if err := p.Check(); err != nil || p.App != sub.app || p.AppDir != sub.dir {
		return true, errors.New("owner operation differs from its protected workload policy")
	}
	if p.Static == nil {
		return false, nil
	}
	if svc != "" {
		return true, errors.New("static serving requires a whole-application operation")
	}
	h.root, h.policy = sub.root, p
	if verb == "stop" {
		// Record intent before waiting for the activation's deployment locks.
		// Its next checkpoint must observe the stop even if this caller exits.
		if err := box.MarkStopped(sub.root, sub.app, by, time.Now()); err != nil {
			return true, err
		}
	}
	lockCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	unlock, err := box.LockDeployment(lockCtx, sub.root, sub.app)
	if err != nil {
		return true, err
	}
	defer unlock()
	var record staticRecord
	if err := h.readJSON(h.staticPath(sub.app), &record); err != nil {
		if verb == "stop" && os.IsNotExist(err) {
			return false, nil // A gate still serving before the first static rollout.
		}
		return true, errors.New("static serving record unavailable; inspect the deployment journal")
	}
	if record.Version != 1 || record.Proxy != p.Static.Proxy || !isStaticRevision(record.Revision) || len(record.DisabledRoute) == 0 || len(record.DisabledRoute) > workload.MaxBytes {
		return true, errors.New("invalid protected static serving record")
	}
	if _, err := workload.StaticRoute(record.DisabledRoute, sub.app, record.Revision, p.Static.Hostnames); err != nil {
		return true, err
	}
	if err := box.RefuseScopedStart(sub.root, sub.app); err != nil && verb != "stop" {
		return true, err
	}
	if verb == "stop" {
		h.static = &staticOperation{record: record}
		if err := h.staticRoute(record.DisabledRoute, false); err != nil {
			return true, err
		}
		r := workload.ActivationRequest{App: sub.app, Candidate: record.Revision, Proxy: p.Static.Proxy}
		if err := h.ReloadProxy(ctx, r); err != nil {
			return true, err
		}
		if err := h.composeWorkload(ctx, r, "stop"); err != nil {
			return true, err
		}
		return true, h.storeStatic()
	}
	stopped, err := box.IsStopped(sub.root, sub.app)
	if err != nil || verb == "restart" && stopped {
		return true, errors.Join(err, errors.New("stopped static application must be explicitly started"))
	}
	if err := ctx.Err(); err != nil {
		return true, err
	}
	// Start/restart revalidate the current accepted image and public tree;
	// they neither pull an image nor authorize another source revision.
	current, err := h.readBytes(filepath.Join(p.AppDir, ".env"))
	versions := []string{}
	for _, line := range strings.Split(string(current), "\n") {
		if strings.HasPrefix(line, "APP_VERSION=") {
			versions = append(versions, strings.TrimSuffix(strings.TrimPrefix(line, "APP_VERSION="), "\r"))
		}
	}
	if err != nil || len(versions) != 1 || versions[0] != record.Revision {
		return true, errors.New("static serving revision differs; inspect the deployment journal")
	}
	var accepted workload.ReleaseAcceptance
	if err := h.readJSON(filepath.Join(sub.root, releaseDirectory, sub.app, record.Revision+".json"), &accepted); err != nil {
		return true, err
	}
	compose, err := h.readBytes(filepath.Join(p.AppDir, "compose.yml"))
	if err != nil {
		return true, err
	}
	if _, err := workload.BindLocalRelease(ctx, h.run, p, accepted, record.Revision, p.ImagePrefix+"config:"+record.Revision, compose); err != nil {
		return true, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return true, err
	}
	r := workload.ActivationRequest{App: sub.app, Candidate: record.Revision, ID: hex.EncodeToString(id[:]),
		Proxy: p.Static.Proxy, RoutePath: filepath.Join(sub.root, box.ProxyDir, "routes", sub.app+".caddy")}
	if err := h.prepareStatic(ctx, r); err != nil {
		return true, errors.Join(err, h.AbortStatic(ctx, r))
	}
	if err := h.ReloadProxy(ctx, r); err != nil {
		return true, errors.Join(err, h.AbortStatic(ctx, r))
	}
	client := h.staticClient()
	if err := workload.VerifyStaticReadiness(ctx, h.run, client, p, r.Candidate); err != nil {
		return true, errors.Join(err, h.AbortStatic(ctx, r))
	}
	if err := h.storeStatic(); err != nil {
		return true, errors.Join(err, h.AbortStatic(ctx, r))
	}
	if verb == "start" {
		return true, box.ClearStopped(sub.root, sub.app)
	}
	return true, nil
}

func isStaticRevision(value string) bool {
	return len(value) == 40 && strings.Trim(value, "0123456789abcdef") == ""
}

func (h *hostActivation) pruneStatic(r workload.ActivationRequest) error {
	directory := filepath.Join(h.root, workload.StaticRoot, r.App)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == r.Candidate || name == r.Previous || !isStaticRevision(name) {
			continue
		}
		target := filepath.Join(directory, name)
		info, err := os.Lstat(target)
		if err != nil || !info.IsDir() || h.staticDirectory(target, 0755) != nil {
			return errors.New("unsafe retired public tree")
		}
		if _, err := workload.StaticTreeChecksum(target); err != nil {
			return err
		}
		if err := os.RemoveAll(target); err != nil {
			return err
		}
	}
	parent, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}
