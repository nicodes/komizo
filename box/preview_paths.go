package box

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A single stable site imports separate PR handlers. Keeping handlers outside
// *.caddy avoids duplicate site definitions when several PRs share one host.
func previewPathSite(r PreviewRecord, k PreviewKnob) string {
	hosts := r.WebHost(k)
	if len(r.Images) > 1 {
		hosts += ", " + r.PublicAPIHost(k)
	}
	return fmt.Sprintf(`# Written by komizo preview. Stable hostname for %s.
%s {
 header >Strict-Transport-Security "max-age=31536000"
 import /etc/caddy/routes/_preview-pr-*.%s.route
 respond "no preview is configured for this path" 404
}
`, r.App, hosts, r.App)
}

func previewPathRoute(r PreviewRecord) string {
	return fmt.Sprintf(`# Written by komizo preview. %s PR #%d.
redir %s %s/?{http.request.uri.query} 308
handle_path %s/* {
 reverse_proxy %s-gate:80 {
  header_up X-Forwarded-Prefix %s
 }
}
`, r.App, r.PR, r.BasePath, r.BasePath, r.BasePath, r.Project, r.BasePath)
}

func applyPreviewRecordRoute(ctx context.Context, run previewRun, cfg PreviewUpConfig, r PreviewRecord) error {
	if r.BasePath == "" {
		return ApplyPreviewRoute(ctx, run, cfg.Proxy, cfg.RoutesDir, r.RouteFile, previewRoute(r, cfg.Knob))
	}
	sitePath := filepath.Join(cfg.RoutesDir, "_preview-path-"+r.App+".caddy")
	previous, err := os.ReadFile(sitePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	site := previewPathSite(r, cfg.Knob)
	// Reject incompatible host configuration while another PR's handler exists.
	// A domain migration must explicitly drain its old path previews first.
	if previous != nil && string(previous) != site {
		matches, err := filepath.Glob(filepath.Join(cfg.RoutesDir, "_preview-pr-*."+r.App+".route"))
		if err != nil {
			return err
		}
		for _, match := range matches {
			if filepath.Base(match) != r.RouteFile {
				return fmt.Errorf("path preview domain changed while another preview is running; drain the app's previews before changing its domain")
			}
		}
	}
	if err := os.WriteFile(sitePath, []byte(site), 0o644); err != nil {
		return err
	}
	if err := ApplyPreviewRoute(ctx, run, cfg.Proxy, cfg.RoutesDir, r.RouteFile, previewPathRoute(r)); err != nil {
		if previous == nil {
			_ = os.Remove(sitePath)
		} else {
			_ = os.WriteFile(sitePath, previous, 0o644)
		}
		return err
	}
	return nil
}

// Path ask authorization is restricted to explicit per-app opt-ins.
func (k PreviewKnob) PathAskAllow(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, line := range strings.Split(k.body, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(key, "PATH_DOMAIN.") {
			continue
		}
		app := strings.TrimPrefix(key, "PATH_DOMAIN.")
		if !previewAppChars.MatchString(app) || k.PathDomainFor(app) == "" {
			continue
		}
		if host == k.HostFor(app, 1) || host == k.APIHostFor(app, 1) {
			return true
		}
	}
	return false
}
