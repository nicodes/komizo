package box

import (
	"context"
	"sort"
	"strings"
)

// Volumes measures every app's docker volumes.
//
// The expensive one. Everything else in this package is a file read; this walks
// whole directory trees, which is why the sampler runs it on a slower cadence
// than the rest and why it is a separate call rather than part of System.
func (p *Probe) Volumes(ctx context.Context, only string) []Volume {
	var out []Volume
	for _, as := range p.appStates() {
		if only != "" && as.name != only {
			continue
		}
		dir := as.dir()
		if dir == "" {
			continue
		}
		ids := p.composeIDs(ctx, dir, true)
		if len(ids) == 0 {
			continue
		}
		// service, volume name, and where it lives on the host. One line per
		// mount, so a volume shared by two containers appears under both.
		args := append([]string{"inspect", "--format",
			`{{$s := index .Config.Labels "com.docker.compose.service"}}` +
				`{{range .Mounts}}{{if eq .Type "volume"}}{{$s}}` + dsep +
				`{{.Name}}` + dsep + `{{.Source}}` + "\n" + `{{end}}{{end}}`}, ids...)
		raw, err := p.docker(ctx, args...)
		if err != nil {
			continue
		}

		type mount struct{ service, name, src string }
		var mounts []mount
		srcs := map[string]bool{}
		for _, ln := range strings.Split(raw, "\n") {
			f := strings.Split(strings.TrimRight(ln, "\r"), dsep)
			if len(f) < 3 || f[2] == "" {
				continue
			}
			mounts = append(mounts, mount{f[0], f[1], f[2]})
			srcs[f[2]] = true
		}

		// Measured once per volume, then attributed. Two containers sharing one
		// volume must not make it count twice, and the walk is far too expensive
		// to run twice for the same answer.
		sizes := make(map[string]uint64, len(srcs))
		for src := range srcs {
			if n, ok := dirBytes(p.path(src)); ok {
				sizes[src] = n
			}
		}
		for _, m := range mounts {
			n, ok := sizes[m.src]
			if !ok {
				continue
			}
			out = append(out, Volume{App: as.name, Service: m.service, Name: m.name, Bytes: n})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].App != out[j].App {
			return out[i].App < out[j].App
		}
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Name < out[j].Name
	})
	return out
}
