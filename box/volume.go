package box

import "context"

// Volumes measures every app's docker volumes, or one app's.
//
// The expensive one. Everything else in this package is a file read; this walks
// whole directory trees, which is why the timer runs it on a slower cadence
// than the rest and why it is a separate call rather than part of Report.
//
// Builds its own index: it is asked for perhaps once every fifteen minutes, and
// two docker calls to answer it is a better trade than making the common path
// carry an argument it does not need.
func (p *Probe) Volumes(ctx context.Context, only string) []Volume {
	inv := p.dockerInventory(ctx)
	// Measured once per SOURCE, then attributed. Two containers sharing one
	// volume must not make it count twice, and the walk is far too expensive to
	// run twice for the same answer.
	sizes := map[string]uint64{}
	var out []Volume
	for _, as := range p.appStates() {
		if only != "" && as.name != only {
			continue
		}
		for _, ci := range inv.forDir(as.dir()) {
			for _, m := range ci.mounts {
				n, seen := sizes[m.source]
				if !seen {
					var ok bool
					if n, ok = dirBytes(p.path(m.source)); !ok {
						continue
					}
					sizes[m.source] = n
				}
				out = append(out, Volume{App: as.name, Service: ci.service, Name: m.name, Bytes: n})
			}
		}
	}
	sortBy(out, func(v Volume) string { return v.App + "\x00" + v.Service + "\x00" + v.Name })
	return out
}
