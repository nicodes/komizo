package box

import (
	"bufio"
	"encoding/json"
	"io"
	"math"
	"os"
	"sort"
	"strings"
)

// Request counts, read off the shared proxy's access log.
//
// COUNTS, NEVER LINES. Everything below reduces a log line to four numbers and
// a hostname before it returns, and nothing in this file can emit a path, a
// client address, a header or a user agent. That is the standing promise the
// whole feature rests on: komizo can tell you an app served 4,000 requests and
// 12 of them failed, and it cannot tell anyone who made them.
//
// The join is the hostname. Every app declares the names it answers on and the
// deploy script records them at /srv/<app>/hostnames, so this needs nothing
// from apps and works the same for an app running nginx as for one running
// Caddy.

// tailBytes is how much of the log to read.
//
// From the END, because the log is append-only and the question is always about
// recent minutes. A box that has been up for a year has a log this would
// otherwise walk in full on every poll.
const tailBytes = 4 << 20

// Metrics totals the requests in a range, per app, per minute.
func (p *Probe) Metrics(from, to int64) Metrics {
	m := Metrics{Rows: []Metric{}}

	// Hostname -> app, from what each app declared. Built first so the walk over
	// the log can attribute as it goes rather than in a second pass.
	type owner struct{ app, service string }
	byHost := map[string]owner{}
	for _, as := range p.appStates() {
		if as.dir() == "" {
			continue
		}
		for _, h := range p.hosts(as.dir()) {
			byHost[h.Name] = owner{as.name, h.Service}
		}
	}

	f, err := os.Open(p.path(AccessLog))
	if err != nil {
		return m
	}
	defer f.Close()

	// seeked decides whether the first line is trustworthy, and ONLY a seek
	// makes it suspect. Dropping it unconditionally would lose the oldest
	// request in every log small enough to be read whole.
	seeked := false
	if fi, err := f.Stat(); err == nil && fi.Size() > tailBytes {
		if _, err := f.Seek(fi.Size()-tailBytes, io.SeekStart); err != nil {
			return m
		}
		seeked = true
	}

	type key struct {
		minute       int64
		app, service string
	}
	counts := map[key]*Metric{}
	var oldest, newest int64

	sc := bufio.NewScanner(f)
	// Caddy writes one JSON object per line and they are not short. The default
	// 64K would silently stop at the first long one, which reads as a box that
	// went quiet.
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		// A seek lands mid-record, so the first line after one is very likely a
		// partial. Dropped rather than reported: an artefact of how this is read.
		if seeked {
			seeked = false
			continue
		}
		var e accessEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		ts := int64(math.Floor(e.TS))
		if ts <= 0 {
			continue
		}

		// What the log actually covers, measured over every request in the tail
		// -- INCLUDING the ones outside the asked-for range, which is the whole
		// point. It is the difference between "nothing was served in this
		// minute" and "nobody was writing this down yet", and only the lines the
		// range excludes can establish where that boundary is.
		if oldest == 0 || ts < oldest {
			oldest = ts
		}
		if ts > newest {
			newest = ts
		}

		// The range, applied HERE rather than by the caller, so the answer is
		// small and roughly constant however wide a range is asked for and
		// however big the log has grown.
		if ts < from || ts > to {
			continue
		}

		host := e.Request.Host
		o, ok := byHost[host]
		if !ok {
			// Not an exact name. Try the wildcard its parent would have claimed:
			// one label off the front, which is all Caddy allows.
			if _, rest, cut := strings.Cut(host, "."); cut {
				o, ok = byHost["*."+rest]
			}
		}
		if !ok {
			// A name pointed at this box by someone else. Counted for no app,
			// which is the honest answer.
			continue
		}

		k := key{minute: ts - ts%60, app: o.app, service: o.service}
		row := counts[k]
		if row == nil {
			row = &Metric{Minute: k.minute, App: k.app, Service: k.service}
			counts[k] = row
		}
		switch {
		case e.Status >= 500:
			row.C5++
		case e.Status >= 400:
			row.C4++
		case e.Status >= 300:
			row.C3++
		default:
			row.C2++
		}
	}

	if oldest > 0 {
		m.Span = &Span{From: oldest, To: newest}
	}
	for _, r := range counts {
		m.Rows = append(m.Rows, *r)
	}
	sort.Slice(m.Rows, func(i, j int) bool {
		a, b := m.Rows[i], m.Rows[j]
		if a.Minute != b.Minute {
			return a.Minute < b.Minute
		}
		if a.App != b.App {
			return a.App < b.App
		}
		return a.Service < b.Service
	})
	return m
}

// accessEntry is the three fields of a Caddy access log line that matter.
//
// Decoded rather than pattern-matched. The shell this replaces pulled each
// field with a regex because awk has no JSON parser, and paid for it with a
// standing hazard: a hostname containing an escaped quote, or a key order
// nothing promises, and the count silently reads zero -- which charts as a flat
// line, indistinguishable from no traffic.
//
// The struct is also the privacy boundary made structural. There is no field
// here for the path, the client address, the headers or the user agent, so no
// amount of later editing in this file can leak one by accident.
type accessEntry struct {
	TS      float64 `json:"ts"`
	Status  int     `json:"status"`
	Request struct {
		Host string `json:"host"`
	} `json:"request"`
}
