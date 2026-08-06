package box

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// How the box keeps what it measures.
//
// Two files with two different jobs. report.json is the CURRENT state, replaced
// whole every interval and read by anything that wants to know how the box is
// right now. history.jsonl is what it WAS, appended one line per reading, and
// is what the charts are drawn from.

// WriteReport replaces report.json atomically.
//
// Atomically because the agent reads this file on its own schedule and the two
// are not coordinated. A reader that caught a half-written document would get a
// JSON error, and the honest reading of a JSON error from a box is "this server
// is broken" -- which would be a lie told every interval.
//
// 0644 by design. This is exactly the boundary that lets the reporting account
// have no privileges at all: root writes, an unprivileged process reads. See
// design/appify.md §3. Nothing secret may ever go in it -- see Report.
func WriteReport(path string, r Report) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o644)
}

// ReadReport loads a report written by WriteReport.
func ReadReport(path string) (Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	return Decode[Report](b)
}

// Document is anything komizo-box emits. Every one of them states the schema it
// was written against, so no reader has to know which document it is holding to
// find out whether it can be trusted.
type Document interface {
	Report | Poll | Monitor
	Schema() int
}

// Decode parses a document and refuses one from a future it cannot read.
//
// The version check is the reason this exists rather than a bare Unmarshal at
// each call site. A box running a newer binary than the CLI is a NORMAL state
// -- boxes are updated by hand, one at a time -- and the failure has to be a
// message about versions rather than a screen of plausible zeroes.
//
// A document with no version at all reads as v0, which no komizo-box has ever
// written, so it fails the same way: this is not a document komizo produced.
func Decode[T Document](b []byte) (T, error) {
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return v, err
	}
	var zero T
	switch got := v.Schema(); {
	case got == 0:
		return zero, fmt.Errorf("this is not something komizo-box wrote -- it states no schema version")
	case got > Version:
		return zero, fmt.Errorf("this server speaks report schema v%d and this komizo understands v%d -- update komizo", got, Version)
	}
	return v, nil
}

// AppendSample adds one reading to the history log and trims it if it has grown
// past max bytes.
//
// Trimmed only when it has grown, rather than rewritten every time: the copy
// costs the whole file, and paying that once every few days is the difference
// between a background job nobody notices and one that shows up in iowait.
//
// Trimmed by BYTES, not by age. Age would make retention depend on how many
// containers the box runs -- twenty containers would keep a fifth as long as
// four, for the same disk -- and the thing actually worth bounding is the disk.
func AppendSample(path string, s Sample, max int64, keep int) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// 0640, and the GROUP bit is load-bearing now rather than decorative. This
	// used to live under a directory nothing unprivileged could traverse, where
	// the mode changed nothing; it lives in ServedDir, which is setgid to the
	// account that serves this file, so 0640 is exactly what lets the read API
	// open it and nothing else on the box do so.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > max {
		return trimLines(path, keep)
	}
	return nil
}

// ReadSamples returns the readings between from and to, inclusive.
func ReadSamples(path string, from, to int64) ([]Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// A box that has not sampled yet is not an error. It is a new box,
			// and its charts are empty because nothing has happened.
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	// The tail only. The question is always about recent minutes and the file is
	// append-only, so a box up for a year would otherwise be walked in full.
	//
	// seeked is tracked because it decides whether the first line is trustworthy,
	// and ONLY a seek makes it suspect. Dropping it unconditionally would silently
	// lose the oldest reading of every small file -- which is every new box.
	seeked := false
	if fi, err := f.Stat(); err == nil && fi.Size() > historyTail {
		if _, err := f.Seek(fi.Size()-historyTail, io.SeekStart); err != nil {
			return nil, err
		}
		seeked = true
	}

	var out []Sample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Bytes()
		// A seek lands mid-record, so the first line after one is very likely a
		// partial. Dropped rather than reported: it is an artefact of how this is
		// read, not something wrong with the box.
		if seeked {
			seeked = false
			continue
		}
		var s Sample
		if err := json.Unmarshal(line, &s); err != nil {
			continue
		}
		if u := s.At.Unix(); u < from || u > to {
			continue
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

const (
	// HistoryMax is roughly a week at a handful of containers.
	HistoryMax = 16 << 20
	// HistoryKeep is how many readings survive a trim.
	HistoryKeep = 20000
	// historyTail bounds one read of the history.
	historyTail = 8 << 20
)

// trimLines rewrites a file keeping only its last n lines.
func trimLines(path string, n int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	// A ring buffer rather than reading the whole file into a slice: this runs
	// on the box, against the largest file komizo writes, and the point of
	// trimming is that the file got big.
	ring := make([][]byte, n)
	count := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		b := make([]byte, len(sc.Bytes()))
		copy(b, sc.Bytes())
		ring[count%n] = b
		count++
	}
	err = sc.Err()
	f.Close()
	if err != nil {
		return err
	}

	start, total := 0, count
	if count > n {
		start, total = count%n, n
	}
	var buf []byte
	for i := 0; i < total; i++ {
		buf = append(buf, ring[(start+i)%n]...)
		buf = append(buf, '\n')
	}
	return writeFileAtomic(path, buf, 0o640)
}

// writeFileAtomic writes via a temp file in the same directory and renames.
//
// Same directory because rename is only atomic within one filesystem, and /tmp
// is frequently its own.
//
// IT CARRIES NO OWNERSHIP, and a caller whose file needs a non-root reader has
// to establish that itself. The temp is created by whatever account is running
// and chmodded to mode; group and owner are whatever the writer's are, not
// whatever the file being replaced had. Every caller today is root writing a
// root-owned file that only root reads, which is why this has never shown.
//
// It is worth stating because this codebase has already paid for the same
// assumption once. komizo#53: results were written root:root 0640 into a
// directory the serving account could list but not read, so every signed
// command succeeded on the machine and was reported to the operator as a
// failure -- after an eleven minute wait, whose obvious next move is to press
// the button again. Nothing logged it, because absent and unreadable were the
// same answer. The moment a file written through here acquires a reader that is
// not root, this function will take that reader's access away on the first
// rewrite and say nothing.
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	// Flushed before the rename. Without it a box that loses power between the
	// two comes back with a report.json that exists, is the right size, and is
	// full of zero bytes.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Now is the clock the box writes with, in UTC.
//
// UTC because these timestamps are compared against a laptop in another zone,
// and a duration computed across two zones is wrong by hours in a way that
// looks like a plausible uptime.
func Now() time.Time { return time.Now().UTC() }
