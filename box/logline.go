package box

import "strings"

// The collected log's line format.
//
// nicodes/komizo-be#165. `docker compose logs` prefixes every line with the
// CONTAINER name and a pipe -- "blog-web-1  | started" -- and komizo stored that
// verbatim. Two things are wrong with it as a record of which service said what:
//
// THE PREFIX FORMAT VARIES BY COMPOSE VERSION. Found in review of komizo#82:
// 5.0.0 writes "gate-1  |" where 5.1.4 writes "web-gate-1  |" for the same
// stack. Anything joining on it is parsing a string whose shape depends on a
// version of docker nobody here chose.
//
// AND A CONTAINER NAME IS NOT A SERVICE NAME. The join from one to the other is
// "strip the project prefix and the replica suffix", which is a guess -- an app
// whose service is called "web-1" is indistinguishable from replica 1 of "web".
//
// So the collector asks compose which container is which service, exactly, and
// writes the SERVICE into each line. This is a breaking change to what
// `komizo logs` prints and what the app renders, which is why the reader below
// accepts both forms rather than assuming its own.

// logSep separates a line's service from its message.
//
// A TAB, because compose forbids one in a service name -- so the split on the
// first tab cannot be ambiguous, and a message containing tabs keeps them. A
// pipe would have collided with compose's own prefix, which is exactly the
// string this exists to stop parsing.
const logSep = "\t"

// LogLine is one collected line: which service said it, and what it said.
type LogLine struct {
	// Service is empty when the line predates this format, or came from a
	// source that has no services. Empty is "not recorded", never "the service
	// with no name" -- see ParseLog.
	Service string
	Text    string
}

// FormatLog writes lines in the stored form.
func FormatLog(lines []LogLine) string {
	var b strings.Builder
	for _, l := range lines {
		if l.Service != "" {
			b.WriteString(l.Service)
			b.WriteString(logSep)
		}
		b.WriteString(l.Text)
		b.WriteString("\n")
	}
	return b.String()
}

// ParseLog reads the stored form, and reads the OLD form too.
//
// BOTH, DELIBERATELY. A box collects on a fifteen-second timer and komizo is
// updated by a person, so between the two there is a window in which the file
// holds lines written by the previous version -- and the tail a reader asks for
// spans it. A parser that assumed the new shape would render the old lines as a
// service called "blog-web-1  | started" with no message.
//
// A line with no separator is a line whose service was not recorded. That is
// reported as empty rather than guessed at from a container name, because
// guessing is what this format exists to stop.
func ParseLog(s string) []LogLine {
	var out []LogLine
	for _, ln := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if ln == "" {
			continue
		}
		svc, text, ok := strings.Cut(ln, logSep)
		if !ok {
			out = append(out, LogLine{Text: ln})
			continue
		}
		out = append(out, LogLine{Service: svc, Text: text})
	}
	return out
}

// FilterLog keeps the lines one service said.
//
// An UNRECORDED service is not a match for anything: a caller asking for "web"
// must not be handed lines from before the service was recorded, because it
// cannot tell whether they are web's. Silence is the honest answer and the
// route says so separately.
func FilterLog(lines []LogLine, service string) []LogLine {
	if service == "" {
		return lines
	}
	out := make([]LogLine, 0, len(lines))
	for _, l := range lines {
		if l.Service == service {
			out = append(out, l)
		}
	}
	return out
}

// LogServices is every service the lines name, in the order they first appear.
//
// First-appearance order rather than sorted: it is the order the stack started
// in, which is the order somebody reading a log already has in their head.
func LogServices(lines []LogLine) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lines {
		if l.Service == "" || seen[l.Service] {
			continue
		}
		seen[l.Service] = true
		out = append(out, l.Service)
	}
	return out
}
