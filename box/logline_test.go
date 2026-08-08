package box

import (
	"strings"
	"testing"
)

// A LINE REMEMBERS WHICH SERVICE SAID IT.
//
// nicodes/komizo-be#165. What was stored was `docker compose logs` verbatim,
// which prefixes each line with the CONTAINER name -- and review of komizo#82
// found that prefix's format varies by compose version: 5.0.0 writes "gate-1  |"
// where 5.1.4 writes "web-gate-1  |" for the same stack. Anything joining on it
// is parsing a string whose shape depends on a version of docker nobody chose.

func TestALineCarriesTheServiceThatSaidIt(t *testing.T) {
	stored := FormatLog([]LogLine{
		{Service: "web", Text: "listening on 8080"},
		{Service: "worker", Text: "picked up job 3"},
	})
	got := ParseLog(stored)

	if len(got) != 2 {
		t.Fatalf("round trip gave %d lines, want 2: %q", len(got), stored)
	}
	if got[0].Service != "web" || got[0].Text != "listening on 8080" {
		t.Errorf("first line = %+v", got[0])
	}
	if got[1].Service != "worker" {
		t.Errorf("second line lost its service: %+v", got[1])
	}
}

// A MESSAGE MAY CONTAIN THE SEPARATOR AND KEEPS IT.
//
// Logs are full of tabs -- a stack trace, a table, anything Go's tabwriter
// produced upstream. Splitting on every tab rather than the first would cut a
// message in half and hand the second half to nothing.
func TestATabInsideAMessageSurvives(t *testing.T) {
	line := "GET /x\t200\t12ms"
	got := ParseLog(FormatLog([]LogLine{{Service: "web", Text: line}}))

	if len(got) != 1 {
		t.Fatalf("want one line, got %d", len(got))
	}
	if got[0].Service != "web" {
		t.Errorf("service = %q, want web", got[0].Service)
	}
	if got[0].Text != line {
		t.Errorf("message = %q, want %q -- the split took more than the first tab", got[0].Text, line)
	}
}

// THE OLD FORMAT STILL READS, and this is the case that decides whether an
// upgrade is visible to anyone.
//
// A box collects every fifteen seconds and komizo is updated by a person, so
// between the two there is a window where the file holds lines written by the
// previous version -- and the tail a reader asks for spans it. A parser that
// assumed the new shape would render those as a service named
// "blog-web-1  | started" with no message.
func TestLinesFromBeforeThisFormatAreStillLines(t *testing.T) {
	old := "blog-web-1  | listening on 8080\nblog-worker-1  | picked up job 3\n"
	got := ParseLog(old)

	if len(got) != 2 {
		t.Fatalf("want two lines, got %d", len(got))
	}
	for _, l := range got {
		if l.Service != "" {
			t.Errorf("a line from the old format claimed a service %q -- guessed from a "+
				"container name, which is what this format exists to stop", l.Service)
		}
		if !strings.Contains(l.Text, "|") {
			t.Errorf("the old line lost its content: %q", l.Text)
		}
	}
}

// AND AN UNRECORDED SERVICE MATCHES NOTHING.
//
// A caller asking for "web" must not be handed lines from before the service
// was recorded, because neither it nor the box can tell whether they are web's.
// Silence is the honest answer; the route reports the available services
// separately so a reader can see there are none.
func TestFilteringNeverGuessesAtAnUnrecordedService(t *testing.T) {
	lines := ParseLog("blog-web-1  | from before\nweb\tfrom after\n")

	got := FilterLog(lines, "web")
	if len(got) != 1 {
		t.Fatalf("filtering gave %d lines, want only the recorded one: %+v", len(got), got)
	}
	if got[0].Text != "from after" {
		t.Errorf("filter matched a line whose service was never recorded: %+v", got[0])
	}
}

// AN EMPTY FILTER IS NOT A FILTER. "" is how a caller says "the whole app", and
// treating it as a service name would answer every request with nothing.
func TestNoServiceMeansTheWholeApp(t *testing.T) {
	lines := ParseLog("web\ta\nworker\tb\nunprefixed\n")
	if got := FilterLog(lines, ""); len(got) != 3 {
		t.Errorf("asking for the whole app returned %d of 3 lines", len(got))
	}
}

func TestTheServicesAreTheOnesTheLinesName(t *testing.T) {
	lines := ParseLog("web\ta\nworker\tb\nweb\tc\nsomething unprefixed\n")
	got := LogServices(lines)

	// FIRST-APPEARANCE ORDER, which is the order the stack started in and the
	// order somebody reading the log already has in their head.
	if strings.Join(got, ",") != "web,worker" {
		t.Errorf("services = %v, want [web worker] -- deduplicated, in the order they spoke", got)
	}
}

// A LOG WITH NO SERVICES REPORTS NONE, rather than reporting one called "".
// The empty string is "not recorded" everywhere else here and cannot become a
// choice a reader is offered.
func TestALogWithNoRecordedServicesOffersNoChoice(t *testing.T) {
	if got := LogServices(ParseLog("blog-web-1  | a\nblog-web-1  | b\n")); len(got) != 0 {
		t.Errorf("services = %v, want none", got)
	}
}
