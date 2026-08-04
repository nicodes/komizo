package app

import (
	"errors"
	"strings"
	"testing"
)

// A box nobody managed to read must not be described as a box with no komizo
// on it.
//
// serverRow's zero value is indistinguishable from a real answer:
// komizoInstalled false reads as "this server has never had komizo", which is
// what the interface said about every box whose FIRST poll failed. The moment
// that was most likely to happen was the refresh immediately after setup -- on
// a box that had just installed Docker and was still starting its agent -- so
// the report was "I set a server up and it says I still need to install it".

func TestAnUnreadBoxSaysSoRatherThanClaimingNoKomizo(t *testing.T) {
	m := newModel(target{user: "root", host: "box", port: 22})
	m.width, m.height = 100, 40

	// A poll that failed for any reason other than the box answering "no
	// agent" -- a dropped connection, a busy sshd, an agent still starting.
	next, _ := m.Update(appsMsg{err: errors.New("connection reset by peer")})
	m = next.(model)

	if m.srv.read {
		t.Fatal("a failed poll marked the server row as read")
	}
	line := stripANSI(m.komizoServerLine())
	if strings.Contains(line, "not installed") {
		t.Errorf("an unread box is described as having no komizo: %q", line)
	}
	if !strings.Contains(line, "not read") {
		t.Errorf("komizo row = %q, want it to say the box has not been read", line)
	}
	// And it must not offer the remedy for a problem it cannot see.
	if strings.Contains(line, "u to install") {
		t.Errorf("an unread box offers an install: %q", line)
	}
}

// The one error that IS an answer: exit 127 from the far end is the box saying
// there is no komizo on it. That belongs on the setup screen, which is what the
// README describes and what this used to skip -- it fell through to the index
// and rendered a page of zero values instead.
func TestABoxWithNoAgentGetsTheSetupScreen(t *testing.T) {
	m := newModel(target{user: "root", host: "box", port: 22})
	m.width, m.height = 100, 40

	next, _ := m.Update(appsMsg{err: errNoAgent{host: "box"}})
	m = next.(model)

	if m.scr != screenSetup {
		t.Errorf("screen = %v, want the setup screen for a box with no agent", m.scr)
	}
	if !m.srv.read {
		t.Error("a box that answered \"no agent\" was not marked as read -- that answer IS a reading")
	}

	// And it is not reported as a failure. The screen is headed "this server is
	// not set up yet" and offers start; a red footer repeating that, and naming
	// a CLI command to run in another terminal, is answering a question the
	// cursor is already sitting on.
	if m.err != nil {
		t.Errorf("the setup screen carries an error footer: %v", m.err)
	}
	body := stripANSI(m.View())
	if strings.Contains(body, "has no komizo agent installed") {
		t.Errorf("the setup screen repeats the no-agent error:\n%s", body)
	}
	if strings.Contains(body, "komizo init --host") {
		t.Errorf("the setup screen tells you to run the CLI instead of pressing start:\n%s", body)
	}
}

// A successful poll is what makes the row able to speak.
func TestAReadBoxStillReportsAMissingKomizo(t *testing.T) {
	m := newModel(target{user: "root", host: "box", port: 22})
	m.width, m.height = 100, 40

	next, _ := m.Update(appsMsg{srv: serverRow{state: "ready", read: true}})
	m = next.(model)

	line := stripANSI(m.komizoServerLine())
	if !strings.Contains(line, "not installed") {
		t.Errorf("komizo row = %q, want it to report a genuinely missing komizo", line)
	}
}

// The os row has the same shape of problem: osName() papers an empty value over
// with what komizo installs, which on an unread box names a distribution nobody
// has looked at.
func TestAnUnreadBoxDoesNotNameAnOperatingSystem(t *testing.T) {
	m := newModel(target{user: "root", host: "box", port: 22})
	m.width, m.height = 100, 40
	next, _ := m.Update(appsMsg{err: errors.New("connection reset by peer")})
	m = next.(model)

	body := stripANSI(m.boxSection())
	if strings.Contains(strings.ToLower(body), "alpine") {
		t.Errorf("an unread box names an OS:\n%s", body)
	}
}

// A poll that fails AFTER a good one keeps what it had -- one dropped
// connection must not blank a working page. The read flag has to survive that.
func TestALaterFailureKeepsTheLastGoodReading(t *testing.T) {
	m := newModel(target{user: "root", host: "box", port: 22})
	m.width, m.height = 100, 40

	next, _ := m.Update(appsMsg{srv: serverRow{state: "ready", os: "Alpine Linux v3.20",
		komizoInstalled: true, komizoVersion: "0.0.15", read: true}})
	m = next.(model)
	next, _ = m.Update(appsMsg{err: errors.New("connection reset by peer")})
	m = next.(model)

	if !m.srv.read {
		t.Fatal("a later failure discarded the last good reading")
	}
	if line := stripANSI(m.komizoServerLine()); strings.Contains(line, "not read") {
		t.Errorf("komizo row = %q, want the last good reading kept", line)
	}
}
