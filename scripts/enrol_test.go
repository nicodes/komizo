package scripts

import (
	"strings"
	"testing"
)

// The enrolment script, and the endpoint it now carries.
//
// A placeholder that is not substituted survives into the shell as the literal
// __API_HOST__, which reaches komizo-box as a hostname and is refused there --
// after the token has already been spent. That is a single-use credential lost
// to a templating mistake, which is why this checks the rendered text rather
// than trusting the substitution table.

func TestEnrolCarriesTheEndpoint(t *testing.T) {
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_abc", "komizo.example.com")

	if strings.Contains(got, "__API_HOST__") {
		t.Error("__API_HOST__ was left unsubstituted")
	}
	if !strings.Contains(got, "--api-host 'komizo.example.com'") {
		t.Errorf("the endpoint did not reach the command line:\n%s", got)
	}
}

// No endpoint is a supported state, not an omission: a box addressed by an IP
// reports normally and is read over SSH. The flag still has to arrive, with an
// empty value, or the box would fall back to a default this side already
// decided against.
func TestAnEmptyEndpointIsStillPassed(t *testing.T) {
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_abc", "")

	if strings.Contains(got, "__API_HOST__") {
		t.Error("__API_HOST__ was left unsubstituted")
	}
	if !strings.Contains(got, "--api-host ''") {
		t.Errorf("an empty endpoint did not reach the command line:\n%s", got)
	}
}

// Shell-quoted like everything else here. The endpoint comes from a flag, and a
// value with a space or a quote in it would otherwise become extra arguments to
// a command running as root on somebody's server.
func TestTheEndpointIsShellQuoted(t *testing.T) {
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_abc", "a'b c")
	if strings.Contains(got, "--api-host a'b c") {
		t.Errorf("the endpoint reached the shell unquoted:\n%s", got)
	}
}
