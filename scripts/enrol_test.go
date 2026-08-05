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

// The route that makes a box readable from the app.
//
// Written into the SHARED proxy, which is what makes every check around it
// matter: a config Caddy will not load is every app on the box, not just this
// one.
func TestEnrolPublishesTheBoxWhenItHasAName(t *testing.T) {
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_x", "komizo.example.com")

	for _, want := range []string{
		// The upstream is the socket, so nothing new listens on the network.
		"reverse_proxy unix/",
		// One origin, never a wildcard.
		`Access-Control-Allow-Origin "https://app.komizo.dev"`,
		// The preflight, without which a request carrying Authorization never
		// happens and the console says only that it was blocked.
		"@preflight method OPTIONS",
		// Validated before reloading, because the proxy is shared.
		"caddy validate",
		// And refused outright if an app already claims the name.
		"already served by an app",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the enrol script is missing %q", want)
		}
	}
}

// A box with no endpoint publishes nothing. There is nothing to publish, and a
// route for an empty hostname is a Caddyfile that will not load.
func TestEnrolPublishesNothingWithoutAName(t *testing.T) {
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_x", "")
	if !strings.Contains(got, "API_HOST=''") {
		t.Errorf("an empty endpoint did not reach the script as empty:\n%s", got)
	}
	// The guard is what stops it writing a route: the block is there, the
	// condition is what decides.
	if !strings.Contains(got, `[ -n "$API_HOST" ]`) {
		t.Error("the route is written without checking there is a hostname to write")
	}
}

// Un-enrolling takes the route with the credential. A box still publishing its
// endpoint afterwards is announcing that there is a komizo box here, which is
// itself an answer.
func TestUnenrolWithdrawsTheRoute(t *testing.T) {
	got := AgentUnenrol()
	if !strings.Contains(got, "_komizo.caddy") {
		t.Error("un-enrolling leaves the route published")
	}
}
