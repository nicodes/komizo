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
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_abc", "komizo.example.com", nil, false)

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
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_abc", "", nil, false)

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
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_abc", "a'b c", nil, false)
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
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_x", "komizo.example.com", nil, false)

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
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_x", "", nil, false)
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

// The keys reach the box as repeated flags, quoted like everything else here.
//
// Repeated rather than one delimited value, so the box parses exactly what was
// passed and there is no separator for the two ends to disagree about.
func TestEnrolCarriesTheDeviceKeys(t *testing.T) {
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_x", "komizo.example.com",
		[]string{"kmz_dev_aaa", "kmz_dev_bbb"}, false)
	cmd := enrolCommand(t, got)
	for _, want := range []string{"--device-key 'kmz_dev_aaa'", "--device-key 'kmz_dev_bbb'"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("the script does not carry %s", want)
		}
	}
}

// A box nobody named a device for gets a clean command line rather than an
// empty flag, which the box would refuse.
//
// Asserted against the COMMAND rather than the whole script: the comment above
// it names the flag too, and a test that reads a comment is a test that passes
// for the wrong reason.
func TestEnrolWithNoDeviceKeysPassesNoFlag(t *testing.T) {
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_x", "", nil, false)
	if strings.Contains(enrolCommand(t, got), "--device-key") {
		t.Error("a --device-key flag was rendered with nothing to put in it")
	}
	if strings.Contains(got, "__DEVICE_KEYS__") {
		t.Error("the placeholder was left in the script")
	}
}

// enrolCommand is the line that actually runs the agent.
func enrolCommand(t *testing.T, script string) string {
	t.Helper()
	for _, ln := range strings.Split(script, "\n") {
		if strings.HasPrefix(ln, "/usr/local/bin/komizo-box enrol") {
			return ln
		}
	}
	t.Fatal("the script never runs `komizo-box enrol`")
	return ""
}

// Shell-quoted, because these come from a caller. The argument ShQuote carries
// everywhere else in this package does not stop applying because a value
// happens to look like base64.
func TestEnrolQuotesADeviceKey(t *testing.T) {
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_x", "", []string{"a'b; rm -rf /"}, false)
	if strings.Contains(got, "; rm -rf /") && !strings.Contains(got, `'a'\''b; rm -rf /'`) {
		t.Errorf("a device key reached the script unquoted:\n%s", got)
	}
}

// A device key is a VALUE, and values are not placeholders.
//
// base64url includes uppercase letters and the underscore, so a key can contain
// something shaped exactly like __BC__. Checking the rendered output for
// leftover placeholders made that crash the CLI claiming a komizo bug -- on a
// value an operator pasted, which is the least appropriate moment to blame the
// tool.
func TestADeviceKeyThatLooksLikeAPlaceholderDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a device key containing a placeholder-shaped substring panicked: %v", r)
		}
	}()
	got := AgentEnrol("https://api.komizo.dev", "kmz_enr_x", "", []string{"kmz_dev_a__BC__d"}, false)
	if !strings.Contains(got, "__BC__") {
		t.Error("the key did not reach the script")
	}
}

// And a placeholder nobody passed is still a bug that fails loudly.
func TestAForgottenPlaceholderStillPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a template with an unsubstituted placeholder rendered quietly")
		}
	}()
	render("hello __NOBODY_PASSED_THIS__", "__X__", "y")
}
