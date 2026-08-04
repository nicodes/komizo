package box

import "testing"

// Which boxes can serve the app, decided once.
//
// The rule is a certificate: a name can carry a real one, an IP cannot, and a
// box that cannot carry one is readable by the CLI and invisible to the app.

func TestAnIPAddressIsNotAnEndpoint(t *testing.T) {
	for _, ip := range []string{
		"203.0.113.10",
		"::1",
		"2001:db8::1",
		"[2001:db8::1]",
	} {
		if !IsIPAddress(ip) {
			t.Errorf("%q was not recognised as an IP address", ip)
		}
		if err := ValidateAPIHost(ip); err == nil {
			t.Errorf("%q was accepted as an endpoint", ip)
		}
	}
}

// The IPv6 case is why this asks net.ParseIP rather than looking at the string:
// a rule about dots and digits calls "2001:db8::1" a hostname.
func TestANameIsNotMistakenForAnAddress(t *testing.T) {
	for _, name := range []string{"komizo.example.com", "a-box.example.co.uk"} {
		if IsIPAddress(name) {
			t.Errorf("%q was mistaken for an IP address", name)
		}
		if err := ValidateAPIHost(name); err != nil {
			t.Errorf("ValidateAPIHost(%q) = %v", name, err)
		}
	}
}

// A bare label cannot be issued for publicly either, and would become the same
// self-signed case without saying so.
func TestABareLabelIsRefused(t *testing.T) {
	for _, s := range []string{"box", "localhost", ""} {
		if err := ValidateAPIHost(s); err == nil {
			t.Errorf("%q was accepted as an endpoint", s)
		}
	}
}

func TestTheEndpointDefaultsToTheNameYouConnectedTo(t *testing.T) {
	got, err := APIHostFor("komizo.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "komizo.example.com" {
		t.Errorf("endpoint = %q, want the SSH host -- reaching a box by name means a record points at it", got)
	}
}

// Not a failure. A box addressed by an IP reports normally and the CLI reads it
// normally; it simply has no endpoint, and the caller says so out loud.
func TestAnIPTargetDefaultsToNoEndpointRatherThanAnError(t *testing.T) {
	got, err := APIHostFor("203.0.113.10", "")
	if err != nil {
		t.Fatalf("an IP target should not be an error, got %v", err)
	}
	if got != "" {
		t.Errorf("endpoint = %q, want none", got)
	}
}

// The override wins, and IS checked -- a value somebody typed is the one most
// worth refusing early, because it lands in a route on the SHARED proxy.
func TestAnOverrideWinsAndIsStillChecked(t *testing.T) {
	got, err := APIHostFor("203.0.113.10", "komizo.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "komizo.example.com" {
		t.Errorf("endpoint = %q, want the override", got)
	}

	if _, err := APIHostFor("komizo.example.com", "203.0.113.10"); err == nil {
		t.Error("an IP override was accepted")
	}
}
