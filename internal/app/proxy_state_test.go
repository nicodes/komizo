package app

import (
	"flag"
	"testing"
)

// The gate is the box's, not the invocation's: passing the flag speaks,
// saying nothing keeps what the box was given before, and an explicit empty
// clears it. These run against a throwaway XDG_CONFIG_HOME, so no machine's
// real state is read or written.

func tlsAskFlagSet(t *testing.T, args ...string) (*flag.FlagSet, string) {
	t.Helper()
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	var v string
	fs.StringVar(&v, "tls-ask", "", "")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return fs, v
}

func TestPassingTLSAskIsRememberedForTheBox(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fs, v := tlsAskFlagSet(t, "--tls-ask", "https://gate.example.com/ask")

	got, err := resolveTLSAsk(fs, "box.example.com", v)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://gate.example.com/ask" {
		t.Errorf("the run did not carry the flag's value: %q", got)
	}
	state, err := readProxyState()
	if err != nil {
		t.Fatal(err)
	}
	if state.TLSAsk["box.example.com"] != "https://gate.example.com/ask" {
		t.Errorf("the gate was not stored for the box: %+v", state.TLSAsk)
	}
}

// The incident this file exists for: a re-run without the flag must still
// say the gate, because the wildcard routes it permits are still on the box.
func TestARerunWithoutTheFlagReemitsTheStoredGate(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fs, v := tlsAskFlagSet(t, "--tls-ask", "https://gate.example.com/ask")
	if _, err := resolveTLSAsk(fs, "box.example.com", v); err != nil {
		t.Fatal(err)
	}

	again, noFlag := tlsAskFlagSet(t)
	got, err := resolveTLSAsk(again, "box.example.com", noFlag)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://gate.example.com/ask" {
		t.Errorf("a re-run without --tls-ask dropped the gate: %q", got)
	}
}

func TestAnotherBoxKeepsItsOwnGate(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fs, v := tlsAskFlagSet(t, "--tls-ask", "https://gate.example.com/ask")
	if _, err := resolveTLSAsk(fs, "one.example.com", v); err != nil {
		t.Fatal(err)
	}

	other, noFlag := tlsAskFlagSet(t)
	got, err := resolveTLSAsk(other, "two.example.com", noFlag)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("a box that was never given a gate inherited another's: %q", got)
	}
}

func TestAnExplicitEmptyFlagClearsTheGate(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fs, v := tlsAskFlagSet(t, "--tls-ask", "https://gate.example.com/ask")
	if _, err := resolveTLSAsk(fs, "box.example.com", v); err != nil {
		t.Fatal(err)
	}

	clearing, empty := tlsAskFlagSet(t, "--tls-ask=")
	got, err := resolveTLSAsk(clearing, "box.example.com", empty)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("--tls-ask= did not clear the gate for this run: %q", got)
	}
	state, err := readProxyState()
	if err != nil {
		t.Fatal(err)
	}
	if _, still := state.TLSAsk["box.example.com"]; still {
		t.Errorf("--tls-ask= left the gate stored: %+v", state.TLSAsk)
	}

	// And it stays cleared: the next flagless re-run finds nothing to re-emit.
	again, noFlag := tlsAskFlagSet(t)
	got, err = resolveTLSAsk(again, "box.example.com", noFlag)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("a cleared gate came back on the next run: %q", got)
	}
}

func TestPassingTheFlagAgainReplacesTheStoredGate(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fs, v := tlsAskFlagSet(t, "--tls-ask", "https://old.example.com/ask")
	if _, err := resolveTLSAsk(fs, "box.example.com", v); err != nil {
		t.Fatal(err)
	}

	newer, nv := tlsAskFlagSet(t, "--tls-ask", "https://new.example.com/ask")
	got, err := resolveTLSAsk(newer, "box.example.com", nv)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://new.example.com/ask" {
		t.Errorf("the new value did not win: %q", got)
	}
	state, err := readProxyState()
	if err != nil {
		t.Fatal(err)
	}
	if state.TLSAsk["box.example.com"] != "https://new.example.com/ask" {
		t.Errorf("the stored gate was not replaced: %+v", state.TLSAsk)
	}
}

func TestAnInvalidFlagIsRefusedAndNothingIsStored(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fs, v := tlsAskFlagSet(t, "--tls-ask", "not-a-url")
	if _, err := resolveTLSAsk(fs, "box.example.com", v); err == nil {
		t.Fatal("a non-URL gate was accepted")
	}
	state, err := readProxyState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.TLSAsk) != 0 {
		t.Errorf("a refused value was stored anyway: %+v", state.TLSAsk)
	}
}
