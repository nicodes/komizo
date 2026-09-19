package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// What `komizo proxy` remembers about each box, held on this machine.
//
// --tls-ask is a SERVER setting that outlives the command that set it: the
// wildcard routes it gates stay on the box, so a later re-run without the
// flag must still say it. Forgetting it once rewrote a box's Caddyfile
// without the on-demand gate while a route still needed one -- a config
// Caddy refuses to load, one restart from every site on the box going dark.
// The script now refuses that rewrite on its own; this file is what makes
// the plain re-run carry the gate rather than depending on the refusal.
type proxyState struct {
	// TLSAsk is the on-demand gate per box, keyed by target.hostDisplay():
	// the host, with the port when it is not 22.
	TLSAsk map[string]string `json:"tlsAsk"`
}

// proxyStatePath is where it lives: beside the session, which is the one
// other thing komizo holds on this machine.
func proxyStatePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "proxy.json"), nil
}

// readProxyState loads it, or returns the zero value.
//
// A missing file is not an error: it is a machine that has never given a box
// an on-demand gate, which is the normal state of every box without a
// wildcard hostname.
func readProxyState() (proxyState, error) {
	path, err := proxyStatePath()
	if err != nil {
		return proxyState{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return proxyState{}, nil
		}
		return proxyState{}, err
	}
	var s proxyState
	if err := json.Unmarshal(b, &s); err != nil {
		return proxyState{}, fmt.Errorf("%s is not readable as proxy state: %w", path, err)
	}
	return s, nil
}

// writeProxyState stores it, with the same care as the session beside it:
// 0600 in a 0700 directory, written to a temp file and moved so a crash
// halfway through leaves the previous state rather than a truncated one.
func writeProxyState(s proxyState) error {
	path, err := proxyStatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// resolveTLSAsk decides which on-demand gate this run of `komizo proxy`
// carries, and records the decision.
//
// The flag PASSED -- including passed empty -- is the operator speaking:
// a value is stored for the box, an explicit `--tls-ask=` clears it. The
// flag ABSENT means the box keeps what it had: the stored value is
// re-emitted, so re-running to update Caddy or move networks cannot drop
// the gate a wildcard route still needs. key is target.hostDisplay().
func resolveTLSAsk(fs *flag.FlagSet, key, flagValue string) (string, error) {
	if !tlsAskWasSet(fs) {
		state, err := readProxyState()
		if err != nil {
			return "", err
		}
		return state.TLSAsk[key], nil
	}
	if err := validateTLSAsk(flagValue); err != nil {
		return "", err
	}
	state, err := readProxyState()
	if err != nil {
		return "", err
	}
	if state.TLSAsk == nil {
		state.TLSAsk = map[string]string{}
	}
	if flagValue == "" {
		delete(state.TLSAsk, key)
	} else {
		state.TLSAsk[key] = flagValue
	}
	if err := writeProxyState(state); err != nil {
		return "", err
	}
	return flagValue, nil
}

// tlsAskWasSet reports whether --tls-ask appeared on the command line, as
// opposed to sitting at its default -- the distinction between "keep the
// box's gate" and "clear it". Same shape as portWasSet.
func tlsAskWasSet(fs *flag.FlagSet) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "tls-ask" {
			set = true
		}
	})
	return set
}
