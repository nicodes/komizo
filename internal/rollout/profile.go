package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nicodes/komizo/internal/release"
)

var ErrNoPending = errors.New("profile has no pending rollout")

// Profile is the root-owned half of the per-application deployment broker.
// None of these values are accepted from CI: the generated deploy command may
// select only the profile installed for its own application.
type Profile struct {
	Version        int           `json:"version"`
	App            string        `json:"app"`
	Network        string        `json:"network"`
	KeyFile        string        `json:"key_file"`
	StateDir       string        `json:"state_dir"`
	GatewaySocket  string        `json:"gateway_socket"`
	GatewayConfig  string        `json:"gateway_config"`
	ComposeBinary  string        `json:"compose_binary"`
	ComposeVersion string        `json:"compose_version"`
	SecretFile     string        `json:"secret_file,omitempty"`
	Overall        time.Duration `json:"overall"`
	MinFreeMemory  uint64        `json:"min_free_memory_bytes"`
	MinFreeDisk    uint64        `json:"min_free_disk_bytes"`
	Limits         Limits        `json:"limits"`
}

type profileWire struct {
	Version        int    `json:"version"`
	App            string `json:"app"`
	Network        string `json:"network"`
	KeyFile        string `json:"key_file"`
	StateDir       string `json:"state_dir"`
	GatewaySocket  string `json:"gateway_socket"`
	GatewayConfig  string `json:"gateway_config"`
	ComposeBinary  string `json:"compose_binary"`
	ComposeVersion string `json:"compose_version"`
	SecretFile     string `json:"secret_file,omitempty"`
	Overall        string `json:"overall"`
	MinFreeMemory  uint64 `json:"min_free_memory_bytes"`
	MinFreeDisk    uint64 `json:"min_free_disk_bytes"`
	Limits         struct {
		Ready, Stabilize, Retire, Operation, Poll string
	} `json:"limits"`
}

func (p *Profile) UnmarshalJSON(data []byte) error {
	var wire profileWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return errors.New("invalid rollout profile")
	}
	parse := func(value string) (time.Duration, error) {
		d, err := time.ParseDuration(value)
		if err != nil || d <= 0 {
			return 0, errors.New("profile durations must be positive Go duration strings")
		}
		return d, nil
	}
	var err error
	p.Version, p.App, p.Network, p.KeyFile, p.StateDir = wire.Version, wire.App, wire.Network, wire.KeyFile, wire.StateDir
	p.GatewaySocket, p.GatewayConfig, p.ComposeBinary, p.ComposeVersion, p.SecretFile = wire.GatewaySocket, wire.GatewayConfig, wire.ComposeBinary, wire.ComposeVersion, wire.SecretFile
	p.MinFreeMemory, p.MinFreeDisk = wire.MinFreeMemory, wire.MinFreeDisk
	if p.Overall, err = parse(wire.Overall); err != nil {
		return err
	}
	for _, item := range []struct {
		value  string
		target *time.Duration
	}{
		{wire.Limits.Ready, &p.Limits.Ready}, {wire.Limits.Stabilize, &p.Limits.Stabilize},
		{wire.Limits.Retire, &p.Limits.Retire}, {wire.Limits.Operation, &p.Limits.Operation}, {wire.Limits.Poll, &p.Limits.Poll},
	} {
		if *item.target, err = parse(item.value); err != nil {
			return err
		}
	}
	return nil
}

func (p Profile) MarshalJSON() ([]byte, error) {
	wire := profileWire{Version: p.Version, App: p.App, Network: p.Network, KeyFile: p.KeyFile, StateDir: p.StateDir,
		GatewaySocket: p.GatewaySocket, GatewayConfig: p.GatewayConfig, ComposeBinary: p.ComposeBinary, ComposeVersion: p.ComposeVersion, SecretFile: p.SecretFile,
		Overall: p.Overall.String(), MinFreeMemory: p.MinFreeMemory, MinFreeDisk: p.MinFreeDisk}
	wire.Limits.Ready, wire.Limits.Stabilize, wire.Limits.Retire = p.Limits.Ready.String(), p.Limits.Stabilize.String(), p.Limits.Retire.String()
	wire.Limits.Operation, wire.Limits.Poll = p.Limits.Operation.String(), p.Limits.Poll.String()
	return json.Marshal(wire)
}

func LoadProfile(path string) (Profile, error) {
	var profile Profile
	if !filepath.IsAbs(path) {
		return profile, errors.New("rollout profile path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrent(info) || info.Size() > 64<<10 {
		return profile, errors.New("rollout profile must be a private bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return profile, errors.New("cannot open rollout profile")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return profile, errors.New("rollout profile changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, errors.New("invalid rollout profile")
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return Profile{}, err
	}
	if err := profile.Validate(); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("rollout profile must contain one JSON document")
	}
	return nil
}

func (p Profile) Validate() error {
	paths := []string{p.KeyFile, p.StateDir, p.GatewaySocket, p.GatewayConfig, p.ComposeBinary}
	if p.SecretFile != "" {
		paths = append(paths, p.SecretFile)
	}
	if p.Version != 1 || !scopeName(p.App) || !scopeName(p.Network) || p.ComposeVersion == "" || strings.ContainsAny(p.ComposeVersion, "\x00\r\n") ||
		p.Overall <= 0 || p.MinFreeMemory == 0 || p.MinFreeDisk == 0 || p.Limits.Ready <= 0 || p.Limits.Stabilize <= 0 || p.Limits.Retire <= p.Limits.Stabilize || p.Limits.Operation <= 0 || p.Limits.Poll <= 0 {
		return errors.New("rollout profile has invalid scope, version, tool version or budgets")
	}
	if slices.ContainsFunc(paths, func(path string) bool { return !filepath.IsAbs(path) }) {
		return errors.New("rollout profile paths must be absolute")
	}
	if filepath.Clean(p.GatewayConfig) != filepath.Join(filepath.Clean(p.StateDir), "gateway", "config.json") {
		return errors.New("gateway config must be the rollout journal's isolated gateway/config.json")
	}
	return nil
}

func (p Profile) run(ctx context.Context, source, key []byte) (Result, error) {
	store, err := OpenStore(ctx, p.StateDir, p.Limits.Poll)
	if err != nil {
		return Result{}, err
	}
	defer store.Close()
	return p.runWithStore(ctx, store, source, key)
}

func (p Profile) runWithStore(ctx context.Context, store *Store, source, key []byte) (Result, error) {
	versions := map[string]string{}
	if p.SecretFile != "" {
		var err error
		versions, err = readSecretVersions(p.SecretFile)
		if err != nil {
			return Result{}, err
		}
	}
	bound, err := release.BindSecretVersions(source, versions)
	if err != nil {
		return Result{}, err
	}
	defer clear(bound)
	router, err := NewGatewayClient(p.GatewaySocket)
	if err != nil {
		return Result{}, err
	}
	backend := &Docker{App: p.App, Network: p.Network, ComposeBinary: p.ComposeBinary, ComposeVersion: p.ComposeVersion, EnvFile: p.SecretFile, Store: store, MinFreeMemory: p.MinFreeMemory, MinFreeDisk: p.MinFreeDisk}
	return (&Engine{Store: store, Backend: backend, Router: router}).Run(ctx, p.App, p.Network, bound, key, p.Limits)
}

// RunProfile executes a model through values fixed in a root-owned profile.
// The model may come from an immutable config artifact; it supplies desired
// application state, never host paths, tools, credentials or execution limits.
func RunProfile(parent context.Context, profilePath, modelPath string) (Result, error) {
	profile, err := LoadProfile(profilePath)
	if err != nil {
		return Result{}, err
	}
	key, err := readInput(profile.KeyFile, 32, true)
	if err != nil {
		return Result{}, errors.New("profile identity key is unavailable or unsafe")
	}
	defer clear(key)
	source, err := readInput(modelPath, releaseModelLimit, false)
	if err != nil {
		return Result{}, errors.New("cannot read bounded normalized model")
	}
	defer clear(source)
	ctx, cancel := context.WithTimeout(parent, profile.Overall)
	defer cancel()
	return profile.run(ctx, source, key)
}

// ResumeProfile resumes only a recorded transaction. It never starts a new
// release from a mutable model path; the journaled source remains authoritative.
func ResumeProfile(parent context.Context, profilePath string) (Result, error) {
	profile, err := LoadProfile(profilePath)
	if err != nil {
		return Result{}, err
	}
	key, err := readInput(profile.KeyFile, 32, true)
	if err != nil {
		return Result{}, errors.New("profile identity key is unavailable or unsafe")
	}
	defer clear(key)
	ctx, cancel := context.WithTimeout(parent, profile.Overall)
	defer cancel()
	store, err := OpenStore(ctx, profile.StateDir, profile.Limits.Poll)
	if err != nil {
		return Result{}, err
	}
	defer store.Close()
	state, err := store.Load()
	if err != nil || state == nil || state.Pending == nil || state.App != profile.App {
		return Result{}, ErrNoPending
	}
	return profile.runWithStore(ctx, store, slices.Clone(state.Pending.Source), key)
}

// ReconcileProfiles gives rootd a bounded, fail-closed recovery pass. Profile
// discovery is intentionally flat and capped: a compromised writer cannot make
// root recurse through the host or schedule unbounded Docker work.
func ReconcileProfiles(parent context.Context, directory string, diagnostics io.Writer) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	if len(entries) > 128 {
		entries = entries[:128]
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		_, err := ResumeProfile(parent, filepath.Join(directory, entry.Name()))
		if err != nil && !errors.Is(err, ErrNoPending) {
			// Profiles and journals may contain private paths/configuration. Name
			// only the app profile file and the value-free executor error.
			_, _ = io.WriteString(diagnostics, "komizo-box: rollout reconciliation for "+entry.Name()+" stalled: "+err.Error()+"\n")
		}
	}
}

// Kept local so profile.go does not widen release's public input API.
const releaseModelLimit = 8 << 20

func readSecretVersions(path string) (map[string]string, error) {
	data, err := readPrivateRecord(path, 1<<20)
	if err != nil {
		return nil, errors.New("cannot read bounded secret materialization record")
	}
	defer clear(data)
	versions := map[string]string{}
	const prefix = "# komizo-secret-version-"
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		nameValue := strings.TrimPrefix(line, prefix)
		name, version, ok := strings.Cut(nameValue, "=")
		if !ok || !validSecretName(name) || len(version) != 32 || strings.ContainsFunc(version, func(c rune) bool { return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') }) {
			return nil, errors.New("invalid secret materialization version marker")
		}
		if _, duplicate := versions[name]; duplicate {
			return nil, errors.New("duplicate secret materialization version marker")
		}
		versions[name] = version
	}
	return versions, nil
}

func validSecretName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func readPrivateRecord(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrent(info) || info.Size() > limit {
		return nil, errors.New("invalid private record")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open private record")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("private record changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("invalid private record size")
	}
	return data, nil
}
