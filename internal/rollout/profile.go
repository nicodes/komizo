package rollout

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nicodes/komizo/internal/gateway"
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

type provisionRoots struct {
	Profiles string
	Keys     string
	States   string
	Gateways string
}

var systemProvisionRoots = provisionRoots{
	Profiles: "/etc/komizo/rollouts",
	Keys:     "/etc/komizo/rollout-keys",
	States:   "/var/lib/komizo/rollouts",
	Gateways: "/run/komizo/gateways",
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

func (p Profile) validateProvisionScope(app string, roots provisionRoots) error {
	if p.App != app || p.KeyFile != filepath.Join(roots.Keys, app+".key") ||
		p.StateDir != filepath.Join(roots.States, app) ||
		p.GatewaySocket != filepath.Join(roots.Gateways, app, "admin.sock") ||
		p.GatewayConfig != filepath.Join(roots.States, app, "gateway", "config.json") {
		return errors.New("rollout profile authority paths are not scoped to this application")
	}
	return nil
}

func ensureProvisionDir(path string, private bool) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return errors.New("cannot create rollout authority directory")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || !ownedByCurrent(info) || info.Mode()&os.ModeSymlink != 0 ||
		(private && info.Mode().Perm()&0o077 != 0) || (!private && info.Mode().Perm()&0o022 != 0) {
		return errors.New("rollout authority directory is not safely owned")
	}
	return nil
}

func installPrivateFile(path string, data []byte) error {
	temporary := filepath.Join(filepath.Dir(path), ".next-"+filepath.Base(path)+"-"+rand.Text())
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("cannot create private rollout authority file")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return errors.New("cannot write private rollout authority file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("cannot synchronize private rollout authority file")
	}
	if err := file.Close(); err != nil {
		return errors.New("cannot close private rollout authority file")
	}
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return errors.New("cannot remove rollout authority staging file")
	}
	ok = true
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("cannot open rollout authority directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("cannot synchronize rollout authority directory")
	}
	return nil
}

// ProvisionProfile installs only new app-scoped rollout authority. It does not
// start a gateway, alter application files, inspect containers or cut traffic.
// Existing policy is accepted only when semantically identical after strict
// profile decoding; changing any budget/path is a separate owner decision.
func ProvisionProfile(source, app string) error {
	return provisionProfile(source, app, systemProvisionRoots)
}

func provisionProfile(source, app string, roots provisionRoots) error {
	p, err := LoadProfile(source)
	if err != nil {
		return err
	}
	if err := p.validateProvisionScope(app, roots); err != nil {
		return err
	}
	profilePath := filepath.Join(roots.Profiles, app+".json")
	if _, statErr := os.Lstat(profilePath); statErr == nil {
		existing, err := LoadProfile(profilePath)
		if err != nil {
			return errors.New("installed rollout profile is unsafe; refusing replacement")
		}
		if existing != p {
			return errors.New("installed rollout profile differs; refusing to replace owner policy")
		}
		return nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("cannot inspect installed rollout profile")
	}
	for _, item := range []struct {
		path    string
		private bool
	}{
		{roots.Profiles, true}, {roots.Keys, true}, {roots.States, false},
		{p.StateDir, true}, {filepath.Dir(p.GatewayConfig), true},
		{roots.Gateways, false}, {filepath.Dir(p.GatewaySocket), true},
	} {
		if err := ensureProvisionDir(item.path, item.private); err != nil {
			return err
		}
	}
	if _, err := readInput(p.KeyFile, 32, true); err != nil {
		if _, statErr := os.Lstat(p.KeyFile); statErr == nil {
			return errors.New("existing rollout identity key is unsafe")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return errors.New("cannot generate rollout identity key")
		}
		defer clear(key)
		if err := installPrivateFile(p.KeyFile, key); err != nil {
			return errors.New("cannot install rollout identity key")
		}
	}
	if _, err := os.Lstat(p.GatewayConfig); errors.Is(err, os.ErrNotExist) {
		body := []byte(`{"app":"` + app + `","generation":"bootstrap","routes":[]}`)
		if err := installPrivateFile(p.GatewayConfig, body); err != nil {
			return errors.New("cannot initialize rollout gateway configuration")
		}
	} else if err != nil {
		return errors.New("cannot inspect rollout gateway configuration")
	} else {
		info, statErr := os.Lstat(p.GatewayConfig)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrent(info) {
			return errors.New("existing rollout gateway configuration is unsafe")
		}
		file, openErr := os.Open(p.GatewayConfig)
		if openErr != nil {
			return errors.New("cannot open rollout gateway configuration")
		}
		opened, openedErr := file.Stat()
		if openedErr != nil || !os.SameFile(info, opened) {
			file.Close()
			return errors.New("rollout gateway configuration changed while opening")
		}
		config, decodeErr := gateway.Decode(io.LimitReader(file, gateway.MaxConfigBytes+1))
		file.Close()
		if decodeErr != nil || config.App != app {
			return errors.New("existing rollout gateway configuration is invalid")
		}
	}
	body, err := json.Marshal(p)
	if err != nil {
		return errors.New("cannot encode rollout profile")
	}
	body = append(body, '\n')
	if err := installPrivateFile(profilePath, body); err != nil {
		return errors.New("cannot install rollout profile")
	}
	return nil
}

// CheckProfile proves the complete host-side capability before CI publishes an
// artifact or rotates a secret. It deliberately applies the profile's current
// capacity floor; a low-capacity host refuses before any deployment mutation.
func CheckProfile(parent context.Context, profilePath, app string) error {
	p, err := LoadProfile(profilePath)
	if err != nil || p.App != app {
		return errors.New("rollout profile is unavailable or belongs to another application")
	}
	if err := p.validateProvisionScope(app, systemProvisionRoots); err != nil {
		return err
	}
	key, err := readInput(p.KeyFile, 32, true)
	if err != nil {
		return errors.New("rollout identity key is unavailable or unsafe")
	}
	clear(key)
	ctx, cancel := context.WithTimeout(parent, p.Limits.Operation)
	defer cancel()
	store, err := OpenStore(ctx, p.StateDir, p.Limits.Poll)
	if err != nil {
		return err
	}
	defer store.Close()
	backend := &Docker{App: p.App, Network: p.Network, ComposeBinary: p.ComposeBinary, ComposeVersion: p.ComposeVersion,
		Store: store, MinFreeMemory: p.MinFreeMemory, MinFreeDisk: p.MinFreeDisk}
	if err := backend.Preflight(ctx, p.App, p.Network); err != nil {
		return err
	}
	router, err := NewGatewayClient(p.GatewaySocket)
	if err != nil {
		return err
	}
	config, _, err := router.Current(ctx)
	if err != nil || config.App != app {
		return errors.New("application rollout gateway is not ready")
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
