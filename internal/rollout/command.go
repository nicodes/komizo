package rollout

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"github.com/nicodes/komizo/internal/release"
)

// Command is an operator-only local Docker operation, not a signed box command
// and not a new privilege grant for CI deploy accounts.
func Command(parent context.Context, args []string, output, diagnostics io.Writer) error {
	if len(args) != 0 && args[0] == "profile" {
		return profileCommand(parent, args[1:], output, diagnostics)
	}
	if len(args) != 0 && args[0] == "status" {
		return statusCommand(parent, args[1:], output, diagnostics)
	}
	flags := flag.NewFlagSet("rollout", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	abort := flags.Bool("abort", false, "cancel a recorded pre-switch rollout only")
	app := flags.String("app", "", "authorized application scope")
	network := flags.String("network", "", "existing owned internal application network")
	modelPath := flags.String("model", "", "canonical Compose JSON with x-komizo metadata")
	keyPath := flags.String("key-file", "", "private 32-byte identity key")
	statePath := flags.String("state-dir", "", "operator-private persistent rollout directory")
	socket := flags.String("gateway-socket", "", "operator-private gateway admin socket")
	compose := flags.String("compose-bin", "", "absolute path to standalone Compose binary")
	version := flags.String("compose-version", "", "exact expected Compose version")
	budget := flags.Duration("timeout", 0, "overall rollout timeout")
	var limits Limits
	flags.DurationVar(&limits.Ready, "ready-timeout", 0, "candidate readiness budget")
	flags.DurationVar(&limits.Operation, "operation-timeout", 0, "individual executor operation budget")
	flags.DurationVar(&limits.Stabilize, "stabilize", 0, "post-switch health observation duration")
	flags.DurationVar(&limits.Retire, "retire-timeout", 0, "retirement budget starting at switch")
	flags.DurationVar(&limits.Poll, "poll", 0, "readiness/drain polling interval")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errors.New("invalid rollout flags")
	}
	if flags.NArg() != 0 || !scopeName(*app) || !scopeName(*network) || *keyPath == "" ||
		!filepath.IsAbs(*statePath) || !filepath.IsAbs(*socket) || *budget <= 0 || limits.Operation <= 0 || limits.Poll <= 0 ||
		(!*abort && (*modelPath == "" || !filepath.IsAbs(*compose) || *version == "" || limits.Ready <= 0 || limits.Stabilize <= 0 || limits.Retire <= limits.Stabilize)) {
		return errors.New("rollout requires explicit scope, model/key/state/socket/tool paths and positive budgets; retire-timeout must exceed stabilize")
	}
	key, err := readInput(*keyPath, 32, true)
	if err != nil {
		return errors.New("identity key must be a private regular 32-byte file")
	}
	defer clear(key)
	var source []byte
	if !*abort {
		source, err = readInput(*modelPath, release.MaxModelBytes, false)
		if err != nil {
			return errors.New("cannot read bounded normalized model")
		}
	}
	defer clear(source)
	// Validate before any journal directories or external processes are created.
	if !*abort {
		model, err := release.Resolve(source, key)
		if err != nil {
			return err
		}
		if err := model.CheckApp(*app); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(parent, *budget)
	defer cancel()
	store, err := OpenStore(ctx, *statePath, limits.Poll)
	if err != nil {
		return err
	}
	defer store.Close()
	router, err := NewGatewayClient(*socket)
	if err != nil {
		return err
	}
	backend := &Docker{App: *app, Network: *network, ComposeBinary: *compose, ComposeVersion: *version, Store: store}
	engine := Engine{Store: store, Backend: backend, Router: router}
	var result Result
	var runErr error
	if *abort {
		result, runErr = engine.Abort(ctx, *app, key, limits.Operation)
	} else {
		result, runErr = engine.Run(ctx, *app, *network, source, key, limits)
	}
	if runErr != nil {
		return runErr
	}
	return json.NewEncoder(output).Encode(result)
}

func profileCommand(parent context.Context, args []string, output, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("rollout profile", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	profilePath := flags.String("profile", "", "root-owned application rollout profile")
	modelPath := flags.String("model", "", "normalized model from the immutable config artifact")
	resume := flags.Bool("resume", false, "resume the profile's pending journaled transaction")
	check := flags.Bool("check", false, "verify complete host capability without changing application state")
	provision := flags.Bool("provision", false, "install new app-scoped authority without starting a gateway")
	app := flags.String("app", "", "fixed application scope for check/provision")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errors.New("invalid rollout profile flags")
	}
	modes := 0
	for _, selected := range []bool{*resume, *modelPath != "", *check, *provision} {
		if selected {
			modes++
		}
	}
	if flags.NArg() != 0 || *profilePath == "" || modes != 1 || ((*check || *provision) && !scopeName(*app)) || (*resume && *app != "" && !scopeName(*app)) {
		return errors.New("profile rollout requires --profile and exactly one operation; check/provision also require app")
	}
	if *provision {
		return ProvisionProfile(*profilePath, *app)
	}
	if *check {
		return CheckProfile(parent, *profilePath, *app)
	}
	var result Result
	var err error
	if *resume {
		if *app == "" {
			result, err = ResumeProfile(parent, *profilePath)
		} else {
			result, err = ResumeProfileForApp(parent, *profilePath, *app)
		}
	} else {
		result, err = RunProfile(parent, *profilePath, *modelPath)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}

func statusCommand(parent context.Context, args []string, output, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("rollout status", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	app := flags.String("app", "", "application scope")
	directory := flags.String("state-dir", "", "private journal directory")
	budget := flags.Duration("timeout", 0, "lock/read timeout")
	poll := flags.Duration("poll", 0, "lock polling interval")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errors.New("invalid status flags")
	}
	if flags.NArg() != 0 || !scopeName(*app) || !filepath.IsAbs(*directory) || *budget <= 0 || *poll <= 0 {
		return errors.New("status requires app, absolute state directory and positive timeout/poll")
	}
	if _, err := os.Lstat(*directory); err != nil {
		return errors.New("rollout journal directory does not exist")
	}
	ctx, cancel := context.WithTimeout(parent, *budget)
	defer cancel()
	store, err := OpenStore(ctx, *directory, *poll)
	if err != nil {
		return err
	}
	defer store.Close()
	state, err := store.Load()
	if err != nil || state == nil || state.App != *app {
		return errors.New("no valid journal for this application")
	}
	type pending struct {
		Generation         string `json:"generation"`
		Phase              string `json:"phase"`
		Candidates         int    `json:"candidates"`
		RetirementExceeded bool   `json:"retirement_exceeded,omitempty"`
	}
	result := struct {
		App        string   `json:"app"`
		Generation string   `json:"generation"`
		Last       Result   `json:"last"`
		Pending    *pending `json:"pending,omitempty"`
	}{App: state.App, Generation: state.Routes.Generation, Last: state.Last}
	if tx := state.Pending; tx != nil {
		result.Pending = &pending{tx.ID, tx.Phase, len(tx.Candidates), tx.RetirementExceeded}
	}
	return json.NewEncoder(output).Encode(result)
}

func readInput(path string, limit int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || private && (info.Size() != 32 || info.Mode().Perm()&0o077 != 0 || !ownedByCurrent(info)) {
		return nil, errors.New("invalid input file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit || private && len(data) != 32 {
		clear(data)
		return nil, errors.New("invalid input size")
	}
	return data, nil
}
