package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nicodes/komizo/internal/release"
)

// RunPlan is deliberately local and read-only. It never routes through the SSH
// account/box command path and never treats the legacy deploy script as dry-run.
func RunPlan(args []string) error {
	return runPlan(args, os.Stdout, os.Stderr)
}

func runPlan(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	beforePath := flags.String("before", "", "previous canonical Compose JSON")
	afterPath := flags.String("after", "", "candidate canonical Compose JSON")
	keyPath := flags.String("key-file", "", "private 32-byte identity key, same for both models")
	initial := flags.Bool("initial", false, "explicitly compare against an empty initial inventory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return ErrSilent
	}
	if flags.NArg() != 0 || *afterPath == "" || *keyPath == "" || (*initial == (*beforePath != "")) {
		return errors.New("plan requires --after and --key-file, and exactly one of --before or --initial")
	}
	key, err := readPlanFile(*keyPath, 32, true)
	if err != nil {
		return errors.New("cannot read identity key: require a private regular file containing exactly 32 bytes")
	}
	defer clear(key)
	load := func(path, side string) (*release.Model, error) {
		data, err := readPlanFile(path, release.MaxModelBytes, false)
		if err != nil {
			return nil, fmt.Errorf("cannot read %s normalized model", side)
		}
		defer clear(data)
		model, err := release.Resolve(data, key)
		if err != nil {
			return nil, fmt.Errorf("%s model: %w", side, err)
		}
		return model, nil
	}
	before := &release.Model{Inventory: release.Inventory{}, Policies: map[string]release.Policy{}}
	if !*initial {
		before, err = load(*beforePath, "before")
		if err != nil {
			return err
		}
	}
	after, err := load(*afterPath, "after")
	if err != nil {
		return err
	}
	changes, err := release.Compare(before.Inventory, after.Inventory)
	if err != nil {
		return err
	}
	type entry struct {
		Service string              `json:"service"`
		Change  release.Kind        `json:"change"`
		Reasons []release.Component `json:"reasons,omitempty"`
		Mode    string              `json:"mode"`
	}
	result := struct {
		AnalysisOnly bool    `json:"analysis_only"`
		Services     []entry `json:"services"`
	}{AnalysisOnly: true, Services: make([]entry, 0, len(changes))}
	for _, change := range changes {
		policy, exists := after.Policies[change.Service]
		if !exists {
			policy = before.Policies[change.Service]
		}
		result.Services = append(result.Services, entry{change.Service, change.Kind, change.Reasons, policy.Mode})
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func readPlanFile(path string, limit int64, key bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("file changed while opening")
	}
	if key && (opened.Mode().Perm()&0o077 != 0 || opened.Size() != 32) {
		return nil, errors.New("identity key must be private and exactly 32 bytes")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit || key && len(data) != 32 {
		clear(data)
		return nil, errors.New("file read failed or exceeds size limit")
	}
	return data, nil
}
