package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nicodes/komizo/internal/project"
)

// ProjectCommand returns typed command results without launching the CLI again.
func ProjectCommand(args []string, in io.Reader, out, progress io.Writer) (bool, int) {
	return projectCommand(context.Background(), args, in, out, progress)
}

func projectCommand(parent context.Context, args []string, in io.Reader, out, progress io.Writer) (bool, int) {
	machine := len(args) > 0 && args[0] == "--json"
	if machine {
		args = args[1:]
	}
	if len(args) == 0 || !slices.Contains([]string{"init", "lock", "dev", "check", "run", "validate", "exec", "describe"}, args[0]) {
		return false, 0
	}
	name := args[0]
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	var help bytes.Buffer
	if machine {
		fs.SetOutput(&help)
	} else {
		fs.SetOutput(out)
	}
	root := fs.String("directory", ".", "project directory")
	var recipe string
	if name == "init" {
		fs.StringVar(&recipe, "recipe", "", "static-site, go-service, go-cli, go-library, godot-app, godot-addon or configuration")
	}
	mode := "auto"
	if name == "dev" || name == "run" {
		fs.StringVar(&mode, "mode", "auto", "auto, preview or local development")
	}
	var tools string
	if name == "run" || name == "exec" {
		fs.StringVar(&tools, "tools", "", "comma-separated declared tools for a named task or explicit command")
	}
	var base string
	var explain bool
	if name == "check" {
		fs.StringVar(&base, "base", "", "exact ancestor commit for affected-input verification")
		fs.BoolVar(&explain, "explain", false, "describe selected verification without executing project code")
	}
	defaultTimeout := 30 * time.Minute
	if name == "dev" {
		defaultTimeout = 0
	}
	timeout := fs.Duration("timeout", defaultTimeout, "execution deadline; dev runs until stopped by default")
	var data any
	var err error
	code := 0
	if err = fs.Parse(args[1:]); err == nil {
		*root, err = filepath.Abs(*root)
		if err == nil {
			*root, err = filepath.EvalSymlinks(*root)
		}
	}
	if err == nil && name == "run" && fs.NArg() == 1 && fs.Arg(0) == "dev" {
		explicit := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "timeout" {
				explicit = true
			}
		})
		if !explicit {
			*timeout = 0
		}
	}
	if err == nil && (*timeout < 0 || *timeout == 0 && name != "dev" && !(name == "run" && fs.NArg() == 1 && fs.Arg(0) == "dev") || *timeout > 24*time.Hour) {
		err = errors.New("execution deadline must be positive and no more than 24h")
	}
	if err == nil && machine && (name == "dev" || name == "run" && slices.Contains(fs.Args(), "dev")) {
		err = errors.New("dev is an interactive foreground command; run komizo dev without --json")
	}
	var selected []string
	if tools != "" {
		selected = strings.Split(tools, ",")
	}
	if err == nil {
		switch name {
		case "init":
			if fs.NArg() != 0 || recipe == "" {
				err = errors.New("usage: komizo init --recipe RECIPE; see komizo init --help")
				break
			}
			data, err = project.Init(*root, recipe, versionText())
		case "lock":
			if fs.NArg() != 0 {
				err = errors.New("komizo lock accepts no positional arguments")
				break
			}
			data, err = project.WriteLock(*root, versionText())
		case "describe":
			if fs.NArg() != 0 {
				err = errors.New("komizo describe accepts no positional arguments")
				break
			}
			data, err = project.Describe(*root, versionText())
		case "validate":
			if fs.NArg() != 0 {
				err = errors.New("komizo validate accepts no positional arguments")
				break
			}
			data, err = project.Validate(*root, versionText())
		case "exec":
			ctx, cancel := projectDeadline(parent, *timeout)
			defer cancel()
			stream := out
			if machine {
				stream = progress
			}
			var result project.Result
			result, err = project.Exec(ctx, *root, versionText(), fs.Args(), selected, in, stream, progress)
			data, code = result, result.ExitCode
		default:
			targets := []string{name}
			if name == "run" {
				targets = fs.Args()
				if len(targets) == 0 {
					err = errors.New("komizo run requires one or more stage names")
					break
				}
			} else if fs.NArg() != 0 {
				err = errors.New("unexpected positional arguments")
				break
			}
			ctx, cancel := projectDeadline(parent, *timeout)
			defer cancel()
			var result project.Result
			if name == "check" && explain {
				data, err = project.Plan(ctx, *root, versionText(), base)
				break
			}
			if name == "check" && base != "" {
				result, err = project.CheckSelected(ctx, *root, versionText(), base, in, progress)
			} else {
				result, err = project.Execute(ctx, *root, versionText(), targets, mode, selected, in, progress)
			}
			data, code = result, result.ExitCode
		}
	}
	isHelp := errors.Is(err, flag.ErrHelp)
	if isHelp {
		err = nil
		data = map[string]string{"text": help.String()}
	}
	if err != nil && code == 0 {
		code = 1
	}
	if machine {
		result := MachineResult{Version: MachineVersion, Command: name, OK: err == nil, ExitCode: code}
		result.Data, _ = json.Marshal(data)
		if err != nil {
			result.Error = &MachineError{Code: "command_failed", Message: err.Error()}
			if errors.Is(err, context.DeadlineExceeded) {
				result.Error.Code = "timeout"
			}
			if r, ok := data.(project.Result); ok {
				result.Error.ReconciliationRequired = r.ReconciliationRequired
				result.NextAction = r.NextAction
			}
		}
		_ = json.NewEncoder(out).Encode(result)
	} else if err != nil {
		fmt.Fprintln(progress, "error:", err)
	} else if plan, ok := data.(project.VerificationPlan); ok {
		fmt.Fprintf(out, "Verification: %s\nStages: %s\n", plan.Mode, strings.Join(plan.Targets, ", "))
		for _, reason := range plan.Reasons {
			fmt.Fprintln(out, reason)
		}
	} else if description, ok := data.(project.Description); ok {
		printProjectDescription(out, description)
	} else if !isHelp && name != "exec" {
		fmt.Fprintln(out, name+": complete")
	}
	return true, code
}

func projectDeadline(parent context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	if duration == 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, duration)
}

func printProjectDescription(out io.Writer, d project.Description) {
	fmt.Fprintf(out, "Recipe: %s\nPlatform: komizo %s\n", d.Recipe, d.Platform)
	if d.Repository != "" {
		fmt.Fprintf(out, "Repository: %s\n", d.Repository)
	}
	names := make([]string, 0, len(d.Tools))
	for name := range d.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintln(out, "Tools:")
	for _, name := range names {
		var version string
		if json.Unmarshal(d.Tools[name], &version) != nil {
			version = string(d.Tools[name])
		}
		fmt.Fprintf(out, "  %s %s\n", name, version)
	}
	names = names[:0]
	for name, available := range d.Stages {
		if available {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	fmt.Fprintf(out, "Stages: %s\n", strings.Join(names, ", "))
	if len(d.Tasks) > 0 {
		fmt.Fprintf(out, "Tasks: %s\n", strings.Join(d.Tasks, ", "))
	}
	names = names[:0]
	for name := range d.Commands {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintln(out, "Commands:")
	for _, name := range names {
		fmt.Fprintf(out, "  %s\n", strings.Join(d.Commands[name], " "))
	}
}
