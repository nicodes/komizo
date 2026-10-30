package app

import (
	"errors"
	"flag"

	"github.com/nicodes/komizo/box"
)

func RunStatus(args []string) (err error) {
	validation := localInput(&err)
	defer validation.finish()
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(commandFlags())
	directory := fs.String("directory", ".", "project directory")
	host := fs.String("host", "", "server; defaults to the private project target")
	port := fs.Int("port", 22, "SSH port")
	app := fs.String("app", "", "application; defaults to the private project target")
	fs.Usage = func() {
		usageJourney("status", "komizo status [--directory DIR] [--host HOST --app APP]", "Read the installed host report without changing application state.")
		fs.PrintDefaults()
	}
	if err = fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("status accepts only flags")
	}
	if _, err = defaultDeploymentTarget(*directory, host, port, app, fs); err != nil {
		return err
	}
	if *app != "" {
		if err = validateApp(*app); err != nil {
			return err
		}
	}
	tgt, err := resolveTarget(fs, *host, *port)
	if err != nil {
		return err
	}
	validation.complete = true
	if err = ensureReachable(tgt, false); err != nil {
		return err
	}
	report, err := fetchBox[box.Report](tgt, "report")
	if err != nil {
		return err
	}
	if *app == "" {
		return emitResult(report)
	}
	for _, application := range report.Apps {
		if application.Name == *app {
			return emitResult(map[string]any{"version": 1, "host": tgt.addr(), "server": report.Server, "application": application})
		}
	}
	return errors.New("bound application is not registered on the target host")
}
