package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nicodes/komizo/internal/gateway"
	"github.com/nicodes/komizo/internal/rollout"
	"github.com/nicodes/komizo/scripts"
)

func RunRollout(args []string) error {
	if len(args) > 0 && args[0] == "provision" {
		return runRolloutProvision(args[1:])
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return rollout.Command(ctx, args, os.Stdout, os.Stderr)
}

func runRolloutProvision(args []string) error {
	fs := flag.NewFlagSet("rollout provision", flag.ContinueOnError)
	var host, appName, profilePath string
	var port int
	var acceptHostKey bool
	fs.StringVar(&host, "host", "", "server to prepare, [user@]HOST")
	fs.StringVar(&appName, "app", "", "existing application scope")
	fs.StringVar(&profilePath, "profile", "", "private owner-authorized profile (omit to install broker only)")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if err := validateApp(appName); err != nil {
		return err
	}
	var profile []byte
	if profilePath != "" {
		p, err := rollout.LoadProfile(profilePath)
		if err != nil {
			return fmt.Errorf("cannot use --profile: %w", err)
		}
		if p.App != appName {
			return errors.New("--profile belongs to another application")
		}
		profile, err = json.Marshal(p)
		if err != nil {
			return errors.New("cannot encode validated rollout profile")
		}
	}
	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}
	if _, err := tgt.quiet("/usr/local/bin/komizo-box rollout profile --help >/dev/null 2>&1"); err != nil {
		return errors.New("host Komizo runtime predates scoped rollout provisioning; install the current released platform before preparing an app")
	}
	records, err := tgt.appRecords()
	if err != nil {
		return err
	}
	var record *appRecord
	for i := range records {
		if records[i].name == appName {
			if record != nil {
				return errors.New("application record is ambiguous")
			}
			record = &records[i]
		}
	}
	if record == nil {
		return fmt.Errorf("%q is not an existing Komizo application on this box", appName)
	}
	if err := record.check(); err != nil {
		return fmt.Errorf("cannot prepare %q: %w", appName, err)
	}
	snapshot := func() (string, error) { return tgt.runCapture(rolloutProvisionSnapshot(*record)) }
	step("Refreshing only %s's app-scoped rollout broker", appName)
	if err := performRolloutProvision(*record, profile, snapshot, tgt.runScript); err != nil {
		return err
	}
	if len(profile) == 0 {
		note("broker authority is installed, but inactive: no timing/capacity profile or gateway was selected.")
		note("Re-run with an owner-authorized --profile after target measurements; application cutover remains separate.")
	} else {
		note("profile/key/state are installed, but no gateway was started and no application traffic changed.")
		note("The application owner must supervise the gateway and explicitly authorize cutover.")
	}
	return nil
}

func rolloutProvisionSnapshot(record appRecord) string {
	return `set -eu
app_dir=` + shQuote(record.dir) + `
[ ! -L "$app_dir" ]
printf 'app-dir\t'; stat -c '%u:%g:%a' "$app_dir"
for file in compose.yml .env secrets.env; do
  path="$app_dir/$file"
  [ ! -L "$path" ] && [ -f "$path" ]
  printf '%s\t' "$file"; stat -c '%u:%g:%a' "$path"; sha256sum "$path"
done
docker ps -a --filter ` + shQuote("label=com.docker.compose.project="+record.name) + ` --format 'container\t{{.ID}}\t{{.State}}\t{{.Image}}' | sort`
}

func performRolloutProvision(record appRecord, profile []byte, snapshot func() (string, error), runner func(string, map[string]string) error) error {
	before, err := snapshot()
	if err != nil {
		return errors.New("cannot prove existing application ownership/state before broker preparation")
	}
	if !strings.Contains(before, "app-dir\t0:0:750") {
		return errors.New("application directory is not already root-owned mode 0750; refusing to normalize ownership during rollout preparation")
	}
	if err := runner(scripts.AlpineScript, appRefreshEnv(record)); err != nil {
		return errors.New("app-scoped broker refresh failed; live application activation was not requested")
	}
	after, err := snapshot()
	if err != nil || after != before {
		return errors.New("broker preparation could not prove application containers and ownership remained unchanged")
	}
	if len(profile) != 0 {
		if err := runner(scripts.RolloutProvisionScript(profile), map[string]string{"APP_NAME": record.name}); err != nil {
			return errors.New("rollout profile authority installation failed; no gateway or cutover was started")
		}
	}
	return nil
}

func RunGateway(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return gateway.Command(ctx, args, os.Stderr)
}
