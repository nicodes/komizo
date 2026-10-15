package app

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path"
	"strings"
)

// The protected executor owns all recovery decisions. This exposes its existing
// exact-stage operation over SSH without accepting arbitrary server paths.
func runPlatformOperation(args []string) (err error) {
	validation := localInput(&err)
	defer validation.finish()
	sub := args[0]
	fs := flag.NewFlagSet("platform "+sub, flag.ContinueOnError)
	host := fs.String("host", "", "operator SSH host")
	port := fs.Int("port", 22, "SSH port")
	stage := fs.String("stage", "", "exact protected server stage from the reviewed plan")
	expected := fs.String("expected-manifest", "", "exact reviewed manifest SHA256")
	fs.Usage = func() {
		usageJourney("platform "+sub, "komizo platform "+sub+" --host root@HOST --stage /var/lib/komizo/upgrades/STAGE --expected-manifest SHA256", "Inspect the exact recorded operation before recovery. Recovery restores recorded prior configuration and retains all executor identity, foreign-writer and fence checks.")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	name := strings.TrimPrefix(*stage, "/var/lib/komizo/upgrades/")
	if fs.NArg() != 0 || !exactHex(*expected, 64) || name == *stage || len(name) < 1 || len(name) > 100 || !onlyChars(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") || path.Clean(*stage) != *stage {
		return errors.New("platform inspection/recovery requires an exact protected stage and manifest digest")
	}
	tgt, err := resolveTarget(fs, *host, *port)
	if err != nil {
		return err
	}
	if tgt.user != "root" {
		return errors.New("platform inspection/recovery requires the root operator")
	}
	validation.complete = true
	if err := ensureReachable(tgt, false); err != nil {
		return err
	}
	body, err := journeyRemote(tgt, []string{"platform", sub, *stage, *expected}, nil)
	if err != nil {
		return err
	}
	var result struct {
		Version  int    `json:"version"`
		Manifest string `json:"manifest"`
		Phase    string `json:"phase"`
	}
	if json.Unmarshal(body, &result) != nil || result.Version != 1 || result.Manifest != *expected || !oneOf(result.Phase, "prepared", "installing", "recovering", "complete", "recovered") {
		return errors.New("platform executor returned an invalid operation identity")
	}
	_, err = os.Stdout.Write(body)
	return err
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
