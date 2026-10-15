package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

type appDefinition struct {
	Version int             `json:"version"`
	App     string          `json:"app"`
	Config  string          `json:"config"`
	Policy  workload.Policy `json:"policy"`
}

func readDefinition(path string) (appDefinition, error) {
	var d appDefinition
	body, err := readJourneyFile(path, workload.MaxBytes, false)
	if err != nil {
		return d, err
	}
	if err := rejectDuplicateMembers(body); err != nil {
		return d, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || dec.Decode(new(any)) != io.EOF {
		return d, errors.New("definition must be one versioned JSON document")
	}
	if d.Version != 1 {
		return d, errors.New("unsupported application definition version")
	}
	if err := validateApp(d.App); err != nil {
		return d, err
	}
	if err := validateConfigImage(d.Config); err != nil {
		return d, err
	}
	base, err := workload.NewPolicy(d.App, "/srv/"+d.App, d.Config, defaultNetwork)
	if err != nil {
		return d, err
	}
	if d.Policy.App != base.App || d.Policy.AppDir != base.AppDir || d.Policy.ImagePrefix != base.ImagePrefix || d.Policy.SharedNetwork != base.SharedNetwork {
		return d, errors.New("definition policy does not match its app, configuration family or default network")
	}
	if err := d.Policy.Check(); err != nil {
		return d, err
	}
	if d.Policy.SourceRepository == "" || d.Policy.Resources == nil || d.Policy.Readiness == nil {
		return d, errors.New("definition needs explicit trusted source, finite resources and readiness")
	}
	return d, nil
}

func RunSetup(args []string) (err error) {
	validation := localInput(&err)
	defer validation.finish()
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.Usage = func() {
		usageJourney("setup", "komizo setup --host root@HOST [--definition app.json] [--key PRIVATE_FILE]", "Check prerequisites, prepare the host and optionally register an app. Existing app authority and keys are preserved; changed policy requires a separate reviewed migration.")
		fs.PrintDefaults()
	}
	host := fs.String("host", "", "server, [user@]HOST")
	port := fs.Int("port", 22, "SSH port")
	accept := fs.Bool("accept-host-key", false, "explicit trust on first use")
	definition := fs.String("definition", "", "operator-reviewed version-1 app definition")
	key := fs.String("key", "", "new private deploy key destination; default private OS config directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*definition == "" && *key != "") {
		return errors.New("setup accepts flags; --key requires --definition")
	}
	var d appDefinition
	if *definition != "" {
		d, err = readDefinition(*definition)
		if err != nil {
			return err
		}
	}
	tgt, err := resolveTarget(fs, *host, *port)
	if err != nil {
		return err
	}
	validation.complete = true
	if err := ensureReachable(tgt, *accept); err != nil {
		return err
	}
	preflight, err := inspectPrerequisites(tgt)
	if err != nil {
		return err
	}
	if !preflight.Supported {
		_ = json.NewEncoder(os.Stdout).Encode(preflight)
		return errors.New("server prerequisites failed; setup made no installation changes")
	}
	connection := []string{"--host", tgt.addr(), "--port", strconv.Itoa(tgt.port)}
	// Upgrades are explicit; registering an app never incidentally refreshes
	// the proxy, daemon or another app's privileged programs.
	if !preflight.Installed {
		if err := runInit(connection, false); err != nil {
			return err
		}
	}
	verified, err := fetchBox[box.Report](tgt, "report")
	if err != nil {
		return err
	}
	if verified.Server.State != "ready" {
		return errors.New("setup did not establish a ready host; inspect report before proceeding")
	}
	result := map[string]any{"version": 1, "host": tgt.addr(), "prepared": true, "app_registered": false}
	if *definition != "" {
		body, err := journeyRemote(tgt, []string{"workload", "capabilities"}, nil)
		var capabilities struct {
			Version         int  `json:"version"`
			PolicyBootstrap bool `json:"policy_bootstrap"`
		}
		if err != nil || json.Unmarshal(body, &capabilities) != nil || capabilities.Version != 1 || !capabilities.PolicyBootstrap {
			return errors.New("installed executor needs an explicit Komizo upgrade before application setup; no registration or key change was made")
		}
		existing := false
		for _, app := range verified.Apps {
			if app.Name == d.App {
				existing = true
				if app.ConfigImage != d.Config {
					return errors.New("existing application configuration family differs; review a migration")
				}
			}
		}
		add := append(append([]string{}, connection...), "--app", d.App, "--config", d.Config, "--no-instructions")
		if existing {
			add = append(add, "--keep-key")
		} else {
			if *key == "" {
				dir, err := os.UserConfigDir()
				if err != nil {
					return err
				}
				sum := sha256.Sum256([]byte(tgt.addr() + ":" + strconv.Itoa(tgt.port)))
				dir = filepath.Join(dir, "komizo", "keys")
				if err := os.MkdirAll(dir, 0700); err != nil {
					return err
				}
				info, err := os.Lstat(dir)
				if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
					return errors.New("key directory must be private and regular")
				}
				*key = filepath.Join(dir, d.App+"-"+hex.EncodeToString(sum[:6]))
			}
			add = append(add, "--key", *key)
			if _, err := os.Lstat(*key); err == nil {
				if _, err := readExistingKey(*key, keyComment(deriveUser(d.App), tgt.host)); err != nil {
					return err
				}
				add = append(add, "--reuse-key")
			} else if !os.IsNotExist(err) {
				return err
			}
		}
		if !existing {
			if err := runAdd(add, false); err != nil {
				return err
			}
		}
		policy, _ := json.Marshal(d.Policy)
		body, err = journeyRemote(tgt, []string{"workload", "policy-bootstrap", "--app", d.App}, policy)
		if err != nil {
			return fmt.Errorf("application registered; policy needs inspection before deployment: %w", err)
		}
		var installed struct {
			Version           int    `json:"version"`
			App               string `json:"app"`
			Installed         bool   `json:"installed"`
			DeploymentEnabled bool   `json:"deployment_enabled"`
		}
		if json.Unmarshal(body, &installed) != nil || installed.Version != 1 || installed.App != d.App || !installed.Installed || !installed.DeploymentEnabled {
			return errors.New("invalid bootstrap policy receipt")
		}
		result["app"], result["app_registered"], result["key_unchanged"], result["authority"] = d.App, true, existing, installed
		if !existing {
			result["deploy_key_file"] = *key
		}
		result["next_action"] = []string{"komizo", "--json", "deploy", "--host", tgt.addr(), "--port", strconv.Itoa(tgt.port), "--app", d.App, "--version", "COMMIT"}
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

// Secrets are read only from bounded regular private files, never argv, env or
// process output. All candidate filenames are local; remote paths are fixed.
func readJourneyFile(path string, limit int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit || private && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("input must be a bounded regular file; credential files must be private")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("input changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("input exceeds its bound")
	}
	return body, nil
}

func journeyRemote(tgt target, args []string, body []byte) ([]byte, error) {
	var command strings.Builder
	command.WriteString(BoxBin)
	for _, arg := range args {
		command.WriteByte(' ')
		command.WriteString(shQuote(arg))
	}
	timeout := 2 * time.Minute
	if len(args) > 1 && args[1] == "activation-wait" {
		timeout = 26 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", tgt.sshArgs(command.String())...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = bytes.NewReader(body)
	output := &boundedOutput{remaining: 4 << 20}
	cmd.Stdout = output
	metadataDiagnostic := &boundedOutput{remaining: 2048}
	if len(args) > 1 && args[1] == "policy-bootstrap" {
		cmd.Stderr = metadataDiagnostic
	}
	if err := cmd.Run(); err != nil {
		if detail := strings.TrimSpace(metadataDiagnostic.String()); detail != "" {
			return nil, fmt.Errorf("host policy bootstrap refused: %s", detail)
		}
		return nil, errors.New("host operation refused or transport interrupted; inspect current state")
	}
	if output.truncated {
		return nil, errors.New("host operation response exceeds its bound")
	}
	return output.Bytes(), nil
}

func RunDeploy(args []string) (err error) {
	validation := localInput(&err)
	defer validation.finish()
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.Usage = func() {
		usageJourney("deploy", "komizo deploy --host root@HOST --app APP --version COMMIT [--proof FILE]", "Submit through installed root-reviewed deployment authority. Registry tokens stay in private files/stdin. On uncertainty inspect the operation; never resubmit blindly.")
		fs.PrintDefaults()
	}
	host := fs.String("host", "", "server, [user@]HOST")
	port := fs.Int("port", 22, "SSH port")
	app := fs.String("app", "", "registered application")
	version := fs.String("version", "", "exact 40-character source commit")
	proof := fs.String("proof", "", "authenticated release proof file; host verification remains mandatory")
	user := fs.String("registry-user", "", "optional ghcr.io read credential username")
	token := fs.String("registry-token-file", "", "private file containing registry token")
	generation := fs.String("generation", "", "exact existing scoped generation, if applicable")
	wait := fs.Bool("wait", true, "wait for the durable activation result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("deploy accepts only flags")
	}
	if err := validateApp(*app); err != nil {
		return err
	}
	if !exactHex(*version, 40) || (*generation != "" && !exactHex(*generation, 32)) {
		return errors.New("deploy requires exact source and scoped generation identities")
	}
	if (*user == "") != (*token == "") {
		return errors.New("registry user and token file must be supplied together")
	}
	var input []byte
	remote := []string{"workload", "deployment-submit", "--policy", "/etc/komizo/workloads/" + *app + ".json", "--version", *version}
	if *token != "" {
		body, err := readJourneyFile(*token, 16384, true)
		if err != nil {
			return err
		}
		body = bytes.TrimSuffix(body, []byte("\n"))
		if len(body) == 0 || bytes.ContainsAny(body, "\x00\r\n") {
			return errors.New("registry token must be one bounded line")
		}
		input = append(input, body...)
		input = append(input, '\n')
		remote = append(remote, "--registry", "ghcr.io", "--registry-user", *user)
	}
	if *proof != "" {
		body, err := readJourneyFile(*proof, 128<<10, false)
		if err != nil {
			return err
		}
		input = append(input, body...)
	}
	if *generation != "" {
		remote = append(remote, "--generation", *generation)
	}
	tgt, err := resolveTarget(fs, *host, *port)
	if err != nil {
		return err
	}
	validation.complete = true
	if err := ensureReachable(tgt, false); err != nil {
		return err
	}
	body, err := journeyRemote(tgt, remote, input)
	if err != nil {
		return errors.New("deployment submission did not acknowledge; inspect the app operation before retrying")
	}
	id, previous, err := decodeDeploymentAcknowledgement(body)
	if err != nil {
		return errors.New("invalid deployment acknowledgement; inspect the app operation before retrying")
	}
	result := map[string]any{"version": 1, "app": *app, "operation_id": id, "previous_revision": previous, "submitted": true, "completed": false, "next_action": []string{"komizo", "--json", "operation", "inspect", "--host", tgt.addr(), "--port", strconv.Itoa(tgt.port), "--app", *app}}
	if *wait {
		_, err = journeyRemote(tgt, []string{"workload", "activation-wait", "--id", id}, nil)
		if err != nil {
			_ = json.NewEncoder(os.Stdout).Encode(result)
			return errors.New("deployment outcome needs inspection; do not resubmit")
		}
		inspection, err := inspectOperation(tgt, *app)
		if err != nil {
			return err
		}
		if inspection.Operation.ID != id || inspection.Operation.Candidate != *version {
			return errors.New("deployment operation changed; inspect current state")
		}
		if phase := inspection.Operation.Phase; phase != "ready" && phase != "prepared_stopped" && phase != "reconciled" {
			return errors.New("deployment is not in an accepted terminal state; inspect before proceeding")
		}
		result["completed"], result["operation"] = true, inspection
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func decodeDeploymentAcknowledgement(body []byte) (string, string, error) {
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) == 3 && strings.HasPrefix(lines[0], "deploy: previous-version=") && strings.HasPrefix(lines[1], "deploy: submitted=") {
		previous := strings.TrimPrefix(lines[0], "deploy: previous-version=")
		id := lines[2]
		if exactHex(id, 32) && lines[1] == "deploy: submitted="+id && (previous == "" || exactHex(previous, 40)) {
			return id, previous, nil
		}
	}
	return "", "", errors.New("unknown or conflicting deployment acknowledgement")
}

func exactHex(value string, size int) bool {
	return len(value) == size && strings.Trim(value, "0123456789abcdef") == ""
}

type operationInspection struct {
	Operation            workload.Operation `json:"operation"`
	PolicySHA256         string             `json:"policy_sha256"`
	SnapshotRetained     bool               `json:"snapshot_retained"`
	PrivateBodiesOmitted bool               `json:"private_bodies_omitted"`
}

func inspectOperation(tgt target, app string) (operationInspection, error) {
	var result operationInspection
	body, err := journeyRemote(tgt, []string{"workload", "inspect", "--policy", "/etc/komizo/workloads/" + app + ".json"}, nil)
	if err != nil {
		return result, err
	}
	if json.Unmarshal(body, &result) != nil || result.Operation.App != app || result.Operation.Version != 1 || !exactHex(result.Operation.ID, 32) || !exactHex(result.PolicySHA256, 64) || !workload.KnownOperationPhase(result.Operation.Phase) || !result.PrivateBodiesOmitted {
		return result, errors.New("invalid operation inspection identity or vocabulary")
	}
	return result, nil
}

func RunOperation(args []string) (err error) {
	validation := localInput(&err)
	defer validation.finish()
	if len(args) == 1 && hasHelp(args) {
		usageJourney("operation", "komizo operation inspect|recover --host root@HOST --app APP", "Start with inspect. Recovery requires exact reviewed operation, policy, phase and serving identities.")
		return nil
	}
	if len(args) == 0 || (args[0] != "inspect" && args[0] != "recover") {
		return errors.New("operation requires inspect or recover; start with operation inspect --host HOST --app APP")
	}
	sub := args[0]
	fs := flag.NewFlagSet("operation "+sub, flag.ContinueOnError)
	fs.Usage = func() {
		usageJourney("operation "+sub, "komizo operation inspect --host root@HOST --app APP", "Recover requires --id, --version, --policy-sha256, --expected-phase, --serving-version and --outcome from reviewed inspection. No automatic restart, data restore, new pull or fence deletion.")
		fs.PrintDefaults()
	}
	host := fs.String("host", "", "server, [user@]HOST")
	port := fs.Int("port", 22, "SSH port")
	app := fs.String("app", "", "registered application")
	fields := map[string]*string{}
	for _, name := range []string{"id", "version", "policy-sha256", "expected-phase", "serving-version", "outcome"} {
		fields[name] = fs.String(name, "", "reviewed "+name)
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("operation accepts only flags")
	}
	if err := validateApp(*app); err != nil {
		return err
	}
	remote := []string{"workload", "inspect", "--policy", "/etc/komizo/workloads/" + *app + ".json"}
	if sub == "recover" {
		if !exactHex(*fields["id"], 32) || !exactHex(*fields["version"], 40) || !exactHex(*fields["policy-sha256"], 64) || !exactHex(*fields["serving-version"], 40) || !workload.KnownOperationPhase(*fields["expected-phase"]) || (*fields["outcome"] != "restore-serving" && *fields["outcome"] != "accept-candidate") {
			return errors.New("recovery requires all exact reviewed operation identities and an explicit outcome")
		}
		remote[1] = "reconcile"
		for _, name := range []string{"id", "version", "policy-sha256", "expected-phase", "serving-version", "outcome"} {
			remote = append(remote, "--"+name, *fields[name])
		}
	} else {
		for _, value := range fields {
			if *value != "" {
				return errors.New("inspect accepts no recovery authority")
			}
		}
	}
	tgt, err := resolveTarget(fs, *host, *port)
	if err != nil {
		return err
	}
	validation.complete = true
	if err := ensureReachable(tgt, false); err != nil {
		return err
	}
	if sub == "inspect" {
		result, err := inspectOperation(tgt, *app)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(operationView(tgt, result))
	}
	body, err := journeyRemote(tgt, remote, nil)
	if err != nil {
		return err
	}
	if !json.Valid(body) {
		return errors.New("invalid reconciliation receipt")
	}
	_, err = os.Stdout.Write(body)
	return err
}

func operationView(tgt target, inspection operationInspection) map[string]any {
	var vocabulary struct {
		Phases map[string]workload.OperationPhase `json:"phases"`
	}
	_ = json.Unmarshal(workload.OperationContract(), &vocabulary)
	op := inspection.Operation
	meaning := vocabulary.Phases[op.Phase]
	result := map[string]any{"version": 1, "inspection": inspection, "decision": meaning.Decision, "reconciliation_required": meaning.ReconciliationRequired}
	if meaning.ReconciliationRequired {
		options := map[string][]string{}
		for _, outcome := range []string{"restore-serving", "accept-candidate"} {
			serving := op.Candidate
			if outcome == "restore-serving" {
				serving = op.Previous
			}
			if !exactHex(serving, 40) {
				continue
			}
			options[outcome] = []string{"komizo", "--json", "operation", "recover", "--host", tgt.addr(), "--port", strconv.Itoa(tgt.port), "--app", op.App, "--id", op.ID, "--version", op.Candidate, "--policy-sha256", inspection.PolicySHA256, "--expected-phase", op.Phase, "--serving-version", serving, "--outcome", outcome}
		}
		result["review_required_options"] = options
		result["instruction"] = "Review the intended serving revision and stateful compatibility before selecting an option. Host postconditions remain mandatory. These commands do not restore database data or replay activation."
	}
	return result
}
