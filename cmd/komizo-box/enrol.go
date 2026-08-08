package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"

	"github.com/nicodes/komizo/box"
)

// Enrolment, run on the box as ROOT.
//
// design/enrolment.md §3 said the exchange happens "as komizo_monitor". Writing
// it showed that cannot be: /etc/komizo is 0750 root:komizo_monitor, so the
// agent can read the credential and not write one. Making the directory
// writable by the agent would mean the process that talks to the internet can
// replace its own identity, which is a strictly worse trade than the one that
// motivated the split.
//
// Root on the box does the exchange instead, which satisfies the actual reason
// for not doing it on the laptop: the long-lived token is written by root, on
// the machine it belongs to, straight from the response. It never touches the
// operator's shell history, process table or disk.

func runEnrol(args []string) error {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	api := fs.String("api", "", "the komizo service, e.g. https://api.komizo.dev")
	token := fs.String("token", "", "the single-use enrolment token from the dashboard")
	confPath := fs.String("config", box.AgentConfPath, "where to write the credential")
	apiHost := fs.String("api-host", "", "the hostname this box answers on, if it has one")
	var deviceKeys box.DeviceKeyList
	fs.Var(&deviceKeys, "device-key", box.DeviceKeyUsage)
	var logKeys box.LogKeyList
	fs.Var(&logKeys, "log-key", box.LogKeyUsage)
	forget := fs.Bool("forget-devices", false, "drop the devices this box already takes orders from")
	forgetLogs := fs.Bool("forget-log-keys", false, "drop the accounts that may read this box's logs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *api == "" || *token == "" {
		return fmt.Errorf("both --api and --token are required")
	}
	base, err := box.ValidateAPI(*api)
	if err != nil {
		return err
	}
	// Empty is a supported state: a box addressed by an IP has no endpoint,
	// reports normally, and is read over SSH by the CLI. A non-empty one is
	// checked here as well as by the CLI, because this command is documented as
	// runnable by hand.
	if *apiHost != "" {
		if err := box.ValidateAPIHost(*apiHost); err != nil {
			return err
		}
	}

	// Read BEFORE the exchange, because the exchange replaces this file. What is
	// in it decides whether the devices this box already trusts survive -- see
	// carryOperatorKeys.
	prev, err := box.ReadAgentConf(*confPath)
	if err != nil {
		return err
	}

	// The first report rides the exchange, so a freshly enrolled server appears
	// populated rather than as an empty row that fills in a minute later -- and
	// so a box that cannot produce one fails HERE, in front of the operator,
	// rather than silently an interval later.
	//
	// Measured now rather than read from report.json, because enrolment can run
	// before rootd's first tick.
	ctx, stop := signalContext()
	defer stop()
	rep := probe().Report(ctx)
	if !rep.Server.Ready() {
		fmt.Fprintf(os.Stderr, "warning: this box reports state %q -- enrolling anyway\n", rep.Server.State)
	}

	conf, err := exchange(ctx, base, *token, *apiHost, rep)
	if err != nil {
		return err
	}
	// Added AFTER the exchange, and never from it. These are the keys this box
	// takes orders from, and the difference between komizo being able to
	// command your machines and not is that they are carried here by the person
	// with root rather than returned by the service -- see box/operator.go.
	var dropped int
	conf.OperatorKeys, dropped = carryOperatorKeys(prev, conf.ServerID, deviceKeys, *forget)
	// The same rule, for the same reason -- see carryOperatorKeys. Kept as its
	// own call rather than folded in: these are DIFFERENT AUTHORITIES with
	// different consequences, and a shared helper that took two lists would be
	// one place to get the pairing wrong.
	var logsDropped int
	conf.LogKeys, logsDropped = carryKeys(prev.LogKeys, prev.ServerID, conf.ServerID, logKeys, *forgetLogs)
	if err := box.WriteAgentConf(*confPath, conf); err != nil {
		return fmt.Errorf("enrolled, but could not store the credential: %w", err)
	}
	fmt.Printf("enrolled as %s\n", conf.ServerID)
	// Said out loud, because it decides whether this box can be read directly
	// or only through what it pushes. A service that offered no key is not a
	// failure, but it is a difference somebody should not have to infer.
	//
	// THE REGISTRY KEY IS ENOUGH ON ITS OWN AGAIN, and this sentence has now been
	// wrong in both directions, which is worth recording rather than tidying.
	//
	// komizo-be#72 removed the reads that took only the registry's token, so
	// answering for itself needed a device key too, and Review 1 on komizo#75
	// found the OLD sentence surviving here after serve.go had been corrected --
	// the same false claim, at the point it does the most damage. komizo-be#180
	// then made the registry key an authority to command as well as to verify,
	// so a box that enrolled successfully answers reads AND takes orders from
	// whoever owns it, with nothing further to plant.
	//
	// The lesson that outlives both is that this is the moment the operator is
	// standing here with root. What is printed here is the last thing they are
	// told before they walk away, so it has to describe the box they are
	// actually leaving behind.
	switch {
	case conf.CanServe():
		fmt.Println("this box can answer for itself; start komizo-api to serve it")
	default:
		fmt.Println("this service issued no registry key, so this box reports but does not serve")
	}
	// And the same for commands. It used to be a different question with a
	// different answer -- reading was authorised by the registry's signature and
	// commanding only by a key an operator planted -- and komizo-be#180 made
	// them one question. Both now rest on the registry key, and the operator
	// keys below are an ADDITIONAL set rather than the only one.
	if dropped > 0 && !*forget {
		// Said loudly, because this is the one way the service can reduce what a
		// box trusts and the operator did not ask for it.
		fmt.Fprintf(os.Stderr, "warning: this box now reports as %s, which is not the server it "+
			"was enrolled as,\n         so the %d device(s) it trusted were dropped.\n",
			conf.ServerID, dropped)
	} else if dropped > 0 {
		fmt.Printf("dropped %d device(s) this box used to take orders from\n", dropped)
	}
	switch {
	case len(conf.OperatorKeys) > 0:
		// PRINTED, so the person who pasted the command can see that what landed
		// here is what their app showed them. That comparison is the only step in
		// this design that depends on somebody looking, and it costs one line.
		//
		// "AS WELL AS" is the whole correction. These keys used to be the only
		// way in, so listing them was a complete account of who could command
		// this box; after komizo-be#180 it is a partial one, and a partial
		// account that reads like a complete one is how somebody concludes that
		// removing the last device key locks komizo out. It does not.
		fmt.Printf("it will take orders from your komizo account, and from %d device(s) as well:\n",
			len(conf.OperatorKeys))
		for _, k := range conf.OperatorKeys {
			fmt.Printf("    %s\n", box.Fingerprint(k))
		}
	case conf.CanCommand():
		// The ordinary box now, and the flow komizo-be#180 exists for: sign in on
		// any device, and it works. Said out loud because it is ALSO the sentence
		// that discloses what was traded for it -- komizo holds the key that
		// signs for you, and the operator is entitled to learn that here rather
		// than from a design doc.
		fmt.Println("it will take orders from anyone signed into your komizo account, on any device")
	default:
		fmt.Println("this box is not enrolled with a registry, so it will take orders from nobody")
	}

	// LOGS ARE A SEPARATE SENTENCE, because they are a separate authority and
	// the two answers genuinely differ -- komizo-be#187. An ordinary box today
	// takes orders from the account and serves no logs, and somebody who is told
	// only the first will go looking for a fault on the machine when the log
	// screen is empty. There is no fault: komizo cannot read these and was never
	// meant to.
	switch {
	case len(conf.LogKeys) > 0:
		fmt.Printf("%d account(s) may read this box's logs:\n", len(conf.LogKeys))
		for _, k := range conf.LogKeys {
			fmt.Printf("    %s\n", box.Fingerprint(k))
		}
	case len(conf.OperatorKeys) > 0:
		fmt.Println("no log keys -- only the planted device(s) may read this box's logs.")
	default:
		fmt.Println("no log keys, so this box serves no logs. That is not a fault:")
		fmt.Println("komizo cannot read them, which is the point -- set a log passphrase")
		fmt.Println("in the app, then re-run this with --log-key kmz_log_...")
	}
	if logsDropped > 0 && !*forgetLogs {
		fmt.Fprintf(os.Stderr, "warning: this box now reports as %s, which is not the server it "+
			"was enrolled as,\n         so the %d account(s) that could read its logs were dropped.\n",
			conf.ServerID, logsDropped)
	} else if logsDropped > 0 {
		fmt.Printf("dropped %d account(s) that could read this box's logs\n", logsDropped)
	}
	return nil
}

// carryOperatorKeys decides which devices survive an enrolment.
//
// Re-enrolment is ROTATION -- komizo-be#24 made it the way to replace an agent
// token you suspect has leaked, precisely so that responding to a leak does not
// mean deleting the server. If that also silently un-trusted every device, the
// app would stop working on that box with nothing anywhere saying why, and the
// person who did it was in the middle of handling an incident.
//
// So the existing keys are kept and --device-key ADDS. --forget-devices is the
// way to say otherwise, out loud.
//
// UNLESS THE BOX IS NOW A DIFFERENT SERVER. A different id means this box
// belongs to another row, and usually another account -- komizo#28's fallback
// covers exactly that. Carrying the previous owner's devices in would leave
// them able to command a machine that is no longer theirs.
//
// The id comes from the service, so THE SERVICE CAN FORCE THIS. It cannot add a
// key -- that is the property this whole file is for and it holds -- but it can
// answer with a new id and make a box forget every device it trusted, which
// denies the app path entirely. That is a real power and it is accepted,
// because the alternative is a box that keeps trusting the devices of whoever
// owned it last. What is NOT accepted is doing it quietly: the caller says so
// out loud, naming the count, rather than reporting the same "no device keys
// were given" a fresh box gets.
func carryOperatorKeys(prev box.AgentConf, serverID string, added []string, forget bool) (keys []string, dropped int) {
	return carryKeys(prev.OperatorKeys, prev.ServerID, serverID, added, forget)
}

// carryKeys is that rule, once, for both kinds of key.
//
// Extracted when komizo-be#187 added a second list rather than copied, because
// two copies of "which authorities survive a re-enrolment" are two chances to
// get the re-issued-under-a-new-id case wrong -- and that case is the one that
// silently keeps trusting whoever owned the box last.
func carryKeys(prevKeys []string, prevServerID, serverID string, added []string, forget bool) (keys []string, dropped int) {
	out := []string{}
	switch {
	case forget:
		dropped = len(prevKeys)
	case prevServerID != "" && prevServerID != serverID:
		dropped = len(prevKeys)
	default:
		out = append(out, prevKeys...)
	}
	for _, k := range added {
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		// nil rather than an empty slice, so the field is omitted from the file
		// entirely and a box that trusts nothing looks like one.
		return nil, dropped
	}
	return out, dropped
}

type enrolBody struct {
	Token string `json:"token"`
	// Endpoint is where this box answers for itself, or empty. The BOX sends
	// it, not the laptop, for the reason the box does the exchange at all --
	// design/enrolment.md §3. Empty means the registry knows there is nothing
	// to fetch from, which is what makes "the app shows nothing for this box"
	// an answerable question rather than a mystery.
	Endpoint string     `json:"endpoint,omitempty"`
	Report   box.Report `json:"report"`
}

type enrolReply struct {
	ServerID   string `json:"server_id"`
	AgentToken string `json:"agent_token"`
	// RegistryKey verifies the read tokens this box will be shown, and is what
	// lets it answer for itself without asking anybody -- see box/token.go.
	//
	// OPTIONAL, so a box can still enrol against a service that does not offer
	// one. Such a box reports exactly as it always did and serves nothing,
	// which is the same box komizo had before any of this. Refusing to enrol
	// would make an old service unusable to a new agent for a capability
	// neither end has yet agreed on.
	RegistryKey string `json:"registry_key"`
	Message     string `json:"message"`
}

func exchange(ctx context.Context, base, token, endpoint string, rep box.Report) (box.AgentConf, error) {
	body, err := json.Marshal(enrolBody{Token: token, Endpoint: endpoint, Report: rep})
	if err != nil {
		return box.AgentConf{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/enrol", bytes.NewReader(body))
	if err != nil {
		return box.AgentConf{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "komizo-box/"+version)

	res, err := (&http.Client{Timeout: postTimeout}).Do(req)
	if err != nil {
		return box.AgentConf{}, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))

	var reply enrolReply
	_ = json.Unmarshal(raw, &reply)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		if reply.Message != "" {
			return box.AgentConf{}, fmt.Errorf("%s", reply.Message)
		}
		return box.AgentConf{}, fmt.Errorf("%s: %s", res.Status, firstLine(raw))
	}
	if reply.AgentToken == "" || reply.ServerID == "" {
		return box.AgentConf{}, fmt.Errorf("the service accepted the enrolment but issued no credential")
	}
	return box.AgentConf{API: base, ServerID: reply.ServerID, Token: reply.AgentToken,
		RegistryKey: reply.RegistryKey}, nil
}

// unenrol removes the credential.
//
// The service side -- revoking the token -- is done there; this is the box
// forgetting. Both are needed and neither implies the other: a box that has
// forgotten still has a row on the dashboard going quiet, and a revoked token
// still sits on a box until somebody removes it.
func runUnenrol(args []string) error {
	fs := flag.NewFlagSet("unenrol", flag.ContinueOnError)
	confPath := fs.String("config", box.AgentConfPath, "the credential to remove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.Remove(*confPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Println("this box no longer reports to a komizo service")
	fmt.Println("revoke its token on the dashboard as well -- removing the file does not")
	return nil
}
