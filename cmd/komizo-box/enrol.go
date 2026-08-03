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

	conf, err := exchange(ctx, base, *token, rep)
	if err != nil {
		return err
	}
	if err := box.WriteAgentConf(*confPath, conf); err != nil {
		return fmt.Errorf("enrolled, but could not store the credential: %w", err)
	}
	fmt.Printf("enrolled as %s\n", conf.ServerID)
	return nil
}

type enrolBody struct {
	Token  string     `json:"token"`
	Report box.Report `json:"report"`
}

type enrolReply struct {
	ServerID   string `json:"server_id"`
	AgentToken string `json:"agent_token"`
	Message    string `json:"message"`
}

func exchange(ctx context.Context, base, token string, rep box.Report) (box.AgentConf, error) {
	body, err := json.Marshal(enrolBody{Token: token, Report: rep})
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
	return box.AgentConf{API: base, ServerID: reply.ServerID, Token: reply.AgentToken}, nil
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
