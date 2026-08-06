package box

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// What the agent needs to talk to the komizo service, and where it lives.
//
// Written by root at enrolment, read by the agent as komizo_monitor. That split
// is the point: the process that talks to the internet holds a credential it
// cannot replace, and the process that can replace it never opens a socket.

const (
	// EtcDir holds the agent's credential.
	//
	// Under /etc, NOT under StateDir. The state directory is 0750 root:root
	// because apps/<app>.env names every deploy account, so nothing
	// unprivileged can traverse into it -- a credential placed there would be
	// unreadable by the one process that needs it. That is exactly what
	// happened to report.json, found by the first run on a real Alpine box, and
	// it is worth not repeating in a file that would fail silently instead of
	// loudly.
	//
	// /etc is world-traversable; /etc/komizo is not. The GROUP is the boundary:
	// root writes it, the agent reads it, nothing else can see it exists.
	EtcDir = "/etc/komizo"

	// AgentConfPath is the whole of what enrolment leaves behind.
	//
	// One file rather than a token beside a URL. They are issued together, they
	// are replaced together, and two files are two things that can disagree
	// about which server this is.
	AgentConfPath = EtcDir + "/agent.json"
)

// AgentConf is what enrolment issued.
type AgentConf struct {
	// API is the base URL of the komizo service, without a trailing slash.
	API string `json:"api"`
	// ServerID is what the service calls this box. Issued by the service, never
	// chosen by the box -- see design/enrolment.md §4.
	ServerID string `json:"server_id"`
	// Token authenticates every report. It may report as this one server and
	// nothing else, which is what makes a leak worth fixing rather than
	// disclosing.
	Token string `json:"token"`
	// RegistryKey verifies the read tokens the service signs, so this box can
	// decide who may read it WITHOUT asking anybody -- see box/token.go. Raw
	// base64 of an ed25519 public key.
	//
	// In this file rather than beside it for the reason the file exists at all:
	// these values are issued together and replaced together, and two files are
	// two things that can disagree about which registry this box trusts.
	//
	// Empty on a box enrolled against a service that does not offer one, which
	// is every box enrolled before this existed. Such a box reports exactly as
	// it did and serves nothing, because there is no key to verify against.
	RegistryKey string `json:"registry_key,omitempty"`

	// OperatorKeys are the devices this box will take orders from -- see
	// operator.go for what they are and why the service does not choose them.
	//
	// Carried here by the person setting the box up rather than returned by the
	// exchange above, which is the whole of the difference between komizo being
	// able to command your machines and not. Everything else in this file is
	// issued BY the service; this one is issued TO it.
	//
	// Empty is the ordinary state: the box reports, serves reads, and accepts
	// no commands.
	OperatorKeys []string `json:"operator_keys,omitempty"`
}

// CanServe reports whether this box can answer for itself.
//
// Both halves are required and neither is optional: the key is what verifies a
// caller, and the server id is what a token has to name. A box missing either
// could only refuse every request, so it does not open a socket at all.
func (c AgentConf) CanServe() bool { return c.RegistryKey != "" && c.ServerID != "" }

// Enrolled reports whether this box has been through enrolment.
//
// A box that has not is not broken. komizo works entirely without the service
// -- appify.md §10 requires that -- so the agent's job when there is no config
// is to say so once and exit, not to retry.
func (c AgentConf) Enrolled() bool {
	return c.API != "" && c.Token != ""
}

// ReportURL and EnrolURL are the two endpoints, built from the base.
func (c AgentConf) ReportURL() string { return c.API + "/v1/report" }
func (c AgentConf) EnrolURL() string  { return c.API + "/v1/enrol" }

// ReadAgentConf loads the credential.
//
// A missing file is not an error: it is a box that has not enrolled, which is
// the normal state for every box until somebody decides otherwise.
func ReadAgentConf(path string) (AgentConf, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return AgentConf{}, nil
		}
		return AgentConf{}, err
	}
	var c AgentConf
	if err := json.Unmarshal(b, &c); err != nil {
		return AgentConf{}, fmt.Errorf("%s is not readable as an agent config: %w", path, err)
	}
	c.API = strings.TrimRight(c.API, "/")
	return c, nil
}

// AgentUser is the account the agent runs as. The GROUP of the same name is
// what makes the credential readable to it and to nothing else.
const AgentUser = "komizo_monitor"

// WriteAgentConf stores the credential, readable by the agent's group and
// nobody else.
//
// Mode AND GROUP, both set explicitly. 0640 alone is not the boundary: a file
// written by root is owned by root:root, so a 0640 credential in a directory
// the agent can traverse is one the agent still cannot read -- which is exactly
// what happened, and is the third time this shape has bitten. The mode says who
// may read it; the group says who they are.
//
// A missing group is not fatal. This is how it behaves in a test, and on a box
// where the account exists the lookup succeeds -- but failing the write would
// turn "the agent cannot read this" into "enrolment does not complete", which
// is a worse outcome for the same misconfiguration.
func WriteAgentConf(path string, c AgentConf) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := writeFileAtomic(path, append(b, '\n'), 0o640); err != nil {
		return err
	}
	return chownToAgentGroup(path)
}

// chownToAgentGroup gives the file to the agent's group, leaving the owner as
// whoever wrote it -- root.
func chownToAgentGroup(path string) error {
	g, err := user.LookupGroup(AgentUser)
	if err != nil {
		// No such group: not a box komizo has set up. Left alone rather than
		// failed, so this works in a test and on a machine mid-provisioning.
		return nil
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return nil
	}
	if err := os.Chown(path, os.Getuid(), gid); err != nil {
		return fmt.Errorf("wrote %s but could not give it to %s, so the agent cannot read it: %w",
			path, AgentUser, err)
	}
	return nil
}

// ValidateAPI refuses a service URL the agent should not be sending a
// credential to.
//
// HTTPS, or nothing. The token is a bearer credential and this runs
// unattended on somebody's server; sending it in the clear because a URL was
// typed without the s is not a mistake the agent should be able to make.
//
// The one exception is a loopback host, which is how this is tested and how
// somebody would run the service alongside the agent while developing. Nothing
// leaves the machine, so there is nothing to intercept.
func ValidateAPI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%q has no host -- it should look like https://api.komizo.dev", raw)
	}
	host := u.Hostname()
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback {
			return "", fmt.Errorf("%q is not https -- the agent's token is a bearer credential "+
				"and will not be sent in the clear", raw)
		}
	default:
		return "", fmt.Errorf("%q is not an http(s) URL", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// APISocketDirMode is 0750 AND SETGID, and the setgid bit is the whole point.
//
// The box's proxy has to connect to the socket in here, and it runs with every
// capability dropped but CAP_NET_BIND_SERVICE -- komizo's own hardening, in
// alpine-proxy.sh. So its root is NOT exempt from permission checks the way
// root usually is: it cannot traverse a directory it does not own, and it
// cannot connect to a socket it has no write bit on.
//
// A socket is created by whoever binds it, which is the agent account, and it
// would inherit that account's group. Setgid on the directory makes it inherit
// the DIRECTORY's group instead -- root -- which the proxy is in. Nothing else
// on the box is.
//
// The alternative was 0666 on the socket. That works, and it means any local
// process can open the one door on this machine that answers questions about
// it. A valid token would still be required; being able to knock is not
// nothing.
const APISocketDirMode = os.ModeSetgid | 0o750

// PrepareAPISocketDir makes the socket directory reachable by the two things
// that need it and nothing else.
//
// Owned by the agent account, so it can create the socket. Grouped to root, so
// the proxy can reach it. Called by rootd, which runs as root -- the agent
// cannot chgrp to a group it is not in, and root is not one of its groups.
func PrepareAPISocketDir(path string) error {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	u, err := user.Lookup(AgentUser)
	if err != nil {
		// No such account: not a box komizo has set up. Left alone rather than
		// failed, so this works in a test and mid-provisioning.
		return nil
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil
	}
	// Group 0. Explicit rather than looked up: it is the group the proxy runs
	// as, not a name that might mean something else on another distribution.
	if err := os.Chown(path, uid, 0); err != nil {
		return fmt.Errorf("could not give %s to %s: %w", path, AgentUser, err)
	}
	// After the chown, because chown clears the setgid bit.
	if err := os.Chmod(path, APISocketDirMode); err != nil {
		return fmt.Errorf("could not set the mode on %s: %w", path, err)
	}
	return nil
}

// ServedDirMode is 0750 and setgid, and it is setgid for the mirror image of
// the reason APISocketDirMode is.
//
// Here root creates the files and the agent account reads them, so a file would
// be born group root and unreadable by the one process that serves it. Setgid
// on the directory gives it the DIRECTORY's group instead -- the agent's -- and
// AppendSample's 0640 then means what it says.
//
// No world bits. Every other account on the box, including every app's deploy
// account, has no business reading what this machine measured about itself.
const ServedDirMode = os.ModeSetgid | 0o750

// PrepareServedDir makes the directory root writes into and the agent reads
// from.
//
// Owned by ROOT, grouped to the agent: the opposite of the socket directory,
// because the direction is the opposite. Called by rootd, which runs as root --
// nothing else on the box can hand a directory to another account.
//
// Idempotent, and called on every start rather than only at install: StateDir
// survives a reboot but an operator, an upgrade or a restored backup can leave
// this directory owned by root with no group at all, and the failure that
// produces is an empty chart rather than an error.
//
// EVERY directory on this side of the boundary goes through here -- the served
// directory itself, the logs, and the results. Each of them is "root writes,
// the agent reads", and the one that had its own two lines instead is the one
// that shipped with the setgid bit cleared; see PrepareResultsDir.
func PrepareServedDir(path string) error {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	// The GROUP is skipped when there is no account to give it to -- not a box
	// komizo has set up, so this works in a test and mid-provisioning -- but the
	// MODE is set either way. It is the directory's own property, it costs
	// nothing on a machine with no agent, and leaving it to the umask on a box
	// that is mid-provisioning means the setgid bit depends on which of the
	// installer and rootd ran first.
	if u, err := user.Lookup(AgentUser); err == nil {
		if gid, err := strconv.Atoi(u.Gid); err == nil {
			// Owner 0, explicitly. Root writes here and the account that reads
			// must not be able to replace what it is given -- which is the same
			// split the credential in EtcDir is on.
			if err := os.Chown(path, 0, gid); err != nil {
				return fmt.Errorf("could not group %s to %s: %w", path, AgentUser, err)
			}
		}
	}
	// After the chown, because chown clears the setgid bit. There is a test for
	// this ordering in the installer for the same reason there is one here:
	// getting it wrong looks exactly like getting it right.
	if err := os.Chmod(path, ServedDirMode); err != nil {
		return fmt.Errorf("could not set the mode on %s: %w", path, err)
	}
	return nil
}
