package scripts

import "github.com/nicodes/komizo/box"

// The scripts that take values, built by substitution rather than by
// formatting. See embed.go for why.

// StagedAgent is where the agent binary is written before agent-install.sh
// moves it into place.
//
// Under /tmp rather than beside its destination, so a transfer that dies half
// way leaves a stray file somewhere harmless rather than a truncated
// komizo-box in /usr/local/bin that the next boot would try to run.
const StagedAgent = "/tmp/.komizo-box.staged"

// AgentInterval is how often the agent probes.
//
// A minute, because the history it writes is charted per minute and a slower
// timer would draw gaps into every chart. The report being up to a minute stale
// is what design/appify.md §3 already accepted as the price of the reporting
// account having no privileges.
const AgentInterval = "60s"

// AgentEnrol exchanges an enrolment token for this box's credential.
//
// Every value is SHELL-QUOTED: they come from a caller rather than from a
// constant in this file, and the token in particular is an opaque string from
// a service. The app package validates the URL too, which is the same
// belt-and-braces argument ShQuote carries everywhere else here.
func AgentEnrol(api, token, apiHost string) string {
	return render(agentEnrol,
		"__API__", ShQuote(api),
		"__API_HOST__", ShQuote(apiHost),
		"__TOKEN__", ShQuote(token),
		"__CONF__", box.AgentConfPath,
	)
}

// AgentUnenrol stops the agent and removes the credential.
func AgentUnenrol() string {
	return render(agentUnenrol, "__CONF__", ShQuote(box.AgentConfPath))
}

// AgentInstall installs komizo-box and starts it under OpenRC.
//
// The BINARY is not in here. It is several megabytes of ELF, staged over its
// own connection at StagedAgent, and this moves it into place -- see
// agent-install.sh.
//
// version is the komizo release doing the installing and stamp is the content
// hash of the agents it carries. Both are recorded so the interface can answer
// two different questions: which komizo set this box up, and would running the
// update change anything.
func AgentInstall(stamp, version string) string {
	return render(agentInstall,
		"__STAGED__", StagedAgent,
		"__INTERVAL__", AgentInterval,
		"__STATE_DIR__", box.StateDir,
		"__PENDING_DIR__", box.PendingDir,
		"__RUN_DIR__", box.RunDir,
		"__ETC_DIR__", box.EtcDir,
		"__REPORT_PATH__", box.ReportPath,
		"__STAMP__", ShQuote(stamp),
		"__VERSION__", ShQuote(version),
	)
}
