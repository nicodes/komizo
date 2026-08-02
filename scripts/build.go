package scripts

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
		"__STAMP__", ShQuote(stamp),
		"__VERSION__", ShQuote(version),
	)
}
