package scripts

import "strconv"

// The scripts that take values, built by substitution rather than by
// formatting. See embed.go for why.

// Where the sampler writes and how much it keeps.
//
// Here rather than in the app package because the two scripts that read and
// write this file are here, and a path that lives apart from the only things
// that use it is a value two places have to agree about.
const (
	SystemLog = "/var/lib/komizo/system.log"
	// Trimmed by BYTES, not by age. Age would make retention depend on how many
	// containers the box runs -- twenty containers would keep a fifth as long as
	// four for the same disk -- and the thing actually worth bounding is the
	// disk. Roughly a week at a handful of containers.
	systemLogMax  = 8000000
	systemLogKeep = 60000 // lines kept when it is trimmed
	systemLogLock = SystemLog + ".lock"

	// How often the sampler measures volumes, in minutes.
	//
	// Not every minute, and this is the one measurement that has to be rationed.
	// Everything else here is a counter read -- open a file, read a number. Disk
	// use needs du, which walks the whole tree, and walking a database volume
	// sixty times an hour would make watching the box the heaviest thing
	// happening on it.
	volEveryMinutes = 15

	// AccessLog is where the generated site blocks write. See alpine.sh.
	AccessLog = "/srv/_proxy/logs/access.log"
)

// Inventory is one tab-separated record per app, plus the box itself.
func Inventory() string {
	return render(inventory,
		"__LIB_STATE__", libState,
		"__LIB_SYSTEM_PROBE__", libSystemProbe,
	)
}

// Metrics totals the requests in a range, per app, off the proxy's access log.
func Metrics(from, to int64) string {
	return render(metrics,
		"__LIB_STATE__", libState,
		"__ACCESS_LOG__", AccessLog,
		"__FROM__", strconv.FormatInt(from, 10),
		"__TO__", strconv.FormatInt(to, 10),
	)
}

// SystemLogRange reads back what the sampler wrote in a range.
func SystemLogRange(from, to int64) string {
	return render(systemLog,
		"__SYSTEM_LOG__", SystemLog,
		"__FROM__", strconv.FormatInt(from, 10),
		"__TO__", strconv.FormatInt(to, 10),
	)
}

// Storage measures one app's volumes with du, now.
//
// The app name is SHELL-QUOTED rather than interpolated bare: it is the only
// value here that comes from a caller rather than from a constant in this file.
// The app package validates it too, but that made the safety of this line
// depend on a rule enforced in another package -- the same argument shQuote
// carries there.
func Storage(app string) string {
	return render(storage,
		"__LIB_STATE__", libState,
		"__LIB_VOLUME_PROBE__", libVolumeProbe,
		"__APP__", ShQuote(app),
	)
}

// Sampler is the per-minute script exactly as it lands on the box.
func Sampler() string {
	return render(sampler,
		"__LOG__", ShQuote(SystemLog),
		"__LOCK__", ShQuote(systemLogLock),
		"__PROBES__", libState+libSystemProbe+libVolumeProbe,
		"__LOG_MAX__", strconv.Itoa(systemLogMax),
		"__LOG_KEEP__", strconv.Itoa(systemLogKeep),
		"__VOL_EVERY__", strconv.Itoa(volEveryMinutes),
	)
}

// SamplerInstall writes the sampler onto the box and puts it in cron.
//
// version is the komizo release doing the installing and stamp is the content
// hash of what it writes. Both are recorded so the interface can answer two
// different questions: which komizo set this box up, and would running the
// update change anything.
func SamplerInstall(stamp, version string) string {
	return render(samplerInstall,
		"__LOG__", SystemLog,
		"__SAMPLER__", Sampler(),
		"__LOCK__", ShQuote(systemLogLock),
		"__LOG_MAX__", strconv.Itoa(systemLogMax),
		"__LOG_KEEP__", strconv.Itoa(systemLogKeep),
		"__VOL_EVERY__", strconv.Itoa(volEveryMinutes),
		"__STAMP__", ShQuote(stamp),
		"__VERSION__", ShQuote(version),
	)
}
