# What this machine is spending: processor, memory, disk.
#
# CUMULATIVE COUNTERS, not rates. A rate needs two readings and this script is
# one of them -- the caller keeps the previous sample and does the subtraction.
# That also makes the interval explicit rather than assumed: a poll that arrived
# late measures the longer gap it actually covered.
# %.0f, never %d, for anything that can pass 2^31: BusyBox awk clamps %d to 32
# bits, so a disk over 2GB printed as -2147483648 and the reader -- correctly
# refusing a negative byte count -- dropped the line. Cumulative jiffies and
# byte counts all cross 2^31 on ordinary boxes; %.0f is exact to 2^53.
awk '$1 == "cpu" {
	t = 0
	for (i = 2; i <= NF; i++) t += $i
	# Idle counts iowait with it. Waiting on a disk is not work, and counting it
	# as busy makes a box that is merely reading from a slow disk look loaded.
	printf "sys\tcpu\t%.0f\t%.0f\n", t, $5 + $6
	exit
}' /proc/stat 2>/dev/null
# clamp-ok: a CPU core count. The largest machine ever built is nowhere near
# 2^31 cores, and this is the one number in the probe that is not a byte count,
# a jiffy total or a microsecond total.
awk '/^processor/ { n++ } END { if (n) printf "sys\tcores\t%d\t0\n", n }' /proc/cpuinfo 2>/dev/null
# MemAvailable, never MemFree. Free memory on a healthy box is near zero -- the
# kernel spends everything spare on cache and hands it back on demand -- so
# reporting free as used is the classic way to make every server on earth look
# seconds from death.
awk '/^MemTotal:/ { t = $2 } /^MemAvailable:/ { a = $2 }
	END { if (t > 0 && a != "") printf "sys\tmem\t%.0f\t%.0f\n", t * 1024, (t - a) * 1024 }' \
	/proc/meminfo 2>/dev/null
# Used and available, rather than the filesystem's raw size. df computes its own
# percentage the same way, excluding the blocks reserved for root -- and a disk
# figure that disagrees with df on the very same box is one nobody will believe,
# however defensible the arithmetic behind it.
#
# Both paths, because the one that fills is usually not the one people watch:
# images and volumes live under /var/lib/docker, which is frequently its own
# filesystem. The device travels with the numbers so the caller can fold the
# two when they are one filesystem -- by DEVICE, not mount point, because
# docker setups routinely bind-mount /var/lib/docker onto itself, and df then
# reports the same filesystem under two names.
for p in / /var/lib/docker; do
	[ -d "$p" ] || continue
	df -k "$p" 2>/dev/null | awk 'NR > 1 && NF >= 4 {
		printf "disk\t%s\t%s\t%.0f\t%.0f\n", $NF, $1, $3 * 1024, ($3 + $4) * 1024
		exit
	}'
done


# What one container is spending.
#
# Read from the CGROUP, which is where the kernel does the accounting anyway --
# 'docker stats' reads the same files and then streams, which is why it costs a
# second per call. This is three small reads with no daemon in the path, cheap
# enough to ride the five-second poll.
#
# Same shape as the box's numbers: cumulative processor time, and memory as of
# now. The caller subtracts.
#
# Memory excludes inactive page cache, which is the convention 'docker stats'
# follows and the honest one: cache is memory the container is BORROWING and the
# kernel will take straight back under pressure. Counting it makes anything that
# has ever read a large file look permanently swollen.
container_stat() {
	_pid="$1"
	[ -n "$_pid" ] && [ "$_pid" != "0" ] || return 0
	_cpu=""; _mem=""; _lim=""
	# cgroup v2: one unified hierarchy, on the line whose id is 0.
	_cg="$(awk -F: '$1 == "0" { print $3; exit }' "/proc/$_pid/cgroup" 2>/dev/null)"
	if [ -n "$_cg" ] && [ -d "/sys/fs/cgroup$_cg" ]; then
		_d="/sys/fs/cgroup$_cg"
		_cpu="$(awk '$1 == "usage_usec" { print $2; exit }' "$_d/cpu.stat" 2>/dev/null)"
		_cur="$(cat "$_d/memory.current" 2>/dev/null)"
		_ina="$(awk '$1 == "inactive_file" { print $2; exit }' "$_d/memory.stat" 2>/dev/null)"
		_lim="$(cat "$_d/memory.max" 2>/dev/null)"
		[ -n "$_cur" ] && _mem=$((_cur - ${_ina:-0}))
	else
		# cgroup v1: a hierarchy per controller, each on its own line. Still what
		# older Alpine and anything with a v1 boot argument presents.
		_c1="$(awk -F: '$2 ~ /(^|,)cpuacct(,|$)/ { print $3; exit }' "/proc/$_pid/cgroup" 2>/dev/null)"
		if [ -n "$_c1" ] && [ -f "/sys/fs/cgroup/cpuacct$_c1/cpuacct.usage" ]; then
			# Nanoseconds there, microseconds under v2. Converted here so the
			# caller never has to know which kind of box it is talking to.
			_cpu="$(awk '{ printf "%.0f", $1 / 1000; exit }' "/sys/fs/cgroup/cpuacct$_c1/cpuacct.usage" 2>/dev/null)"
		fi
		_m1="$(awk -F: '$2 ~ /(^|,)memory(,|$)/ { print $3; exit }' "/proc/$_pid/cgroup" 2>/dev/null)"
		if [ -n "$_m1" ] && [ -f "/sys/fs/cgroup/memory$_m1/memory.usage_in_bytes" ]; then
			_cur="$(cat "/sys/fs/cgroup/memory$_m1/memory.usage_in_bytes" 2>/dev/null)"
			_ina="$(awk '$1 == "total_inactive_file" { print $2; exit }' "/sys/fs/cgroup/memory$_m1/memory.stat" 2>/dev/null)"
			_lim="$(cat "/sys/fs/cgroup/memory$_m1/memory.limit_in_bytes" 2>/dev/null)"
			[ -n "$_cur" ] && _mem=$((_cur - ${_ina:-0}))
		fi
	fi
	# Blanks travel as blanks. A cgroup this could not read is UNKNOWN, and a
	# zero would be a measurement -- one saying the container is using nothing.
	printf '%s\t%s\t%s' "${_cpu:-}" "${_mem:-}" "${_lim:-}"
}

# Every running container on the box, with the app it belongs to.
#
# The sampler's own enumeration. The live poll already walks the apps for other
# reasons and calls container_stat as it goes; cron has no such loop, and
# without this the sampler wrote the box's numbers and nothing else -- so every
# app and container chart was empty however long the box had been up, which is a
# failure that looks exactly like an idle machine.
#
# Membership comes from compose rather than a label match on the project name:
# compose derives that name from the directory and normalises it, so an app
# under a custom --app-dir would not match its own containers.
#
# Running containers only. A stopped one has no pid and no cgroup, so there is
# nothing to read -- and its ABSENCE from a reading is the honest record of it,
# which the reader turns back into a zero.
container_stats_all() {
	command -v docker >/dev/null 2>&1 || return 0
	docker info >/dev/null 2>&1 || return 0
	for _state in /var/lib/komizo/apps/*.env; do
		[ -f "$_state" ] || continue
		_app="${_state##*/}"; _app="${_app%.env}"
		_dir="$(komizo_state "$_state" APP_DIR)"
		# shellcheck disable=SC2015 # both sides are tests; either failing means skip
		[ -n "$_dir" ] && [ -f "$_dir/compose.yml" ] || continue
		for _cid in $(docker compose -f "$_dir/compose.yml" --project-directory "$_dir" ps -q 2>/dev/null); do
			# One inspect for both fields: this runs per container per minute,
			# and two calls would be twice the docker round trips for one row.
			_info="$(docker inspect "$_cid" -f '{{index .Config.Labels "com.docker.compose.service"}}	{{.State.Pid}}' 2>/dev/null)"
			_svc="${_info%%	*}"
			_cpid="${_info##*	}"
			[ -n "$_svc" ] || continue
			printf 'cstat\t%s\t%s\t%s\n' "$_app" "$_svc" "$(container_stat "$_cpid")"
		done
	done
}
