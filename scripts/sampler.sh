#!/bin/sh
# Written by komizo. Edits are lost the next time the server is set up.
#
# One reading of this machine, appended to a log. Run by cron every minute.
set -u
LOG=__LOG__
LOCK=__LOCK__
# Bound to variables rather than substituted inline at the point of use. A bare
# __LOG_MAX__ inside `[ ... -gt "$LOG_MAX" ]` is not a number until the moment
# it is substituted, so shellcheck reads the template as comparing against a
# word -- and it is right to: the file has to be valid shell BEFORE rendering,
# because that is the form it is linted in.
LOG_MAX=__LOG_MAX__
LOG_KEEP=__LOG_KEEP__
VOL_EVERY=__VOL_EVERY__
now="$(date +%s)"

# One sampler at a time. Every minute is comfortable for counter reads, and then
# every fifteenth minute runs du over the volumes -- which on a large one can
# outlast the minute it started in. Two overlapping runs would interleave their
# lines into the log, and a half of one reading merged with a half of another is
# worse than a missing minute: it looks like a reading.
#
# mkdir because it is atomic on every filesystem this will ever run on. A lock
# left behind by a kill -9 is cleared once it is older than any honest run.
if [ -d "$LOCK" ] && [ -z "$(find "$LOCK" -maxdepth 0 -mmin +20 2>/dev/null)" ]; then
	exit 0
fi
rm -rf "$LOCK" 2>/dev/null || true
mkdir "$LOCK" 2>/dev/null || exit 0
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT INT TERM

# The whole reading is built before ANY of it is written. A sampler killed
# half way through a slow docker call would otherwise leave a partial minute
# in the log -- a box that appears to have lost containers for one minute,
# which is exactly the shape of the incident somebody would come here to
# investigate.
out="$(
__PROBES__
container_stats_all
# Volumes on a slower cadence than everything else, because they cost a du
# rather than a file read. Keyed off the clock rather than off a counter kept
# somewhere, so it stays on the same quarter-hours across reboots and re-installs.
#
# Inside this block, and after it, deliberately: the probe DEFINES volumes_all,
# and a shell runs a file as it reads it -- so calling it above would be calling
# a function that does not exist yet, on a line that then quietly produces
# nothing. Which is the same failure the sampler already shipped once.
# Also on the very first run, whether or not the clock has reached a quarter
# hour. Otherwise a box set up at 11:07 records no storage at all until 11:15,
# and needs a second one at 11:30 before there are two points to draw a line
# between -- so the chart is missing for the first half hour after installing
# the thing that draws it, which reads as broken rather than as new.
if [ ! -f "$LOG" ] || [ "$(( now / 60 % VOL_EVERY ))" -eq 0 ]; then
	volumes_all
fi
)"
[ -n "$out" ] || exit 0
printf '%s\n' "$out" | sed "s/^/S	$now	/" >> "$LOG"

# Trimmed only when it has grown, rather than rewritten every minute: the copy
# costs the whole file, and paying that once every few days is the difference
# between a cron job nobody notices and one that shows up in iowait.
if [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt "$LOG_MAX" ]; then
	tail -n "$LOG_KEEP" "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"
fi