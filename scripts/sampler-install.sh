set -eu
log() { printf '\n==> %s\n' "$*"; }

log "Installing the resource sampler"
mkdir -p /var/lib/komizo
chmod 750 /var/lib/komizo

# Quoted delimiter: everything between here and the end marker is written
# literally, so the probe's own $variables survive into the installed script
# instead of being expanded once, now, against this shell.
cat > /usr/local/bin/komizo-sample <<'KOMIZO_SAMPLER_EOF'
__SAMPLER__
KOMIZO_SAMPLER_EOF
chmod 755 /usr/local/bin/komizo-sample

# The crontab line is replaced rather than appended to, so re-running setup on a
# box that already has one leaves one and not two.
mkdir -p /etc/crontabs
touch /etc/crontabs/root
grep -v 'komizo-sample' /etc/crontabs/root > /etc/crontabs/root.tmp 2>/dev/null || true
printf '* * * * * /usr/local/bin/komizo-sample\n' >> /etc/crontabs/root.tmp
mv /etc/crontabs/root.tmp /etc/crontabs/root

# busybox crond is installed on Alpine but not necessarily running, and a
# crontab nothing reads is the quietest possible failure: every screen looks
# right and the history is simply always empty.
if command -v rc-update >/dev/null 2>&1; then
	rc-update add crond default >/dev/null 2>&1 || true
	rc-service crond start >/dev/null 2>&1 || rc-service crond restart >/dev/null 2>&1 || true
fi

# Written now rather than waiting up to a minute for cron, so the first reading
# exists by the time anyone opens the monitor -- and so a sampler that cannot
# run fails HERE, visibly, in the output of the thing that installed it.
/usr/local/bin/komizo-sample

# Two lines, written together: the komizo VERSION that set this box up, and the
# content STAMP of what it wrote. The version is what the interface shows beside
# the CLI's own -- "which komizo provisioned this box" -- and the stamp is the
# separate, exact answer to "would running the update change anything". An update
# rewrites both, so after one the box reads as the version in your hand.
printf '%s\n%s\n' __VERSION__ __STAMP__ > /var/lib/komizo/version

if [ -s __LOG__ ]; then
	log "Sampling this machine every minute into __LOG__"
else
	printf 'warning: the sampler wrote nothing -- resource history will be empty\n' >&2
fi
