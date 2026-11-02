set -eu
os=unknown
if [ -r /etc/os-release ]; then
 os=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"' | head -n 1)
fi
printf 'os=%s\n' "$os"
printf 'kernel=%s\n' "$(uname -s)"
printf 'arch=%s\n' "$(uname -m)"
printf 'uid=%s\n' "$(id -u)"
printf 'memory_kib=%s\n' "$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
printf 'disk_kib=%s\n' "$(df -Pk /var/lib 2>/dev/null | awk 'END {print $4}')"
printf 'inodes=%s\n' "$(df -Pi /var/lib 2>/dev/null | awk 'END {print $4}')"
if command -v apk >/dev/null 2>&1; then echo apk=yes; else echo apk=no; fi
if command -v rc-service >/dev/null 2>&1; then echo openrc=yes; else echo openrc=no; fi
if [ -r /sys/fs/cgroup/cgroup.controllers ]; then echo cgroup_v2=yes; else echo cgroup_v2=no; fi
if [ -e /var/lib/komizo/version ] || [ -d /var/lib/komizo/apps ]; then echo installed=yes; else echo installed=no; fi
