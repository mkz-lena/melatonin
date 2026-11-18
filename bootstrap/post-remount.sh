#!/bin/sh
# re-apply rootful state after a userspace restart
set -e
JB=/var/jb

/usr/bin/melatonind --remount-only || { echo "remount fail"; exit 1; }

for d in /usr/bin /usr/sbin /usr/libexec /bin /sbin; do
    /var/jb/usr/bin/ldid -S "$d"/* 2>/dev/null || true
done

tpctl --ldrun 2>/dev/null || true
echo "rootful state reapplied"
