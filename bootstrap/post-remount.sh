#!/bin/sh
# re-apply rootful state after a userspace restart
set -e
ROOT=${MELA_ROOT:-}
LDID="$ROOT/usr/bin/ldid"

"$ROOT/usr/bin/melatonind" --remount-only || { echo "remount fail"; exit 1; }

if [ -x "$LDID" ]; then
    for d in /usr/bin /usr/sbin /usr/libexec /bin /sbin; do
        "$LDID" -S "$d"/* 2>/dev/null || true
    done
fi

tpctl --ldrun 2>/dev/null || true
echo "rootful state reapplied"
