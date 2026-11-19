#!/bin/sh
# diff two matching VM ranges from two kernelcaches at instruction level.
#
# kdiff points at the changed region; this shows what the change is. addresses
# and branch targets are normalised so layout shifts do not drown the patch.
#
# usage: tools/kguard.sh <old.kc> <new.kc> <old_va> <new_va> [bytes]
set -e
OLD=$1; NEW=$2; OVA=$3; NVA=$4; LEN=${5:-256}
[ -n "$NVA" ] || { echo "usage: $0 <old.kc> <new.kc> <old_va> <new_va> [bytes]"; exit 2; }

DIR=$(dirname "$0")
A=$(mktemp); B=$(mktemp)
trap 'rm -f "$A" "$B"' EXIT

"$DIR/kdis.sh" "$OLD" "$OVA" "$LEN" 2>/dev/null \
    | sed -E 's/^[0-9a-f]+:\s+([0-9a-f]{8} )+\s*//; s/0x[0-9a-f]+/T/g; s/[[:space:]]+$//' \
    | grep -v '^$\|file format\|Disassembly\|^\.data\|<\.data>' > "$A"
"$DIR/kdis.sh" "$NEW" "$NVA" "$LEN" 2>/dev/null \
    | sed -E 's/^[0-9a-f]+:\s+([0-9a-f]{8} )+\s*//; s/0x[0-9a-f]+/T/g; s/[[:space:]]+$//' \
    | grep -v '^$\|file format\|Disassembly\|^\.data\|<\.data>' > "$B"

echo "old $OLD $OVA"
echo "new $NEW $NVA"
diff -u "$A" "$B" || true
