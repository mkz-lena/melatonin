#!/usr/bin/env bash
# pull_kc.sh - one command from a build number to a usable kernelcache.
#
#   tools/pull_kc.sh 24A5380h            # beta 3, iPhone 16e
#   tools/pull_kc.sh 24B119 --device iPhone17,5
#   tools/pull_kc.sh --list              # what we already pulled
#
# steps, all of which used to be typed by hand:
#   1. resolve the IPSW URL (table below for beta builds, ipsw.me otherwise)
#   2. HTTP range-read only the kernelcache member out of the zip (~24 MB of 12 GB)
#   3. find the bvx2 lzfse stream inside the IM4P wrapper and decode it
#   4. write the __PRELINK_INFO kext address map
#
# output: build/kcache/<build>.macho and build/kcache/<build>.map
# the .macho is what koff/kdiff want; the .map is what --map wants.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
out=${KCACHE_DIR:-$root/build/kcache}
mkdir -p "$out"

DEVICE=iPhone17,5

# beta builds are not in the ipsw.me API (that only tracks release trains), so
# the URLs are kept here once found. each is a full restore image on apple's CDN.
known_url() {
    case "$1" in
        24A5380h) echo "https://updates.cdn-apple.com/2026SpringSeed/fullrestores/140-36371/38D6F2FB-A7ED-4D3B-8261-2B56C137360B/iPhone17,5_27.0_24A5380h_Restore.ipsw" ;;
        *) return 1 ;;
    esac
}

resolve_url() {
    local build=$1 url
    if url=$(known_url "$build"); then echo "$url"; return; fi
    python3 - "$DEVICE" "$build" <<'PY'
import json, sys, urllib.request
dev, build = sys.argv[1], sys.argv[2]
d = json.load(urllib.request.urlopen(
    f"https://api.ipsw.me/v4/device/{dev}?type=ipsw", timeout=30))
for f in d.get("firmwares", []):
    if f["buildid"].lower() == build.lower():
        print(f["url"]); break
else:
    sys.exit(f"build {build} not found for {dev}")
PY
}

command -v lzfse >/dev/null || { echo "need lzfse (brew/apt: lzfse)"; exit 1; }

if [ "${1:-}" = "--list" ]; then
    printf '%-12s %-12s %s\n' build kind size
    for f in "$out"/*.macho; do
        [ -e "$f" ] || continue
        b=$(basename "$f" .macho)
        printf '%-12s %-12s %s\n' "$b" mach-o "$(du -h "$f" | cut -f1)"
    done
    exit 0
fi

build=${1:?usage: pull_kc.sh <build> [--device iPhone17,5]}
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --device) DEVICE=$2; shift 2 ;;
        *) echo "unknown arg $1"; exit 2 ;;
    esac
done

macho=$out/$build.macho
map=$out/$build.map

if [ -f "$macho" ] && [ -f "$map" ]; then
    echo "already have $macho"
    exit 0
fi

url=$(resolve_url "$build")
echo "build  $build  ($DEVICE)"
echo "ipsw   $url"

img=$out/$build.im4p
python3 "$here/remote_unzip.py" "$url" kernelcache "$img"

# IM4P wrapper: 4-byte magic, 4-byte length, 4-byte type, then the payload.
# the payload starts with 'bvx2', an lzfse stream. no plist parsing needed.
python3 - "$img" "$out/$build.lzfse" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
o = d.find(b"bvx2")
if o < 0: sys.exit("no bvx2 stream in " + sys.argv[1])
open(sys.argv[2], "wb").write(d[o:])
print(f"payload at +{o}, {len(d)-o} bytes compressed")
PY
lzfse -decode -i "$out/$build.lzfse" -o "$macho"

python3 "$here/prelink_map.py" "$macho" > "$map"

rm -f "$img" "$out/$build.lzfse"
printf 'wrote  %s (%s)\n' "$macho" "$(du -h "$macho" | cut -f1)"
printf 'wrote  %s (%s kexts)\n' "$map" "$(grep -cv '^#' "$map")"
