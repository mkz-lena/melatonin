#!/bin/sh
# disassemble a VM range out of a kernelcache.
#
# the kernelcache is an MH_FILESET and its executable code can land in segments
# llvm-objdump 11 will not walk, so the range is cut out of the file using the
# segment table and handed to objdump as raw aarch64 with the VM address as the
# base. branch targets then read as real kernel addresses.
#
# usage: tools/kdis.sh <kernelcache> <va> [bytes]
set -e

KC=$1
VA=$2
LEN=${3:-128}
[ -n "$KC" ] && [ -n "$VA" ] || { echo "usage: $0 <kernelcache> <va> [bytes]"; exit 2; }

OD=${OBJDUMP:-aarch64-linux-gnu-objdump}
command -v "$OD" >/dev/null 2>&1 || {
    echo "aarch64 objdump not found (set OBJDUMP=...)"
    exit 2
}

TMP=$(mktemp /tmp/kdis.XXXXXX)
trap 'rm -f "$TMP"' EXIT

python3 - "$KC" "$TMP" "$VA" "$LEN" <<'PY'
import struct, sys

src, dst, va, ln = sys.argv[1], sys.argv[2], int(sys.argv[3], 0), int(sys.argv[4])
data = open(src, "rb").read()
if data[:4] != b"\xcf\xfa\xed\xfe":
    sys.exit("not a little-endian 64-bit mach-o")

ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<II", data, off)
    if cmd == 0x19:                                   # LC_SEGMENT_64
        name = data[off + 8:off + 24].split(b"\0")[0].decode(errors="replace")
        vm, vs, fo, fs = struct.unpack_from("<QQQQ", data, off + 24)
        if vm <= va < vm + fs:
            pos = fo + (va - vm)
            avail = min(ln, fs - (va - vm))
            open(dst, "wb").write(data[pos:pos + avail])
            print(f"{name} +0x{va - vm:x}", file=sys.stderr)
            break
    off += size
else:
    sys.exit(f"0x{va:x} is not file-backed")
PY

"$OD" -D -b binary -m aarch64 --adjust-vma="$VA" "$TMP"
