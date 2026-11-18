#!/usr/bin/env python3
"""prelink_map.py <kernelcache.macho> -> "addr size bundleid" lines.

A release kernelcache has no LC_SYMTAB, but it does carry __PRELINK_INFO: an
XML plist of every kext with its load address and size. That is enough to turn
a raw address from kdiff into a kext name.
"""
import struct, sys, plistlib

LC_SEGMENT_64 = 0x19

def segments(d):
    magic = struct.unpack_from("<I", d, 0)[0]
    ncmds = struct.unpack_from("<I", d, 16)[0]
    if magic != 0xfeedfacf:
        return
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == LC_SEGMENT_64:
            name = d[off + 8:off + 24].split(b"\0")[0].decode()
            vm, vs, fo, fs = struct.unpack_from("<QQQQ", d, off + 24)
            yield name, vm, vs, fo, fs
        off += cmdsize

def main():
    d = open(sys.argv[1], "rb").read()
    for name, vm, vs, fo, fs in segments(d):
        if name != "__PRELINK_INFO":
            continue
        blob = d[fo:fo + fs]
        i = blob.find(b"<?xml")
        j = blob.rfind(b"</plist>")
        if i < 0 or j < 0:
            print(f"# {name}: no xml plist", file=sys.stderr)
            return 1
        p = plistlib.loads(blob[i:j + 8])
        ks = p.get("_PrelinkInfoDictionary", [])
        rows = []
        for k in ks:
            bid = k.get("CFBundleIdentifier")
            addr = k.get("_PrelinkExecutableLoadAddr")
            size = k.get("_PrelinkExecutableSize", 0)
            if not bid or addr is None:
                continue
            rows.append((addr & 0xffffffffffffffff, size, bid))
        rows.sort()
        for a, s, bid in rows:
            print(f"{a:016x} {s:08x} {bid}")
        print(f"# {len(rows)} kexts", file=sys.stderr)
        return 0
    print("# no __PRELINK_INFO", file=sys.stderr)
    return 1

if __name__ == "__main__":
    sys.exit(main())
